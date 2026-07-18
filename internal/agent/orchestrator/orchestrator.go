// Package orchestrator coordinates the backup sync pipeline:
// rule merge -> scan -> diff -> push for each configured server.
package orchestrator

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/example/datavault/internal/agent/pool"
	"github.com/example/datavault/internal/agent/transport"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/glob"
	"github.com/example/datavault/pkg/hooks"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/retry"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/scanner"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
)

// Orchestrator coordinates backup sync operations across multiple servers.
// It merges rules, scans filesystems, computes diffs against the local
// snapshot database, and pushes changes to each configured backup server.
type Orchestrator struct {
	Cfg       *config.AgentConfig
	Pool      *pool.ConnPool
	DB        *sql.DB
	RuleStore *rules.UserRuleStore

	mu    sync.RWMutex
	tasks map[string]*progress.Tracker
	// failureNotified deduplicates parallel replica failures into one operator
	// notification per task.
	failureNotified map[string]bool
	FailureHook     func(hooks.TaskFailure)
}

var lookupUserHome = userHomeDir

const machineUsername = "_machine"

// New creates a new Orchestrator with the given configuration, connection
// pool, database handle, and rule store.
func New(cfg *config.AgentConfig, p *pool.ConnPool, db *sql.DB, rs *rules.UserRuleStore) *Orchestrator {
	return &Orchestrator{
		Cfg:             cfg,
		Pool:            p,
		DB:              db,
		RuleStore:       rs,
		tasks:           make(map[string]*progress.Tracker),
		failureNotified: make(map[string]bool),
	}
}

// SetFailureHook installs the optional terminal-failure callback used by the
// root Agent to invoke the configured operator hook.
func (o *Orchestrator) SetFailureHook(fn func(hooks.TaskFailure)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.FailureHook = fn
}

func (o *Orchestrator) markFailed(taskID, username, server string, tracker *progress.Tracker, cause error) {
	if tracker != nil {
		tracker.SetPhase(progress.PhaseFailed)
	}
	reason := "task failed"
	if cause != nil {
		reason = cause.Error()
	}
	if o.DB != nil {
		_ = store.UpdateTaskFailure(o.DB, taskID, reason)
	}
	o.mu.Lock()
	if o.failureNotified[taskID] {
		o.mu.Unlock()
		return
	}
	o.failureNotified[taskID] = true
	hook := o.FailureHook
	o.mu.Unlock()
	if hook != nil {
		go hook(hooks.TaskFailure{TaskID: taskID, Username: username, Server: server, Reason: reason})
	}
}

// generateTaskID produces a unique task identifier using the current time and
// a short random suffix (no external uuid dependency).
func generateTaskID(prefix, username string) (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random suffix: %w", err)
	}
	suffix := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s", prefix, time.Now().UTC().Format("20060102-150405"), username, suffix), nil
}

// RunSync executes a full backup sync for a user against all configured
// servers. It loads the user's rules, fetches global config from each server,
// merges rules, scans filesystems, computes diffs, and pushes changes.
//
// An optional ruleName filter can restrict the sync to a single named rule;
// pass an empty string to sync all rules.
func (o *Orchestrator) RunSync(username, ruleName string) (string, error) {
	return o.runSync(username, ruleName, nil)
}

// RunSyncWithSigner runs a user sync using a caller-owned SSH-agent signer.
// The signer is intentionally supplied by the Unix-socket service rather
// than inherited from the root Agent environment.
func (o *Orchestrator) RunSyncWithSigner(username, ruleName string, signFunc func([]byte) ([]byte, *ssh.Signature, error)) (string, error) {
	return o.runSync(username, ruleName, signFunc)
}

func (o *Orchestrator) runSync(username, ruleName string, signFunc func([]byte) ([]byte, *ssh.Signature, error)) (string, error) {
	if o == nil || o.Cfg == nil || len(o.Cfg.Servers) == 0 {
		return "", fmt.Errorf("no backup servers configured")
	}
	if username != machineUsername && signFunc == nil {
		return "", fmt.Errorf("user sync requires a caller SSH-agent signer")
	}
	taskID, err := generateTaskID("sync", username)
	if err != nil {
		return "", fmt.Errorf("generate task ID: %w", err)
	}

	tracker := progress.NewTracker()

	o.mu.Lock()
	o.tasks[taskID] = tracker
	o.mu.Unlock()

	// Record the task in the history database.
	if err := store.InsertTask(o.DB, store.TaskRecord{
		TaskID: taskID, ServerID: "all", Username: username,
	}); err != nil {
		o.markFailed(taskID, username, "", tracker, fmt.Errorf("insert task record: %w", err))
		return taskID, fmt.Errorf("insert task record: %w", err)
	}

	var userRules []rules.Rule
	if username != machineUsername {
		var err error
		userRules, err = o.RuleStore.Load(username)
		if err != nil {
			o.markFailed(taskID, username, "", tracker, fmt.Errorf("load user rules: %w", err))
			return taskID, fmt.Errorf("load user rules: %w", err)
		}
		account, err := user.Lookup(username)
		if err != nil {
			o.markFailed(taskID, username, "", tracker, fmt.Errorf("lookup user home: %w", err))
			return taskID, fmt.Errorf("lookup user home: %w", err)
		}
		for _, rule := range userRules {
			if err := rules.ValidateUserPaths(rule.Paths, account.HomeDir); err != nil {
				o.markFailed(taskID, username, "", tracker, fmt.Errorf("validate user rule %q: %w", rule.Name, err))
				return taskID, fmt.Errorf("validate user rule %q: %w", rule.Name, err)
			}
		}
		userRules = filterRulesByName(userRules, ruleName)
	}

	// For each configured server, run the sync pipeline in parallel.
	var wg sync.WaitGroup
	for _, srv := range o.Cfg.Servers {
		wg.Add(1)
		go func(server config.ServerEntry) {
			defer wg.Done()
			o.syncToServerWithRetry(server, username, ruleName, userRules, tracker, taskID, signFunc)
		}(srv)
	}

	// Mark the task as completed once all server syncs finish.
	go func() {
		wg.Wait()
		phase, _, _ := tracker.Snapshot()
		if phase == progress.PhaseFailed {
			return
		}
		tracker.SetPhase(progress.PhaseCompleted)
		store.UpdateTaskPhase(o.DB, taskID, "COMPLETED", "")
	}()

	return taskID, nil
}

func (o *Orchestrator) syncToServerWithRetry(server config.ServerEntry, username, ruleName string, userRules []rules.Rule, tracker *progress.Tracker, taskID string, signFunc func([]byte) ([]byte, *ssh.Signature, error)) {
	backoff := retry.New(retry.Config{
		Initial:    o.Cfg.Retry.InitialInterval,
		Max:        o.Cfg.Retry.MaxInterval,
		Multiplier: o.Cfg.Retry.Multiplier,
		Jitter:     o.Cfg.Retry.Jitter,
		MaxElapsed: o.Cfg.Retry.MaxElapsedTime,
	})
	for {
		err := o.syncToServer(server, username, ruleName, userRules, tracker, signFunc)
		if err == nil {
			return
		}
		if !retry.IsRetryable(err) {
			o.markFailed(taskID, username, server.Address, tracker, err)
			return
		}
		delay := backoff.Next()
		if delay <= 0 {
			o.markFailed(taskID, username, server.Address, tracker, fmt.Errorf("sync retries exhausted: %w", err))
			return
		}
		time.Sleep(delay)
	}
}

// syncToServer runs one complete sync attempt for a single server:
// fetch global config -> merge rules -> scan paths -> compute diff -> push.
// It returns a classified error so the caller can retry only transient faults.
func (o *Orchestrator) syncToServer(server config.ServerEntry, username, ruleName string, userRules []rules.Rule, tracker *progress.Tracker, signFunc func([]byte) ([]byte, *ssh.Signature, error)) error {
	serverAddr := server.Address
	client, err := o.Pool.GetClientWithServerName(serverAddr, server.TLSServerName)
	if err != nil {
		return fmt.Errorf("get client for %s: %w", serverAddr, err)
	}

	ruleType := "user"
	syncRules := userRules
	if username == machineUsername {
		ruleType = "machine"
		syncRules = machineRulesFromConfig(o.Cfg.MachineRules, ruleName)
	} else {
		// Fetch global rules and user policy from the server.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		gcfg, err := client.GetGlobalConfig(ctx, &backuppbv1.GetGlobalConfigRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("get global config from %s: %w", serverAddr, err)
		}

		// Convert protobuf global config to local config types.
		globalRules := make([]config.GlobalRule, 0, len(gcfg.GlobalRules))
		for _, gr := range gcfg.GlobalRules {
			globalRules = append(globalRules, config.GlobalRule{
				Name:    gr.Name,
				Paths:   gr.Paths,
				Exclude: gr.Exclude,
			})
		}
		policy := convertUserPolicy(gcfg.UserPolicy)

		// Merge global + user rules with per-user policy overrides.
		syncRules = rules.MergeUserRules(globalRules, userRules, policy, username).Rules
	}
	if ruleName != "" && len(syncRules) == 0 {
		return retry.Permanent(fmt.Errorf("rule %q is not enabled or does not exist", ruleName))
	}

	type rootDiffs struct {
		rootPath   string
		rootPrefix string
		diffs      []scanner.FileDiff
	}

	var batches []rootDiffs
	var totalDiffs int64
	for _, rule := range syncRules {
		if !rule.Enabled {
			continue
		}
		excludes, err := glob.Compile(rule.Exclude)
		if err != nil {
			return retry.Permanent(fmt.Errorf("compile excludes for rule %q: %w", rule.Name, err))
		}
		for _, rootPath := range rule.Paths {
			result, scanErr := scanner.Scan(rootPath, excludes)
			if scanErr != nil {
				return retry.Permanent(fmt.Errorf("scan root %q: %w", rootPath, scanErr))
			}
			// A partial scan cannot safely establish that omitted files were
			// deleted. Failing the whole task avoids turning a transient permission
			// or I/O error into a remote delete marker while still reporting a
			// false successful backup to the caller.
			if len(result.Errors) != 0 {
				return retry.Permanent(fmt.Errorf("scan root %q: %w", rootPath, result.Errors[0]))
			}
			tracker.AddScanned(int64(len(result.Files)))

			rootPrefix, archivedFiles, namespaceErr := scanner.NamespaceFiles(rootPath, result.Files)
			if namespaceErr != nil {
				return retry.Permanent(fmt.Errorf("namespace root %q: %w", rootPath, namespaceErr))
			}
			diffs, diffErrs := scanner.ComputeDiffUnderRoot(archivedFiles, o.DB, serverAddr, username, rootPrefix)
			if len(diffErrs) > 0 {
				return retry.Permanent(fmt.Errorf("compute diff for root %q: %w", rootPath, diffErrs[0]))
			}
			if len(diffs) > 0 {
				batches = append(batches, rootDiffs{rootPath: rootPath, rootPrefix: rootPrefix, diffs: diffs})
				totalDiffs += int64(len(diffs))
			}
		}
	}

	tracker.SetPhase(progress.PhaseScanning)
	tracker.SetTotals(totalDiffs, totalDiffs)

	// Push diffs to the server via streaming gRPC. Snapshot state is updated
	// only after a root's transfer succeeds.
	tracker.SetPhase(progress.PhaseTransferring)
	for _, batch := range batches {
		if err := o.pushDiffsToServer(client, serverAddr, username, ruleType, batch.rootPath, batch.rootPrefix, batch.diffs, tracker, signFunc); err != nil {
			return fmt.Errorf("push %q to %s: %w", batch.rootPath, serverAddr, err)
		}

		if err := o.updateSnapshots(serverAddr, username, batch.diffs); err != nil {
			return retry.Permanent(fmt.Errorf("update local snapshots after %q: %w", serverAddr, err))
		}
	}
	return nil
}

func (o *Orchestrator) updateSnapshots(serverAddr, username string, diffs []scanner.FileDiff) error {
	for _, d := range diffs {
		if d.Action == scanner.DiffDelete {
			if err := store.DeleteSnapshot(o.DB, serverAddr, username, d.File.Path); err != nil {
				return fmt.Errorf("delete local snapshot %q: %w", d.File.Path, err)
			}
			continue
		}
		if err := store.UpsertSnapshot(o.DB, store.FileSnapshot{
			ServerID: serverAddr,
			Username: username,
			FilePath: d.File.Path,
			Mtime:    d.File.Mtime,
			Size:     d.File.Size,
			Mode:     d.File.Mode,
			SHA256:   d.File.SHA256,
		}); err != nil {
			return fmt.Errorf("upsert local snapshot %q: %w", d.File.Path, err)
		}
	}
	return nil
}

// pushDiffsToServer streams file diffs to the backup server via
// BackupService.PushBackup. It reads file contents from disk and sends them
// in batches. This is the core transfer step of the sync pipeline.
func (o *Orchestrator) pushDiffsToServer(client backuppbv1.BackupServiceClient, serverAddr, username, ruleType, rootPath, rootPrefix string, diffs []scanner.FileDiff, tracker *progress.Tracker, signFunc func([]byte) ([]byte, *ssh.Signature, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return transport.PushBackup(ctx, transport.PushConfig{
		Client:                       client,
		Username:                     username,
		RuleType:                     ruleType,
		ServerID:                     serverAddr,
		Tracker:                      tracker,
		RootPath:                     rootPath,
		PathPrefix:                   rootPrefix,
		SignFunc:                     signFunc,
		BandwidthLimitBytesPerSecond: o.Cfg.BandwidthLimitBytesPerSecond,
	}, diffs)
}

func filterRulesByName(input []rules.Rule, ruleName string) []rules.Rule {
	if ruleName == "" {
		return input
	}
	filtered := make([]rules.Rule, 0, len(input))
	for _, rule := range input {
		if rule.Name == ruleName {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

func machineRulesFromConfig(machineRules []config.MachineRule, ruleName string) []rules.Rule {
	result := make([]rules.Rule, 0, len(machineRules))
	for _, rule := range machineRules {
		if !rule.Enabled {
			continue
		}
		if ruleName != "" && rule.Name != ruleName {
			continue
		}
		result = append(result, rules.Rule{
			Name:     rule.Name,
			Paths:    rule.Paths,
			Exclude:  rule.Exclude,
			Schedule: rule.Schedule,
			Enabled:  true,
		})
	}
	return result
}

// RunRestore starts a full restore of the latest server-side backup into a
// user-owned path under the user's home directory.
func (o *Orchestrator) RunRestore(username string, uid uint32, targetPath, server string, nonce, signature []byte) (string, error) {
	taskID, err := generateTaskID("restore", username)
	if err != nil {
		return "", fmt.Errorf("generate task ID: %w", err)
	}

	tracker := progress.NewTracker()

	o.mu.Lock()
	o.tasks[taskID] = tracker
	o.mu.Unlock()

	if err := store.InsertTask(o.DB, store.TaskRecord{
		TaskID: taskID, ServerID: "all", Username: username,
	}); err != nil {
		o.markFailed(taskID, username, "", tracker, fmt.Errorf("insert restore task record: %w", err))
		return taskID, fmt.Errorf("insert task record: %w", err)
	}

	target, err := validateRestoreTarget(username, uid, targetPath)
	if err != nil {
		o.markFailed(taskID, username, "", tracker, err)
		return taskID, err
	}

	go o.runRestoreTask(taskID, username, uid, target, server, nonce, signature, tracker)
	return taskID, nil
}

func (o *Orchestrator) runRestoreTask(taskID, username string, uid uint32, targetPath, requestedServer string, nonce, signature []byte, tracker *progress.Tracker) {
	tracker.SetPhase(progress.PhaseTransferring)

	if len(o.Cfg.Servers) == 0 {
		o.markFailed(taskID, username, "", tracker, fmt.Errorf("no backup servers configured"))
		return
	}
	server, err := o.resolveServer(requestedServer)
	if err != nil {
		o.markFailed(taskID, username, requestedServer, tracker, err)
		return
	}
	serverAddr := server.Address
	client, err := o.Pool.GetClientWithServerName(serverAddr, server.TLSServerName)
	if err != nil {
		o.markFailed(taskID, username, serverAddr, tracker, fmt.Errorf("get restore client: %w", err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if len(nonce) == 0 || len(signature) == 0 {
		o.markFailed(taskID, username, serverAddr, tracker, fmt.Errorf("missing restore signature"))
		return
	}

	req := &backuppbv1.PullRestoreRequest{Username: username, Nonce: nonce, Signature: signature}
	stream, err := client.PullRestore(ctx, req)
	if err != nil {
		o.markFailed(taskID, username, serverAddr, tracker, fmt.Errorf("start restore: %w", err))
		return
	}

	if err := restoreFromStream(stream, targetPath, uid, tracker); err != nil {
		o.markFailed(taskID, username, serverAddr, tracker, fmt.Errorf("restore stream: %w", err))
		return
	}

	tracker.SetPhase(progress.PhaseCompleted)
	store.UpdateTaskPhase(o.DB, taskID, "COMPLETED", "")
}

func (o *Orchestrator) GetAuthChallenge() (server string, challenge *backuppbv1.Challenge, err error) {
	if len(o.Cfg.Servers) == 0 {
		return "", nil, fmt.Errorf("no backup servers configured")
	}
	var failures []string
	for _, entry := range o.Cfg.Servers {
		client, clientErr := o.Pool.GetClientWithServerName(entry.Address, entry.TLSServerName)
		if clientErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", entry.Address, clientErr))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		challenge, err = client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
		cancel()
		if err == nil {
			return entry.Address, challenge, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", entry.Address, err))
	}
	return "", nil, fmt.Errorf("get challenge from configured servers: %s", strings.Join(failures, "; "))
}

func (o *Orchestrator) GetQuotaUsage(username, requestedServer string, nonce, signature []byte) (*backuppbv1.QuotaUsage, error) {
	server, err := o.resolveServer(requestedServer)
	if err != nil {
		return nil, err
	}
	client, err := o.Pool.GetClientWithServerName(server.Address, server.TLSServerName)
	if err != nil {
		return nil, err
	}
	if len(nonce) == 0 || len(signature) == 0 {
		return nil, fmt.Errorf("missing quota signature")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := &backuppbv1.GetQuotaUsageRequest{Username: username, Nonce: nonce, Signature: signature}
	usage, err := client.GetQuotaUsage(ctx, req)
	if err != nil {
		return nil, err
	}
	return &backuppbv1.QuotaUsage{
		UsedBytes:  usage.UsedBytes,
		QuotaBytes: usage.QuotaBytes,
		Dataset:    usage.Dataset,
	}, nil
}

// resolveServer only accepts a configured server from the loaded Agent configuration.
// The CLI echoes the address that issued its nonce; accepting arbitrary input
// here would let an untrusted local peer redirect the root Agent to a server
// outside the configured mTLS policy.
func (o *Orchestrator) resolveServer(requested string) (config.ServerEntry, error) {
	if requested == "" {
		return config.ServerEntry{}, fmt.Errorf("server selected by authentication challenge is required")
	}
	for _, entry := range o.Cfg.Servers {
		if entry.Address == requested {
			return entry, nil
		}
	}
	return config.ServerEntry{}, fmt.Errorf("server %q is not configured", requested)
}

func validateRestoreTarget(username string, uid uint32, targetPath string) (string, error) {
	homeDir, err := lookupUserHome(username, uid)
	if err != nil {
		return "", err
	}

	if targetPath == "" {
		targetPath = filepath.Join(homeDir, "restored")
	}
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(homeDir, targetPath)
	}

	homeDir = filepath.Clean(homeDir)
	targetPath = filepath.Clean(targetPath)
	if targetPath != homeDir && !hasPathPrefix(targetPath, homeDir) {
		return "", fmt.Errorf("restore target must be inside %s", homeDir)
	}

	if info, err := os.Lstat(targetPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("restore target must not be a symlink")
		}
		if !info.IsDir() {
			return "", fmt.Errorf("restore target must be a directory")
		}
		if err := validateOwner(info, uid); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect restore target: %w", err)
	} else {
		parent := filepath.Dir(targetPath)
		info, statErr := os.Lstat(parent)
		if statErr != nil {
			return "", fmt.Errorf("inspect restore parent: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("restore parent must not be a symlink")
		}
		if !info.IsDir() {
			return "", fmt.Errorf("restore parent must be a directory")
		}
		if err := validateOwner(info, uid); err != nil {
			return "", err
		}
	}

	return targetPath, nil
}

func userHomeDir(username string, uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", fmt.Errorf("lookup user home: %w", err)
	}
	if u.Username != username {
		return "", fmt.Errorf("username %q does not match uid %d", username, uid)
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("user %q has no home directory", username)
	}
	return u.HomeDir, nil
}

func validateOwner(info os.FileInfo, uid uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect target owner")
	}
	if stat.Uid != uid {
		return fmt.Errorf("restore target must be owned by uid %d", uid)
	}
	return nil
}

func hasPathPrefix(path, prefix string) bool {
	rel, err := filepath.Rel(prefix, path)
	return err == nil && rel != "." && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func restoreFromStream(stream backuppbv1.BackupService_PullRestoreClient, targetPath string, uid uint32, tracker *progress.Tracker) error {
	parent := filepath.Dir(targetPath)
	tmpDir, err := os.MkdirTemp(parent, ".dvault-restore-*")
	if err != nil {
		return fmt.Errorf("create restore temp dir: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	chunkWriters := make(map[string]*restoreChunkWriter)
	defer abortRestoreChunks(chunkWriters)
	sawLast := false

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return fmt.Errorf("restore stream ended before final batch")
		}
		if err != nil {
			return fmt.Errorf("receive restore batch: %w", err)
		}
		if batch.IsLast {
			sawLast = true
			break
		}
		for _, file := range batch.Files {
			if file.Chunked {
				if err := writeRestoredChunk(tmpDir, file, chunkWriters); err != nil {
					return err
				}
				if file.FinalChunk {
					tracker.AddTransferred(1, int64(len(file.Content)))
				} else {
					tracker.AddTransferred(0, int64(len(file.Content)))
				}
				continue
			}
			if _, exists := chunkWriters[file.Path]; exists {
				return fmt.Errorf("restore file %q has an unfinished chunked write", file.Path)
			}
			if err := writeRestoredFile(tmpDir, file); err != nil {
				return err
			}
			tracker.AddTransferred(1, int64(len(file.Content)))
		}
	}
	if !sawLast || len(chunkWriters) != 0 {
		return fmt.Errorf("restore stream ended with incomplete chunked file")
	}

	if info, err := os.Lstat(targetPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("restore target must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect restore target before rename: %w", err)
	}

	if err := os.RemoveAll(targetPath); err != nil {
		return fmt.Errorf("remove existing restore target: %w", err)
	}
	if err := os.Rename(tmpDir, targetPath); err != nil {
		return fmt.Errorf("rename restore temp dir: %w", err)
	}
	cleanup = false
	if err := chownRestoreTree(targetPath, uid); err != nil {
		_ = os.RemoveAll(targetPath)
		return err
	}
	return nil
}

// chownRestoreTree transfers ownership of a completed restore from the
// root-run Agent to the Unix-socket user who requested it. Lchown prevents a
// future malformed restore from following a symlink if one is ever present.
func chownRestoreTree(root string, uid uint32) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := os.Lchown(path, int(uid), -1); err != nil {
			return fmt.Errorf("set restore ownership for %q: %w", path, err)
		}
		return nil
	})
}

func writeRestoredFile(root string, file *backuppbv1.FileEntry) error {
	target, err := restoreTargetPath(root, file.Path)
	if err != nil {
		return err
	}
	if file.Deleted {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return fmt.Errorf("create restore parent: %w", err)
	}
	if err := os.WriteFile(target, file.Content, os.FileMode(file.Mode)); err != nil {
		return fmt.Errorf("write restored file %q: %w", file.Path, err)
	}
	return nil
}

type restoreChunkWriter struct {
	file       *os.File
	nextOffset uint64
	mode       uint32
}

func writeRestoredChunk(root string, entry *backuppbv1.FileEntry, writers map[string]*restoreChunkWriter) error {
	if entry.Deleted {
		return fmt.Errorf("chunked restore entry may not be a delete marker")
	}
	writer, exists := writers[entry.Path]
	if !exists {
		if entry.ChunkOffset != 0 {
			return fmt.Errorf("first restore chunk offset is %d, want 0", entry.ChunkOffset)
		}
		target, err := restoreTargetPath(root, entry.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return fmt.Errorf("create restore parent: %w", err)
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("create chunked restore file %q: %w", entry.Path, err)
		}
		writer = &restoreChunkWriter{file: file, mode: entry.Mode}
		writers[entry.Path] = writer
	}
	if entry.ChunkOffset != writer.nextOffset {
		return fmt.Errorf("restore chunk offset is %d, want %d", entry.ChunkOffset, writer.nextOffset)
	}
	if entry.Mode != writer.mode {
		return fmt.Errorf("restore chunk mode changed from %#o to %#o", writer.mode, entry.Mode)
	}
	if _, err := writer.file.Write(entry.Content); err != nil {
		return fmt.Errorf("write restore chunk %q: %w", entry.Path, err)
	}
	writer.nextOffset += uint64(len(entry.Content))
	if !entry.FinalChunk {
		return nil
	}
	if err := writer.file.Close(); err != nil {
		return fmt.Errorf("close chunked restore file %q: %w", entry.Path, err)
	}
	if err := os.Chmod(writer.file.Name(), os.FileMode(entry.Mode&0777)); err != nil {
		return fmt.Errorf("chmod chunked restore file %q: %w", entry.Path, err)
	}
	delete(writers, entry.Path)
	return nil
}

func abortRestoreChunks(writers map[string]*restoreChunkWriter) {
	for _, writer := range writers {
		name := writer.file.Name()
		_ = writer.file.Close()
		_ = os.Remove(name)
	}
}

func restoreTargetPath(root, path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) {
		cleanPath = cleanPath[1:]
	}
	target := filepath.Join(root, cleanPath)
	if target != root && !hasPathPrefix(target, root) {
		return "", fmt.Errorf("restore path traversal detected: %q", path)
	}
	return target, nil
}

// convertUserPolicy converts a protobuf UserPolicy to the local config type.
func convertUserPolicy(pb *backuppbv1.UserPolicy) config.UserPolicyBlock {
	if pb == nil {
		return config.UserPolicyBlock{}
	}

	p := config.UserPolicyBlock{
		DefaultSchedule:  pb.DefaultSchedule,
		DefaultQuotaGB:   pb.DefaultQuotaGb,
		PerUserOverrides: make(map[string]config.UserOverride),
	}

	for name, o := range pb.PerUserOverrides {
		p.PerUserOverrides[name] = config.UserOverride{
			QuotaGB:  o.QuotaGb,
			Schedule: o.Schedule,
		}
	}

	return p
}

// GetTracker returns the progress tracker for a given task ID.
// It returns an error if the task is not found.
func (o *Orchestrator) GetTracker(taskID string) (*progress.Tracker, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	t, ok := o.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task %q not found", taskID)
	}
	return t, nil
}

// GetTrackerForUser returns a task tracker only when it belongs to username.
// Root may inspect machine and user tasks; every other local user is limited
// to their own task history. Checking the durable task record prevents the
// world-readable Agent socket from exposing another user's paths in progress
// updates.
func (o *Orchestrator) GetTrackerForUser(username, taskID string) (*progress.Tracker, error) {
	var (
		record *store.TaskRecord
		err    error
	)
	if taskID == "" {
		record, err = store.GetLatestTaskForUser(o.DB, username)
	} else {
		record, err = store.GetTask(o.DB, taskID)
	}
	if err != nil {
		return nil, fmt.Errorf("look up task: %w", err)
	}
	if record == nil {
		return nil, fmt.Errorf("task %q not found", taskID)
	}
	if username != "root" && record.Username != username {
		return nil, fmt.Errorf("task %q not found", taskID)
	}
	tracker, err := o.GetTracker(record.TaskID)
	if err == nil {
		return tracker, nil
	}

	// Completed tasks survive daemon restarts in SQLite even though their
	// live tracker does not. Reconstruct a terminal view for status queries;
	// detailed counters are intentionally zero because task history currently
	// persists no statistics payload.
	tracker = progress.NewTracker()
	switch progress.Phase(record.Phase) {
	case "PENDING", progress.PhaseScanning, progress.PhaseTransferring:
		// This only happens for a legacy row or a process that stopped before
		// FailIncompleteTasks could run. It cannot still be executing without
		// an in-memory tracker, so expose it as failed rather than hanging the
		// status stream forever.
		tracker.SetPhase(progress.PhaseFailed)
	case progress.PhaseCompleted, progress.PhaseFailed:
		tracker.SetPhase(progress.Phase(record.Phase))
	default:
		return nil, fmt.Errorf("task %q has invalid stored phase %q", record.TaskID, record.Phase)
	}
	return tracker, nil
}

// ActiveTasks returns a copy of the current task ID to tracker mapping.
func (o *Orchestrator) ActiveTasks() map[string]*progress.Tracker {
	o.mu.RLock()
	defer o.mu.RUnlock()
	m := make(map[string]*progress.Tracker, len(o.tasks))
	for k, v := range o.tasks {
		m[k] = v
	}
	return m
}
