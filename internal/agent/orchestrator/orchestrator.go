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
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/scanner"
	"github.com/example/datavault/pkg/store"
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
}

var lookupUserHome = userHomeDir

const machineUsername = "_machine"

// New creates a new Orchestrator with the given configuration, connection
// pool, database handle, and rule store.
func New(cfg *config.AgentConfig, p *pool.ConnPool, db *sql.DB, rs *rules.UserRuleStore) *Orchestrator {
	return &Orchestrator{
		Cfg:       cfg,
		Pool:      p,
		DB:        db,
		RuleStore: rs,
		tasks:     make(map[string]*progress.Tracker),
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
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return taskID, fmt.Errorf("insert task record: %w", err)
	}

	var userRules []rules.Rule
	if username != machineUsername {
		var err error
		userRules, err = o.RuleStore.Load(username)
		if err != nil {
			tracker.SetPhase(progress.PhaseFailed)
			store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
			return taskID, fmt.Errorf("load user rules: %w", err)
		}
		userRules = filterRulesByName(userRules, ruleName)
	}

	// For each configured server, run the sync pipeline in parallel.
	var wg sync.WaitGroup
	for _, srv := range o.Cfg.Servers {
		wg.Add(1)
		go func(serverAddr string) {
			defer wg.Done()
			o.syncToServer(serverAddr, username, ruleName, userRules, tracker, taskID)
		}(srv.Address)
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

// syncToServer runs the full sync pipeline for a single server:
// fetch global config -> merge rules -> scan paths -> compute diff -> push.
func (o *Orchestrator) syncToServer(serverAddr, username, ruleName string, userRules []rules.Rule, tracker *progress.Tracker, taskID string) {
	client, err := o.Pool.GetClient(serverAddr)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
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
			tracker.SetPhase(progress.PhaseFailed)
			store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
			return
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

	type rootDiffs struct {
		rootPath string
		diffs    []scanner.FileDiff
	}

	var batches []rootDiffs
	var totalDiffs int64
	for _, rule := range syncRules {
		if !rule.Enabled {
			continue
		}
		excludes, err := glob.Compile(rule.Exclude)
		if err != nil {
			continue
		}
		for _, rootPath := range rule.Paths {
			result, scanErr := scanner.Scan(rootPath, excludes)
			if scanErr != nil {
				continue
			}
			tracker.AddScanned(int64(len(result.Files)))

			diffs, diffErrs := scanner.ComputeDiff(result.Files, o.DB, serverAddr, username)
			if len(diffErrs) > 0 {
				// Log errors but continue with valid diffs.
			}
			if len(diffs) > 0 {
				batches = append(batches, rootDiffs{rootPath: rootPath, diffs: diffs})
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
		if err := o.pushDiffsToServer(client, serverAddr, username, ruleType, batch.rootPath, batch.diffs, tracker); err != nil {
			tracker.SetPhase(progress.PhaseFailed)
			store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
			return
		}

		for _, d := range batch.diffs {
			if d.Action == scanner.DiffDelete {
				_ = store.DeleteSnapshot(o.DB, serverAddr, username, d.File.Path)
			} else {
				_ = store.UpsertSnapshot(o.DB, store.FileSnapshot{
					ServerID: serverAddr,
					Username: username,
					FilePath: d.File.Path,
					Mtime:    d.File.Mtime,
					Size:     d.File.Size,
					SHA256:   d.File.SHA256,
				})
			}
		}
	}
}

// pushDiffsToServer streams file diffs to the backup server via
// BackupService.PushBackup. It reads file contents from disk and sends them
// in batches. This is the core transfer step of the sync pipeline.
func (o *Orchestrator) pushDiffsToServer(client backuppbv1.BackupServiceClient, serverAddr, username, ruleType, rootPath string, diffs []scanner.FileDiff, tracker *progress.Tracker) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return transport.PushBackup(ctx, transport.PushConfig{
		Client:   client,
		Username: username,
		RuleType: ruleType,
		ServerID: serverAddr,
		Tracker:  tracker,
		RootPath: rootPath,
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
func (o *Orchestrator) RunRestore(username string, uid uint32, targetPath string, nonce, signature []byte) (string, error) {
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
		tracker.SetPhase(progress.PhaseFailed)
		return taskID, fmt.Errorf("insert task record: %w", err)
	}

	target, err := validateRestoreTarget(username, uid, targetPath)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return taskID, err
	}

	go o.runRestoreTask(taskID, username, target, nonce, signature, tracker)
	return taskID, nil
}

func (o *Orchestrator) runRestoreTask(taskID, username, targetPath string, nonce, signature []byte, tracker *progress.Tracker) {
	tracker.SetPhase(progress.PhaseTransferring)

	if len(o.Cfg.Servers) == 0 {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
	}
	serverAddr := o.Cfg.Servers[0].Address
	client, err := o.Pool.GetClient(serverAddr)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if len(nonce) == 0 || len(signature) == 0 {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
	}

	req := &backuppbv1.PullRestoreRequest{Username: username, Nonce: nonce, Signature: signature}
	stream, err := client.PullRestore(ctx, req)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
	}

	if err := restoreFromStream(stream, targetPath, tracker); err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
	}

	tracker.SetPhase(progress.PhaseCompleted)
	store.UpdateTaskPhase(o.DB, taskID, "COMPLETED", "")
}

func (o *Orchestrator) GetAuthChallenge() (server string, challenge *backuppbv1.Challenge, err error) {
	if len(o.Cfg.Servers) == 0 {
		return "", nil, fmt.Errorf("no backup servers configured")
	}
	serverAddr := o.Cfg.Servers[0].Address
	client, err := o.Pool.GetClient(serverAddr)
	if err != nil {
		return "", nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	challenge, err = client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
	if err != nil {
		return "", nil, fmt.Errorf("get challenge: %w", err)
	}
	return serverAddr, challenge, nil
}

func (o *Orchestrator) GetQuotaUsage(username string, nonce, signature []byte) (*backuppbv1.QuotaUsage, error) {
	if len(o.Cfg.Servers) == 0 {
		return nil, fmt.Errorf("no backup servers configured")
	}
	serverAddr := o.Cfg.Servers[0].Address
	client, err := o.Pool.GetClient(serverAddr)
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

func restoreFromStream(stream backuppbv1.BackupService_PullRestoreClient, targetPath string, tracker *progress.Tracker) error {
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

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive restore batch: %w", err)
		}
		if batch.IsLast {
			break
		}
		for _, file := range batch.Files {
			if err := writeRestoredFile(tmpDir, file); err != nil {
				return err
			}
			tracker.AddTransferred(1, int64(len(file.Content)))
		}
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
	return nil
}

func writeRestoredFile(root string, file *backuppbv1.FileEntry) error {
	cleanPath := filepath.Clean(file.Path)
	if filepath.IsAbs(cleanPath) {
		cleanPath = cleanPath[1:]
	}
	target := filepath.Join(root, cleanPath)
	if target != root && !hasPathPrefix(target, root) {
		return fmt.Errorf("restore path traversal detected: %q", file.Path)
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
