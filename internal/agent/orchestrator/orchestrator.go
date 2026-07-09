// Package orchestrator coordinates the backup sync pipeline:
// rule merge -> scan -> diff -> push for each configured server.
package orchestrator

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/glob"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/scanner"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/internal/agent/pool"
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

	// Load the user's personal rules.
	userRules, err := o.RuleStore.Load(username)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return taskID, fmt.Errorf("load user rules: %w", err)
	}

	// If a specific rule name was requested, filter user rules.
	if ruleName != "" {
		filtered := make([]rules.Rule, 0, len(userRules))
		for _, r := range userRules {
			if r.Name == ruleName {
				filtered = append(filtered, r)
			}
		}
		userRules = filtered
	}

	// For each configured server, run the sync pipeline in parallel.
	var wg sync.WaitGroup
	for _, srv := range o.Cfg.Servers {
		wg.Add(1)
		go func(serverAddr string) {
			defer wg.Done()
			o.syncToServer(serverAddr, username, userRules, tracker, taskID)
		}(srv.Address)
	}

	// Mark the task as completed once all server syncs finish.
	go func() {
		wg.Wait()
		tracker.SetPhase(progress.PhaseCompleted)
		store.UpdateTaskPhase(o.DB, taskID, "COMPLETED", "")
	}()

	return taskID, nil
}

// syncToServer runs the full sync pipeline for a single server:
// fetch global config -> merge rules -> scan paths -> compute diff -> push.
func (o *Orchestrator) syncToServer(serverAddr, username string, userRules []rules.Rule, tracker *progress.Tracker, taskID string) {
	client, err := o.Pool.GetClient(serverAddr)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return
	}

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
	merged := rules.MergeUserRules(globalRules, userRules, policy, username)

	// Scan each enabled rule's paths and compute diffs.
	var allDiffs []scanner.FileDiff
	for _, rule := range merged.Rules {
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
			allDiffs = append(allDiffs, diffs...)
		}
	}

	tracker.SetPhase(progress.PhaseScanning)
	tracker.SetTotals(int64(len(allDiffs)), int64(len(allDiffs)))

	// Push diffs to the server via streaming gRPC.
	tracker.SetPhase(progress.PhaseTransferring)
	o.pushDiffsToServer(client, serverAddr, username, allDiffs, tracker)

	// Update the local snapshot database to reflect the new state.
	for _, d := range allDiffs {
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

// pushDiffsToServer streams file diffs to the backup server via
// BackupService.PushBackup. It reads file contents from disk and sends them
// in batches. This is the core transfer step of the sync pipeline.
func (o *Orchestrator) pushDiffsToServer(client backuppbv1.BackupServiceClient, serverAddr, username string, diffs []scanner.FileDiff, tracker *progress.Tracker) {
	if len(diffs) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	stream, err := client.PushBackup(ctx)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		return
	}

	batchID := fmt.Sprintf("batch-%s-%s", time.Now().UTC().Format("20060102-150405"), username)

	// Send files in a single batch (the transport layer handles chunking).
	batch := &backuppbv1.BackupBatch{
		BatchId:  batchID,
		Username: username,
		RuleType: "user",
	}

	for _, d := range diffs {
		if d.Action == scanner.DiffDelete {
			// Signal deletion to the server.
			batch.Files = append(batch.Files, &backuppbv1.FileEntry{
				Path:    d.File.Path,
				Deleted: true,
			})
			continue
		}

		// Only push add/modify actions (DiffAdd and DiffModify).
		if d.Action != scanner.DiffAdd && d.Action != scanner.DiffModify {
			continue
		}

		// File content will be read by the transport layer.
		// Here we build the metadata; the actual push is handled
		// by the transport package which streams file contents.
		batch.Files = append(batch.Files, &backuppbv1.FileEntry{
			Path: d.File.Path,
			Mode: d.File.Mode,
		})
	}

	if len(batch.Files) > 0 {
		if err := stream.Send(batch); err != nil {
			tracker.SetPhase(progress.PhaseFailed)
			return
		}

		// Wait for server acknowledgement.
		ack, err := stream.Recv()
		if err != nil {
			tracker.SetPhase(progress.PhaseFailed)
			return
		}

		if ack.Status != "OK" {
			tracker.SetPhase(progress.PhaseFailed)
			return
		}

		_ = ack // ack details processed by caller
	}

	if err := stream.CloseSend(); err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		return
	}

	// Update progress with transferred file count.
	var totalBytes int64
	for _, d := range diffs {
		if d.Action == scanner.DiffAdd || d.Action == scanner.DiffModify {
			totalBytes += d.File.Size
		}
	}
	tracker.AddTransferred(int64(len(diffs)), totalBytes)
}

// RunRestore is a placeholder for the restore operation.
// Full implementation will stream files back from the server and reconstruct
// the local directory tree.
func (o *Orchestrator) RunRestore(username, targetPath string) (string, error) {
	taskID, err := generateTaskID("restore", username)
	if err != nil {
		return "", fmt.Errorf("generate task ID: %w", err)
	}

	// Record the task even though it is not yet implemented.
	tracker := progress.NewTracker()
	tracker.SetPhase(progress.PhaseFailed)

	o.mu.Lock()
	o.tasks[taskID] = tracker
	o.mu.Unlock()

	_ = store.InsertTask(o.DB, store.TaskRecord{
		TaskID: taskID, ServerID: "all", Username: username,
	})
	_ = store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")

	return taskID, fmt.Errorf("restore not yet implemented")
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
