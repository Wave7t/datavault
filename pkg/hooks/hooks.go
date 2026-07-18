// Package hooks executes bounded, environment-only operator hook scripts.
package hooks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const defaultTimeout = 30 * time.Second

// TaskFailure carries the non-secret context exposed to a failure hook.
type TaskFailure struct {
	TaskID   string
	Username string
	Server   string
	Reason   string
	Elapsed  time.Duration
}

type QuotaWarning struct {
	Username string
	Server   string
	Used     int64
	Quota    int64
}

// RunTaskFailed invokes script after a terminal task failure. It does not use
// a shell, preserves the daemon environment, and adds DATAVAULT_* variables.
func RunTaskFailed(ctx context.Context, script string, event TaskFailure) error {
	return run(ctx, script, []string{
		"DATAVAULT_EVENT=task_failed",
		"DATAVAULT_TASK_ID=" + event.TaskID,
		"DATAVAULT_USER=" + event.Username,
		"DATAVAULT_SERVER=" + event.Server,
		"DATAVAULT_ERROR=" + event.Reason,
		"DATAVAULT_ELAPSED=" + event.Elapsed.String(),
	})
}

// RunQuotaWarning invokes script when a quota check crosses the configured
// warning threshold.
func RunQuotaWarning(ctx context.Context, script string, event QuotaWarning) error {
	return run(ctx, script, []string{
		"DATAVAULT_EVENT=quota_warning",
		"DATAVAULT_USER=" + event.Username,
		"DATAVAULT_SERVER=" + event.Server,
		fmt.Sprintf("DATAVAULT_USED_BYTES=%d", event.Used),
		fmt.Sprintf("DATAVAULT_QUOTA_BYTES=%d", event.Quota),
	})
}

func run(ctx context.Context, script string, variables []string) error {
	if script == "" {
		return nil
	}
	if !filepath.IsAbs(script) {
		return fmt.Errorf("failure hook must be an absolute path: %q", script)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, script)
	cmd.Env = append(os.Environ(), variables...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("run failure hook: %w: %s", err, string(output))
	}
	return nil
}
