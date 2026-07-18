package hooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunTaskFailedPassesEventEnvironment(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s' \"$DATAVAULT_TASK_ID\" \"$DATAVAULT_USER\" \"$DATAVAULT_EVENT\" > \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// The hook interface intentionally has no user-controlled positional
	// arguments; bake the output path into a wrapper script for this test.
	wrapped := filepath.Join(dir, "wrapped.sh")
	if err := os.WriteFile(wrapped, []byte("#!/bin/sh\nprintf '%s|%s|%s' \"$DATAVAULT_TASK_ID\" \"$DATAVAULT_USER\" \"$DATAVAULT_EVENT\" > "+output+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := RunTaskFailed(context.Background(), wrapped, TaskFailure{TaskID: "task-1", Username: "alice", Server: "server:8443", Reason: "offline", Elapsed: time.Second}); err != nil {
		t.Fatalf("RunTaskFailed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != "task-1|alice|task_failed" {
		t.Fatalf("hook environment=%q", got)
	}
}

func TestRunTaskFailedRejectsRelativeScript(t *testing.T) {
	if err := RunTaskFailed(context.Background(), "hook.sh", TaskFailure{}); err == nil {
		t.Fatal("expected relative hook path to be rejected")
	}
}

func TestRunQuotaWarningPassesUsage(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s' \"$DATAVAULT_EVENT\" \"$DATAVAULT_USED_BYTES\" \"$DATAVAULT_QUOTA_BYTES\" > "+output+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := RunQuotaWarning(context.Background(), script, QuotaWarning{Username: "alice", Server: "server", Used: 90, Quota: 100}); err != nil {
		t.Fatalf("RunQuotaWarning: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != "quota_warning|90|100" {
		t.Fatalf("quota hook environment=%q", got)
	}
}
