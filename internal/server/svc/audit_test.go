package svc

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/example/datavault/internal/server/middleware"
)

func TestLogAuthDecision_Allow(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	LogAuthDecision(logger, "/backup.v1.BackupService/GetQuotaUsage", "web-01", "alice", 1020, middleware.DecisionAllow)
	line := buf.String()
	for _, want := range []string{"method=GetQuotaUsage", "agent=web-01", "user=alice", "uid=1020", "auth_method=host_vouched", "decision=allow"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %q", want, line)
		}
	}
}

func TestLogAuthDecision_RequireSig(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	LogAuthDecision(logger, "/backup.v1.BackupService/GetQuotaUsage", "web-01", "bob", 2040, middleware.DecisionRequireSig)
	line := buf.String()
	for _, want := range []string{"method=GetQuotaUsage", "agent=web-01", "user=bob", "uid=2040", "auth_method=ssh_signature", "decision=require_sig"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %q", want, line)
		}
	}
}

func TestLogAuthDecision_Deny(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	LogAuthDecision(logger, "/backup.v1.BackupService/GetQuotaUsage", "web-01", "eve", 3040, middleware.DecisionDeny)
	line := buf.String()
	for _, want := range []string{"method=GetQuotaUsage", "agent=web-01", "user=eve", "uid=3040", "auth_method=denied", "decision=deny"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %q", want, line)
		}
	}
}
