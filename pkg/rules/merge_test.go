package rules

import (
	"testing"

	"github.com/example/datavault/pkg/config"
)

func TestMergeGlobalAndUserRules(t *testing.T) {
	global := []config.GlobalRule{
		{Name: "ssh-keys", Paths: []string{"/etc/ssh"}, Exclude: []string{"*.pub"}},
	}
	user := []Rule{
		{Name: "docs", Paths: []string{"/home/alice/docs"}, Enabled: true},
		{Name: "disabled-rule", Paths: []string{"/tmp"}, Enabled: false},
	}
	policy := config.UserPolicyBlock{
		DefaultSchedule: "30 3 * * *",
		DefaultQuotaGB:  20,
	}

	result := MergeUserRules(global, user, policy, "alice")

	// 1 global + 1 enabled user rule = 2
	if len(result.Rules) != 2 {
		t.Fatalf("expected 2 rules (1 global + 1 user), got %d", len(result.Rules))
	}
	if result.Schedule != "30 3 * * *" {
		t.Fatalf("expected default schedule, got %q", result.Schedule)
	}
	if result.QuotaGB != 20 {
		t.Fatalf("expected quota 20, got %d", result.QuotaGB)
	}
}

func TestMergePerUserOverride(t *testing.T) {
	policy := config.UserPolicyBlock{
		DefaultSchedule: "30 3 * * *",
		DefaultQuotaGB:  20,
		PerUserOverrides: map[string]config.UserOverride{
			"alice": {QuotaGB: 100, Schedule: "0 4 * * *"},
		},
	}

	result := MergeUserRules(nil, nil, policy, "alice")
	if result.QuotaGB != 100 {
		t.Fatalf("expected quota 100, got %d", result.QuotaGB)
	}
	if result.Schedule != "0 4 * * *" {
		t.Fatalf("expected overridden schedule, got %q", result.Schedule)
	}
}

func TestMergeNoOverride(t *testing.T) {
	policy := config.UserPolicyBlock{
		DefaultSchedule: "30 3 * * *",
		DefaultQuotaGB:  20,
	}

	result := MergeUserRules(nil, nil, policy, "bob")
	if result.QuotaGB != 20 {
		t.Fatalf("expected default quota 20, got %d", result.QuotaGB)
	}
}
