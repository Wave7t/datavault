package middleware

import (
	"testing"

	"github.com/example/datavault/pkg/config"
)

func hostVouchedCfg(agent string, trust config.TrustPolicy, caps []string) *config.ServerConfig {
	return &config.ServerConfig{
		AllowedHosts: []config.AllowedHost{{CN: agent}},
		UserAuth: config.UserAuth{
			DefaultMode: "per_user_key",
			Agents: []config.UserAuthAgentEntry{
				{Agent: agent, Mode: "host_vouched", Trust: trust, Capabilities: caps},
			},
		},
	}
}

func TestDecideAuth_PerUserKeyDefault_RequiresSig(t *testing.T) {
	cfg := &config.ServerConfig{UserAuth: config.UserAuth{DefaultMode: "per_user_key"}}
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", nil, "/backup.v1.BackupService/GetQuotaUsage")
	if d != DecisionRequireSig {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_HostVouched_TrustsByMinUID(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", nil, "/backup.v1.BackupService/PushBackup")
	if d != DecisionAllow {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_HostVouched_TrustsByGroup(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000, Groups: []string{"backupusers"}}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", []string{"backupusers"}, "/backup.v1.BackupService/PushBackup")
	if d != DecisionAllow {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_HostVouched_RejectsLowUID(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 999, "svc", nil, "/backup.v1.BackupService/PushBackup")
	if d != DecisionDeny {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_HostVouched_RejectsMissingGroup(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000, Groups: []string{"backupusers"}}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", []string{"everyone"}, "/backup.v1.BackupService/PushBackup")
	if d != DecisionDeny {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_HostVouched_RespectsExclude(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000, Exclude: []string{"alice"}}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", nil, "/backup.v1.BackupService/PushBackup")
	if d != DecisionDeny {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_HostVouched_IncludeBeatsMinUID(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000, Include: []string{"service"}}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 100, "service", nil, "/backup.v1.BackupService/PushBackup")
	if d != DecisionAllow {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_CapabilityNotListed_RequiresSig(t *testing.T) {
	// agent configured with only [backup]; restore request falls back to per_user_key path
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", nil, "/backup.v1.BackupService/PullRestore")
	if d != DecisionRequireSig {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_PerAgentOverrideToPerUserKey(t *testing.T) {
	// default is host_vouched but web-02 is overridden to per_user_key
	cfg := &config.ServerConfig{
		UserAuth: config.UserAuth{
			DefaultMode: "host_vouched",
			Agents: []config.UserAuthAgentEntry{
				{Agent: "web-02", Mode: "per_user_key"},
			},
		},
	}
	d, _ := DecideAuth(cfg, "web-02", 1020, "alice", nil, "/backup.v1.BackupService/PushBackup")
	if d != DecisionRequireSig {
		t.Fatalf("got %v", d)
	}
}

func TestDecideAuth_GroupCheckIsAnyOf(t *testing.T) {
	cfg := hostVouchedCfg("web-01", config.TrustPolicy{MinUID: 1000, Groups: []string{"backupusers", "operators"}}, []string{"backup"})
	d, _ := DecideAuth(cfg, "web-01", 1020, "alice", []string{"everyone", "operators"}, "/backup.v1.BackupService/PushBackup")
	if d != DecisionAllow {
		t.Fatalf("got %v", d)
	}
}

func TestMethodToCapability(t *testing.T) {
	cases := map[string]string{
		"/backup.v1.BackupService/PushBackup":            CapBackup,
		"/backup.v1.BackupService/GetQuotaUsage":         CapQuota,
		"/backup.v1.BackupService/PullRestore":           CapRestore,
		"/backup.v1.BackupService/RegisterDelegationKey": CapDelegation,
		"/backup.v1.BackupService/RemoveDelegationKey":   CapDelegation,
		"/backup.v1.BackupService/RegisterTaskGrant":     CapDelegation,
		"/backup.v1.BackupService/GetChallenge":          "",
	}
	for m, want := range cases {
		if got := MethodToCapability(m); got != want {
			t.Fatalf("%s: got %q want %q", m, got, want)
		}
	}
}
