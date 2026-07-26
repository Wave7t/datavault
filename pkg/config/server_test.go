package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadServerConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  ca_file: /etc/datavault/server/ca.pem
  backup_pool: tank/backups
allowed_hosts:
  - cn: web-01.example.com
snapshot_policy:
  min_snapshots: 2
  max_snapshots: 7
  min_free_gb: 1000
`), 0644)

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Server.BackupPool != "tank/backups" {
		t.Fatalf("backup_pool: got %q", cfg.Server.BackupPool)
	}
	if len(cfg.AllowedHosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(cfg.AllowedHosts))
	}
	if cfg.Server.CAFile != "/etc/datavault/server/ca.pem" {
		t.Fatalf("unexpected CA file %q", cfg.Server.CAFile)
	}
}

func TestLoadServerConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  ca_file: /etc/datavault/server/ca.pem
  backup_pool: tank/backups
allowed_hosts:
  - cn: web-01.example.com
`), 0644)

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:8443" {
		t.Fatalf("default listen: got %q", cfg.Server.Listen)
	}
	if cfg.UserPolicy.DefaultSchedule != "30 3 * * *" {
		t.Fatalf("default schedule: got %q", cfg.UserPolicy.DefaultSchedule)
	}
	if cfg.KeyEnrollment.Mode != "admin_only" {
		t.Fatalf("default key enrollment mode: got %q", cfg.KeyEnrollment.Mode)
	}
}

func TestLoadServerConfigRejectsUnsafePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  ca_file: /etc/datavault/server/ca.pem
  backup_pool: tank/backups
allowed_hosts:
  - cn: web-01.example.com
snapshot_policy:
  min_snapshots: 3
  max_snapshots: 2
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("expected unsafe snapshot retention policy to be rejected")
	}
}

func TestLoadServerConfigValidatesKeyEnrollmentPolicy(t *testing.T) {
	base := `
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  ca_file: /etc/datavault/server/ca.pem
  backup_pool: tank/backups
allowed_hosts:
  - cn: relay-01
key_enrollment:
  mode: server_os_login
  server_os_login:
    allowed_agents: [relay-01]
    min_uid: 1000
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err != nil {
		t.Fatalf("expected valid enrollment policy: %v", err)
	}

	invalid := strings.Replace(base, "allowed_agents: [relay-01]", "allowed_agents: [other-agent]", 1)
	if err := os.WriteFile(path, []byte(invalid), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("expected enrollment agent outside allowed_hosts to be rejected")
	}
}

// writeTmp writes the given yaml content to a file in a temp dir and returns
// the path. It is a convenience helper for tests that exercise LoadServerConfig
// with inline configs.
func writeTmp(t *testing.T, yamlContent string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("writeTmp: %v", err)
	}
	return path
}

func TestUserAuthDefaultsToPerUserKey(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server_minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserAuth.DefaultMode != "per_user_key" {
		t.Fatalf("default mode: got %q", cfg.UserAuth.DefaultMode)
	}
}

func TestUserAuthRejectsAgentNotInAllowedHosts(t *testing.T) {
	yaml := `server: {cert_file: c, key_file: k, ca_file: a, backup_pool: tank}
allowed_hosts: [{cn: web-01}]
user_policy: {default_quota_gb: 20}
user_auth:
  default_mode: host_vouched
  agents:
    - agent: web-02       # not in allowed_hosts
      mode: host_vouched
      capabilities: [backup]
`
	tmp := writeTmp(t, yaml)
	_, err := LoadServerConfig(tmp)
	if err == nil || !strings.Contains(err.Error(), "not in allowed_hosts") {
		t.Fatalf("expected allowed_hosts rejection, got %v", err)
	}
}

func TestUserAuthRejectsUnknownCapability(t *testing.T) {
	yaml := `server: {cert_file: c, key_file: k, ca_file: a, backup_pool: tank}
allowed_hosts: [{cn: web-01}]
user_policy: {default_quota_gb: 20}
user_auth:
  agents:
    - agent: web-01
      mode: host_vouched
      trust: {min_uid: 1000}
      capabilities: [frobnicate]
`
	tmp := writeTmp(t, yaml)
	_, err := LoadServerConfig(tmp)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown-capability rejection, got %v", err)
	}
}

func TestUserAuthRejectsEmptyTrustPolicy(t *testing.T) {
	yaml := `server: {cert_file: c, key_file: k, ca_file: a, backup_pool: tank}
allowed_hosts: [{cn: web-01}]
user_policy: {default_quota_gb: 20}
user_auth:
  agents:
    - agent: web-01
      mode: host_vouched
      capabilities: [backup]
`
	tmp := writeTmp(t, yaml)
	_, err := LoadServerConfig(tmp)
	if err == nil || !strings.Contains(err.Error(), "at least one of") {
		t.Fatalf("expected empty-trust rejection, got %v", err)
	}
}

func TestUserAuthEntryForAgent(t *testing.T) {
	// verifies ModeForAgent falls back to DefaultMode when agent not listed,
	// and EntryForAgent returns the per-agent entry when present.
	cfg := &UserAuth{
		DefaultMode: "per_user_key",
		Agents: []UserAuthAgentEntry{
			{Agent: "web-01", Mode: "host_vouched", Trust: TrustPolicy{MinUID: 1000}, Capabilities: []string{"backup"}},
		},
	}
	if cfg.ModeForAgent("web-01") != "host_vouched" {
		t.Fatal("expected host_vouched")
	}
	if cfg.ModeForAgent("other") != "per_user_key" {
		t.Fatal("expected fallback to default")
	}
	if _, ok := cfg.EntryForAgent("web-01"); !ok {
		t.Fatal("expected entry found")
	}
	if _, ok := cfg.EntryForAgent("other"); ok {
		t.Fatal("expected entry not found")
	}
}
