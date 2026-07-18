package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAgentConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem
servers:
  - address: backup-server:8443
    tls_server_name: backup.internal.example
machine_rules:
  - name: app-config
    paths: [/opt/app/data]
    schedule: "0 3 * * *"
    enabled: true
`), 0644)

	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(cfg.Servers))
	}
	if len(cfg.MachineRules) != 1 {
		t.Fatalf("expected 1 machine rule, got %d", len(cfg.MachineRules))
	}
	if cfg.Agent.CAFile != "/etc/datavault/agent/ca.pem" {
		t.Fatalf("unexpected CA file %q", cfg.Agent.CAFile)
	}
	if cfg.Servers[0].TLSServerName != "backup.internal.example" {
		t.Fatalf("unexpected TLS server name %q", cfg.Servers[0].TLSServerName)
	}
}

func TestLoadAgentConfigRejectsNoServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/cert.pem
  key_file: /etc/key.pem
servers: []
`), 0644)

	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected empty servers to be rejected")
	}
}

func TestLoadAgentConfigRejectsEmptyServerAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("servers:\n  - address: '   '\n"), 0644)

	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected empty server address to be rejected")
	}
}

func TestLoadAgentConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem
servers:
  - address: backup-server:8443
`), 0644)

	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if cfg.Retry.InitialInterval == 0 {
		t.Fatal("retry defaults should be set")
	}
}

func TestLoadAgentConfigRejectsMissingTLSFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("servers:\n  - address: backup-server:8443\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentConfig(path); err == nil {
		t.Fatal("expected missing TLS configuration to be rejected")
	}
}

func TestLoadAgentConfigRejectsRelativeMachinePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem
servers:
  - address: backup-server:8443
machine_rules:
  - name: invalid
    paths: [relative]
    schedule: "0 3 * * *"
    enabled: true
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentConfig(path); err == nil {
		t.Fatal("expected relative machine path to be rejected")
	}
}

func TestLoadAgentConfigRejectsInvalidOperationalLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem
servers:
  - address: backup-server:8443
bandwidth_limit_bytes_per_second: -1
hooks:
  on_task_failed: relative-hook
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentConfig(path); err == nil {
		t.Fatal("expected invalid operational limits to be rejected")
	}
}

func TestLoadAgentConfigAcceptsScheduleWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem
servers:
  - address: backup-server:8443
bandwidth_limit_bytes_per_second: 1048576
schedule_window:
  start: "22:00"
  end: "06:00"
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if cfg.BandwidthLimitBytesPerSecond != 1048576 || cfg.ScheduleWindow == nil {
		t.Fatalf("unexpected operational config: %#v", cfg)
	}
}
