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
servers:
  - address: backup-server:8443
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
}

func TestLoadAgentConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/cert.pem
  key_file: /etc/key.pem
servers: []
`), 0644)

	cfg, _ := LoadAgentConfig(path)
	if cfg.Retry.InitialInterval == 0 {
		t.Fatal("retry defaults should be set")
	}
}
