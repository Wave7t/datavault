package config

import (
	"os"
	"path/filepath"
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
  backup_pool: tank/backups
`), 0644)

	cfg, _ := LoadServerConfig(path)
	if cfg.Server.Listen != "0.0.0.0:8443" {
		t.Fatalf("default listen: got %q", cfg.Server.Listen)
	}
	if cfg.UserPolicy.DefaultSchedule != "30 3 * * *" {
		t.Fatalf("default schedule: got %q", cfg.UserPolicy.DefaultSchedule)
	}
}
