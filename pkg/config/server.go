package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/example/datavault/pkg/zfs"
	"gopkg.in/yaml.v3"
)

type ServerBlock struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	Listen     string `yaml:"listen"`
	BackupPool string `yaml:"backup_pool"`
}

type AllowedHost struct {
	CN string `yaml:"cn"`
}

type GlobalRule struct {
	Name    string   `yaml:"name"`
	Paths   []string `yaml:"paths"`
	Exclude []string `yaml:"exclude,omitempty"`
}

type UserOverride struct {
	QuotaGB  int64  `yaml:"quota_gb"`
	Schedule string `yaml:"schedule,omitempty"`
}

type UserPolicyBlock struct {
	DefaultSchedule  string                  `yaml:"default_schedule"`
	DefaultQuotaGB   int64                   `yaml:"default_quota_gb"`
	PerUserOverrides map[string]UserOverride `yaml:"per_user_overrides,omitempty"`
}

type SnapshotPolicyBlock struct {
	MinSnapshots int   `yaml:"min_snapshots"`
	MaxSnapshots int   `yaml:"max_snapshots"`
	MinFreeGB    int64 `yaml:"min_free_gb"`
}

type ServerConfig struct {
	Server         ServerBlock         `yaml:"server"`
	AllowedHosts   []AllowedHost       `yaml:"allowed_hosts"`
	GlobalRules    []GlobalRule        `yaml:"global_rules"`
	UserPolicy     UserPolicyBlock     `yaml:"user_policy"`
	SnapshotPolicy SnapshotPolicyBlock `yaml:"snapshot_policy"`
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config: %w", err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse server config: %w", err)
	}

	// Defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0:8443"
	}
	if cfg.SnapshotPolicy.MinSnapshots < 2 {
		cfg.SnapshotPolicy.MinSnapshots = 2
	}
	if cfg.SnapshotPolicy.MaxSnapshots == 0 {
		cfg.SnapshotPolicy.MaxSnapshots = 7
	}
	if cfg.UserPolicy.DefaultQuotaGB == 0 {
		cfg.UserPolicy.DefaultQuotaGB = 20
	}
	if cfg.UserPolicy.DefaultSchedule == "" {
		cfg.UserPolicy.DefaultSchedule = "30 3 * * *"
	}
	for field, value := range map[string]string{
		"server.cert_file":   cfg.Server.CertFile,
		"server.key_file":    cfg.Server.KeyFile,
		"server.ca_file":     cfg.Server.CAFile,
		"server.backup_pool": cfg.Server.BackupPool,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s is required", field)
		}
	}
	if err := zfs.ValidateDatasetName(cfg.Server.BackupPool); err != nil {
		return nil, fmt.Errorf("server.backup_pool: %w", err)
	}
	if len(cfg.AllowedHosts) == 0 {
		return nil, fmt.Errorf("at least one allowed_hosts entry is required")
	}
	for i, host := range cfg.AllowedHosts {
		if err := zfs.ValidateHostname(host.CN); err != nil {
			return nil, fmt.Errorf("allowed_hosts[%d].cn: %w", i, err)
		}
	}
	if cfg.UserPolicy.DefaultQuotaGB <= 0 {
		return nil, fmt.Errorf("user_policy.default_quota_gb must be positive")
	}
	for username, override := range cfg.UserPolicy.PerUserOverrides {
		if err := zfs.ValidateUsername(username); err != nil {
			return nil, fmt.Errorf("user_policy.per_user_overrides[%q]: %w", username, err)
		}
		if override.QuotaGB <= 0 {
			return nil, fmt.Errorf("user_policy.per_user_overrides[%q].quota_gb must be positive", username)
		}
	}
	if cfg.SnapshotPolicy.MaxSnapshots < cfg.SnapshotPolicy.MinSnapshots {
		return nil, fmt.Errorf("snapshot_policy.max_snapshots must be at least min_snapshots")
	}
	if cfg.SnapshotPolicy.MinFreeGB < 0 {
		return nil, fmt.Errorf("snapshot_policy.min_free_gb must not be negative")
	}

	return &cfg, nil
}
