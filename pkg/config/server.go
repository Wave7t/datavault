package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ServerBlock struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
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

	return &cfg, nil
}
