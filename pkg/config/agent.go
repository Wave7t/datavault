package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type AgentBlock struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

type ServerEntry struct {
	Address       string `yaml:"address"`
	TLSServerName string `yaml:"tls_server_name,omitempty"`
}

type MachineRule struct {
	Name     string   `yaml:"name"`
	Paths    []string `yaml:"paths"`
	Schedule string   `yaml:"schedule"`
	Exclude  []string `yaml:"exclude,omitempty"`
	Enabled  bool     `yaml:"enabled"`
}

type RetryConfig struct {
	InitialInterval time.Duration `yaml:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval"`
	Multiplier      float64       `yaml:"multiplier"`
	Jitter          float64       `yaml:"jitter"`
	MaxElapsedTime  time.Duration `yaml:"max_elapsed_time"`
}

type HooksConfig struct {
	OnTaskFailed   string `yaml:"on_task_failed"`
	OnQuotaWarning string `yaml:"on_quota_warning"`
}

// ScheduleWindow limits scheduled machine backups to a local-time window.
// Manual CLI-triggered syncs are intentionally not limited by this policy.
type ScheduleWindow struct {
	Start string `yaml:"start"`
	End   string `yaml:"end"`
}

type AgentConfig struct {
	Agent        AgentBlock    `yaml:"agent"`
	Servers      []ServerEntry `yaml:"servers"`
	MachineRules []MachineRule `yaml:"machine_rules"`
	Retry        RetryConfig   `yaml:"retry"`
	Hooks        HooksConfig   `yaml:"hooks"`
	// BandwidthLimitBytesPerSecond is shared by one transfer attempt. Zero
	// means unlimited; use an explicit positive value in production configs.
	BandwidthLimitBytesPerSecond int64           `yaml:"bandwidth_limit_bytes_per_second"`
	ScheduleWindow               *ScheduleWindow `yaml:"schedule_window,omitempty"`
	// QuotaWarningPercent triggers hooks.on_quota_warning at or above this
	// percentage of a server-reported user quota. Zero disables the hook.
	QuotaWarningPercent int64 `yaml:"quota_warning_percent"`
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent config: %w", err)
	}

	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent config: %w", err)
	}

	// Defaults
	if cfg.Retry.InitialInterval == 0 {
		cfg.Retry.InitialInterval = 60 * time.Second
	}
	if cfg.Retry.MaxInterval == 0 {
		cfg.Retry.MaxInterval = 30 * time.Minute
	}
	if cfg.Retry.Multiplier == 0 {
		cfg.Retry.Multiplier = 2.0
	}
	if cfg.Retry.Jitter == 0 {
		cfg.Retry.Jitter = 0.1
	}
	if cfg.Retry.MaxElapsedTime == 0 {
		cfg.Retry.MaxElapsedTime = 4 * time.Hour
	}
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("at least one backup server is required")
	}
	for i, server := range cfg.Servers {
		if strings.TrimSpace(server.Address) == "" {
			return nil, fmt.Errorf("servers[%d].address is required", i)
		}
		if server.TLSServerName != "" && strings.TrimSpace(server.TLSServerName) == "" {
			return nil, fmt.Errorf("servers[%d].tls_server_name must not be blank", i)
		}
	}
	for field, value := range map[string]string{
		"agent.cert_file": cfg.Agent.CertFile,
		"agent.key_file":  cfg.Agent.KeyFile,
		"agent.ca_file":   cfg.Agent.CAFile,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s is required", field)
		}
	}
	if cfg.Retry.InitialInterval <= 0 || cfg.Retry.MaxInterval <= 0 || cfg.Retry.MaxElapsedTime <= 0 {
		return nil, fmt.Errorf("retry intervals must be positive")
	}
	if cfg.Retry.MaxInterval < cfg.Retry.InitialInterval {
		return nil, fmt.Errorf("retry.max_interval must be at least retry.initial_interval")
	}
	if cfg.Retry.Multiplier < 1 {
		return nil, fmt.Errorf("retry.multiplier must be at least 1")
	}
	if cfg.Retry.Jitter < 0 || cfg.Retry.Jitter > 1 {
		return nil, fmt.Errorf("retry.jitter must be between 0 and 1")
	}
	if cfg.BandwidthLimitBytesPerSecond < 0 {
		return nil, fmt.Errorf("bandwidth_limit_bytes_per_second must not be negative")
	}
	if cfg.QuotaWarningPercent < 0 || cfg.QuotaWarningPercent > 100 {
		return nil, fmt.Errorf("quota_warning_percent must be between 0 and 100")
	}
	for field, script := range map[string]string{
		"hooks.on_task_failed":   cfg.Hooks.OnTaskFailed,
		"hooks.on_quota_warning": cfg.Hooks.OnQuotaWarning,
	} {
		if script != "" && !filepath.IsAbs(script) {
			return nil, fmt.Errorf("%s must be an absolute path", field)
		}
	}
	if cfg.ScheduleWindow != nil {
		if _, err := time.Parse("15:04", cfg.ScheduleWindow.Start); err != nil {
			return nil, fmt.Errorf("schedule_window.start must be HH:MM: %w", err)
		}
		if _, err := time.Parse("15:04", cfg.ScheduleWindow.End); err != nil {
			return nil, fmt.Errorf("schedule_window.end must be HH:MM: %w", err)
		}
		if cfg.ScheduleWindow.Start == cfg.ScheduleWindow.End {
			return nil, fmt.Errorf("schedule_window start and end must differ")
		}
	}
	for i, rule := range cfg.MachineRules {
		if strings.TrimSpace(rule.Name) == "" || len(rule.Paths) == 0 {
			return nil, fmt.Errorf("machine_rules[%d] requires a name and at least one path", i)
		}
		if rule.Enabled && strings.TrimSpace(rule.Schedule) == "" {
			return nil, fmt.Errorf("machine_rules[%d].schedule is required for enabled rules", i)
		}
		for _, path := range rule.Paths {
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("machine_rules[%d] path must be absolute: %q", i, path)
			}
		}
	}

	return &cfg, nil
}
