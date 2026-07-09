package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type AgentBlock struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type ServerEntry struct {
	Address string `yaml:"address"`
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

type AgentConfig struct {
	Agent        AgentBlock    `yaml:"agent"`
	Servers      []ServerEntry `yaml:"servers"`
	MachineRules []MachineRule `yaml:"machine_rules"`
	Retry        RetryConfig   `yaml:"retry"`
	Hooks        HooksConfig   `yaml:"hooks"`
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

	return &cfg, nil
}
