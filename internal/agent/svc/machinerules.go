package svc

import (
	"context"
	"os"
	"path/filepath"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// AddMachineRule adds a machine-level backup rule to the agent config.
// Only root can manage machine rules.
func (s *AgentService) AddMachineRule(ctx context.Context, req *agentpbv1.AddMachineRuleRequest) (*agentpbv1.AddMachineRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if username != "root" {
		return nil, status.Error(codes.PermissionDenied, "only root can manage machine rules")
	}

	s.Cfg.MachineRules = append(s.Cfg.MachineRules, config.MachineRule{
		Name:     req.Name,
		Paths:    req.Paths,
		Schedule: req.Schedule,
		Exclude:  req.Exclude,
		Enabled:  true,
	})

	if err := saveAgentConfig(s.ConfigPath, s.Cfg); err != nil {
		return nil, status.Errorf(codes.Internal, "save config: %v", err)
	}
	return &agentpbv1.AddMachineRuleResponse{}, nil
}

// RemoveMachineRule removes a machine-level backup rule from the agent config.
// Only root can manage machine rules.
func (s *AgentService) RemoveMachineRule(ctx context.Context, req *agentpbv1.RemoveMachineRuleRequest) (*agentpbv1.RemoveMachineRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if username != "root" {
		return nil, status.Error(codes.PermissionDenied, "only root can manage machine rules")
	}

	found := false
	filtered := make([]config.MachineRule, 0, len(s.Cfg.MachineRules))
	for _, r := range s.Cfg.MachineRules {
		if r.Name == req.Name {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "machine rule %q not found", req.Name)
	}
	s.Cfg.MachineRules = filtered

	if err := saveAgentConfig(s.ConfigPath, s.Cfg); err != nil {
		return nil, status.Errorf(codes.Internal, "save config: %v", err)
	}
	return &agentpbv1.RemoveMachineRuleResponse{}, nil
}

// ListMachineRules returns all machine-level backup rules.
func (s *AgentService) ListMachineRules(ctx context.Context, req *agentpbv1.ListMachineRulesRequest) (*agentpbv1.ListMachineRulesResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if username != "root" {
		return nil, status.Error(codes.PermissionDenied, "only root can list machine rules")
	}

	resp := &agentpbv1.ListMachineRulesResponse{}
	for _, r := range s.Cfg.MachineRules {
		resp.Rules = append(resp.Rules, &agentpbv1.Rule{
			Name:    r.Name,
			Paths:   r.Paths,
			Exclude: r.Exclude,
			Enabled: r.Enabled,
		})
	}
	return resp, nil
}

// saveAgentConfig marshals the agent config back to YAML and writes it to disk.
func saveAgentConfig(path string, cfg *config.AgentConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".datavault-config-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
