package svc

import (
	"context"

	"github.com/example/datavault/pkg/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/rules"
)

// extractUsername determines the calling user's username from SO_PEERCRED.
func (s *AgentService) extractUsername(ctx context.Context) (string, error) {
	uid, err := auth.GetPeerUIDFromContext(ctx)
	if err != nil {
		return "", status.Errorf(codes.Unauthenticated, "cannot determine peer user: %v", err)
	}

	username, err := auth.LookupUsername(uid)
	if err != nil {
		return "", status.Errorf(codes.Unauthenticated, "cannot lookup peer user: %v", err)
	}
	return username, nil
}

// AddUserRule adds a new backup rule for the calling user.
func (s *AgentService) AddUserRule(ctx context.Context, req *agentpbv1.AddUserRuleRequest) (*agentpbv1.AddUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	rule := rules.Rule{
		Name:    req.Name,
		Paths:   req.Paths,
		Exclude: req.Exclude,
	}
	if err := rule.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.UserRuleStore.Add(username, rule); err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "add rule: %v", err)
	}

	return &agentpbv1.AddUserRuleResponse{}, nil
}

// RemoveUserRule removes a backup rule by name for the calling user.
func (s *AgentService) RemoveUserRule(ctx context.Context, req *agentpbv1.RemoveUserRuleRequest) (*agentpbv1.RemoveUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.UserRuleStore.Remove(username, req.Name); err != nil {
		return nil, status.Errorf(codes.NotFound, "remove rule: %v", err)
	}

	return &agentpbv1.RemoveUserRuleResponse{}, nil
}

// ListUserRules returns all backup rules for the calling user.
func (s *AgentService) ListUserRules(ctx context.Context, req *agentpbv1.ListUserRulesRequest) (*agentpbv1.ListUserRulesResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	userRules, err := s.UserRuleStore.Load(username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load rules: %v", err)
	}

	resp := &agentpbv1.ListUserRulesResponse{}
	for _, r := range userRules {
		resp.Rules = append(resp.Rules, &agentpbv1.Rule{
			Name:    r.Name,
			Paths:   r.Paths,
			Exclude: r.Exclude,
			Enabled: r.Enabled,
		})
	}
	return resp, nil
}

// EnableUserRule enables a disabled backup rule by name for the calling user.
func (s *AgentService) EnableUserRule(ctx context.Context, req *agentpbv1.EnableUserRuleRequest) (*agentpbv1.EnableUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.UserRuleStore.SetEnabled(username, req.Name, true); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	return &agentpbv1.EnableUserRuleResponse{}, nil
}

// DisableUserRule disables an enabled backup rule by name for the calling user.
func (s *AgentService) DisableUserRule(ctx context.Context, req *agentpbv1.DisableUserRuleRequest) (*agentpbv1.DisableUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.UserRuleStore.SetEnabled(username, req.Name, false); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	return &agentpbv1.DisableUserRuleResponse{}, nil
}
