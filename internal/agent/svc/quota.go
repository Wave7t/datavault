package svc

import (
	"context"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *AgentService) GetQuotaUsage(ctx context.Context, req *agentpbv1.GetQuotaUsageRequest) (*agentpbv1.QuotaUsage, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if s.GetQuotaUsageFn == nil {
		return nil, status.Error(codes.Unimplemented, "quota orchestrator not configured")
	}
	usage, err := s.GetQuotaUsageFn(username, req.Nonce, req.Signature)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get quota usage: %v", err)
	}
	return usage, nil
}
