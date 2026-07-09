package svc

import (
	"context"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TriggerSync triggers a backup sync for the specified rule (or all rules if empty).
func (s *AgentService) TriggerSync(ctx context.Context, req *agentpbv1.TriggerSyncRequest) (*agentpbv1.TriggerSyncResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	if s.TriggerSyncFn == nil {
		return nil, status.Error(codes.Unimplemented, "sync orchestrator not configured")
	}

	taskID, err := s.TriggerSyncFn(username, req.RuleName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "trigger sync: %v", err)
	}
	return &agentpbv1.TriggerSyncResponse{TaskId: taskID}, nil
}
