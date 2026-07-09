package svc

import (
	"context"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequestRestore initiates a restore operation to the specified target path.
func (s *AgentService) RequestRestore(ctx context.Context, req *agentpbv1.RequestRestoreRequest) (*agentpbv1.RequestRestoreResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	if s.RequestRestoreFn == nil {
		return nil, status.Error(codes.Unimplemented, "restore orchestrator not configured")
	}

	taskID, err := s.RequestRestoreFn(username, req.TargetPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "request restore: %v", err)
	}
	return &agentpbv1.RequestRestoreResponse{TaskId: taskID}, nil
}
