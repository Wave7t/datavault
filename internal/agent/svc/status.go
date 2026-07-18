package svc

import (
	"time"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetSyncStatus streams progress updates for a sync task.
// It polls the orchestrator via GetStatusFn until the task completes or fails.
func (s *AgentService) GetSyncStatus(req *agentpbv1.GetSyncStatusRequest, stream agentpbv1.AgentService_GetSyncStatusServer) error {
	if s.GetStatusFn == nil {
		return status.Error(codes.Unimplemented, "status tracker not configured")
	}
	username, err := s.extractUsername(stream.Context())
	if err != nil {
		return err
	}

	for {
		update, err := s.GetStatusFn(username, req.TaskId)
		if err != nil {
			return status.Errorf(codes.NotFound, "task not found: %v", err)
		}
		if err := stream.Send(update); err != nil {
			return err
		}
		if update.Phase == "COMPLETED" || update.Phase == "FAILED" {
			return nil
		}
		select {
		case <-stream.Context().Done():
			return status.FromContextError(stream.Context().Err()).Err()
		case <-time.After(time.Second):
		}
	}
}
