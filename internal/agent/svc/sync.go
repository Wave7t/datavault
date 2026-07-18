package svc

import (
	"context"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
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
	uid, err := auth.GetPeerUIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cannot determine peer user: %v", err)
	}
	if req.SshAuthSock == "" {
		return nil, status.Error(codes.InvalidArgument, "SSH_AUTH_SOCK is required for user sync")
	}
	if err := auth.ValidateSSHAgentSocketForUser(req.SshAuthSock, uid); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "validate SSH_AUTH_SOCK: %v", err)
	}

	taskID, err := s.TriggerSyncFn(username, req.RuleName, req.SshAuthSock, uid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "trigger sync: %v", err)
	}
	return &agentpbv1.TriggerSyncResponse{TaskId: taskID}, nil
}
