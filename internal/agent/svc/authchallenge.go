package svc

import (
	"context"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *AgentService) GetAuthChallenge(ctx context.Context, req *agentpbv1.GetAuthChallengeRequest) (*agentpbv1.AuthChallenge, error) {
	if req.Method != "GetQuotaUsage" && req.Method != "PullRestore" {
		return nil, status.Error(codes.InvalidArgument, "unsupported auth challenge method")
	}
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if s.GetAuthChallengeFn == nil {
		return nil, status.Error(codes.Unimplemented, "auth challenge provider not configured")
	}
	challenge, err := s.GetAuthChallengeFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get auth challenge: %v", err)
	}
	challenge.Username = username
	return challenge, nil
}
