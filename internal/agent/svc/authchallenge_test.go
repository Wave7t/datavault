package svc

import (
	"context"
	"os"
	"testing"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
)

func TestGetAuthChallengeAddsPeerUsername(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	service := &AgentService{
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
			return &agentpbv1.AuthChallenge{Nonce: []byte("nonce"), Server: "server:8443"}, nil
		},
	}

	challenge, err := service.GetAuthChallenge(ctx, &agentpbv1.GetAuthChallengeRequest{Method: "GetQuotaUsage"})
	if err != nil {
		t.Fatalf("GetAuthChallenge: %v", err)
	}
	if challenge.Username == "" {
		t.Fatal("expected peer username")
	}
	if string(challenge.Nonce) != "nonce" || challenge.Server != "server:8443" {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
}

func TestGetAuthChallengeRejectsUnsupportedMethod(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	service := &AgentService{GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
		return &agentpbv1.AuthChallenge{}, nil
	}}

	_, err := service.GetAuthChallenge(ctx, &agentpbv1.GetAuthChallengeRequest{Method: "PushBackup"})
	if err == nil {
		t.Fatal("expected unsupported method error")
	}
}
