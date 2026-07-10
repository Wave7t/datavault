package svc

import (
	"context"
	"os"
	"testing"

	"github.com/example/datavault/pkg/auth"
)

func TestExtractUsernameUsesPeerUID(t *testing.T) {
	service := &AgentService{}
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))

	username, err := service.extractUsername(ctx)
	if err != nil {
		t.Fatalf("extractUsername: %v", err)
	}
	if username == "" {
		t.Fatal("expected non-empty username")
	}
}

func TestExtractUsernameRequiresPeerUID(t *testing.T) {
	service := &AgentService{}

	_, err := service.extractUsername(context.Background())
	if err == nil {
		t.Fatal("expected missing peer UID error")
	}
}
