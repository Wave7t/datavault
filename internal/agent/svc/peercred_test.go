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

func TestExtractCallerIdentityResolvesUIDAndUsername(t *testing.T) {
	service := &AgentService{}
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))

	ident, err := service.extractCallerIdentity(ctx)
	if err != nil {
		t.Fatalf("extractCallerIdentity: %v", err)
	}
	if ident.UID != uint32(os.Getuid()) {
		t.Fatalf("unexpected uid %d", ident.UID)
	}
	if ident.Username == "" {
		t.Fatal("expected non-empty username")
	}
}

func TestExtractCallerIdentityRequiresPeerUID(t *testing.T) {
	service := &AgentService{}

	_, err := service.extractCallerIdentity(context.Background())
	if err == nil {
		t.Fatal("expected missing peer UID error")
	}
}
