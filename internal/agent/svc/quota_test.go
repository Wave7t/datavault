package svc

import (
	"context"
	"os"
	"testing"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
)

func TestGetQuotaUsageUsesPeerUser(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	called := false
	service := &AgentService{
		GetQuotaUsageFn: func(username, server string, nonce, signature []byte) (*agentpbv1.QuotaUsage, error) {
			called = true
			if username == "" {
				t.Fatal("expected username")
			}
			if server != "server:8443" {
				t.Fatalf("unexpected server %q", server)
			}
			if string(nonce) != "nonce" || string(signature) != "signature" {
				t.Fatalf("unexpected auth material: %q/%q", nonce, signature)
			}
			return &agentpbv1.QuotaUsage{UsedBytes: 10, QuotaBytes: 20, Dataset: "tank/host/user", Server: "server:8443"}, nil
		},
	}

	usage, err := service.GetQuotaUsage(ctx, &agentpbv1.GetQuotaUsageRequest{Nonce: []byte("nonce"), Signature: []byte("signature"), Server: "server:8443"})
	if err != nil {
		t.Fatalf("GetQuotaUsage: %v", err)
	}
	if !called {
		t.Fatal("expected quota hook to be called")
	}
	if usage.UsedBytes != 10 || usage.QuotaBytes != 20 {
		t.Fatalf("unexpected usage: %#v", usage)
	}
}

func TestGetQuotaUsageRequiresHook(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	service := &AgentService{}

	_, err := service.GetQuotaUsage(ctx, &agentpbv1.GetQuotaUsageRequest{})
	if err == nil {
		t.Fatal("expected missing hook error")
	}
}
