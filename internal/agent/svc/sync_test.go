package svc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
)

func TestTriggerSyncForwardsCallerSSHAgentSocket(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	called := false
	service := &AgentService{TriggerSyncFn: func(username, ruleName, sshAuthSock string, uid uint32) (string, error) {
		called = true
		if username == "" || ruleName != "only-this-rule" || sshAuthSock != socketPath || uid != uint32(os.Getuid()) {
			t.Fatalf("unexpected trigger arguments: user=%q rule=%q socket=%q uid=%d", username, ruleName, sshAuthSock, uid)
		}
		return "sync-1", nil
	}}

	response, err := service.TriggerSync(ctx, &agentpbv1.TriggerSyncRequest{
		RuleName:    "only-this-rule",
		SshAuthSock: socketPath,
	})
	if err != nil {
		t.Fatalf("TriggerSync: %v", err)
	}
	if !called || response.TaskId != "sync-1" {
		t.Fatalf("unexpected trigger response: called=%v response=%#v", called, response)
	}
}

func TestTriggerSyncRequiresCallerSSHAgentSocket(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	service := &AgentService{TriggerSyncFn: func(string, string, string, uint32) (string, error) {
		t.Fatal("sync hook should not be called without SSH agent socket")
		return "", nil
	}}
	if _, err := service.TriggerSync(ctx, &agentpbv1.TriggerSyncRequest{}); err == nil {
		t.Fatal("expected missing SSH agent socket to be rejected")
	}
}

func TestTriggerSyncRejectsInvalidCallerSSHAgentSocket(t *testing.T) {
	ctx := auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
	service := &AgentService{TriggerSyncFn: func(string, string, string, uint32) (string, error) {
		t.Fatal("sync hook should not be called with an invalid SSH agent socket")
		return "", nil
	}}
	if _, err := service.TriggerSync(ctx, &agentpbv1.TriggerSyncRequest{SshAuthSock: "relative.sock"}); err == nil {
		t.Fatal("expected invalid SSH agent socket to be rejected")
	}
}
