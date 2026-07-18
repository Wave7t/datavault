package svc

import (
	"context"
	"os"
	"testing"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
)

func TestGetSyncStatusPassesPeerUsernameToStatusProvider(t *testing.T) {
	stream := &fakeStatusStream{ctx: auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))}
	service := &AgentService{GetStatusFn: func(username, taskID string) (*agentpbv1.SyncStatusUpdate, error) {
		if username == "" || taskID != "task-1" {
			t.Fatalf("unexpected status lookup: user=%q task=%q", username, taskID)
		}
		return &agentpbv1.SyncStatusUpdate{TaskId: taskID, Phase: "FAILED", Error: "server unavailable"}, nil
	}}

	if err := service.GetSyncStatus(&agentpbv1.GetSyncStatusRequest{TaskId: "task-1"}, stream); err != nil {
		t.Fatalf("GetSyncStatus: %v", err)
	}
	if len(stream.updates) != 1 || stream.updates[0].Phase != "FAILED" || stream.updates[0].Error != "server unavailable" {
		t.Fatalf("unexpected status updates: %#v", stream.updates)
	}
}

type fakeStatusStream struct {
	agentpbv1.AgentService_GetSyncStatusServer
	ctx     context.Context
	updates []*agentpbv1.SyncStatusUpdate
}

func (s *fakeStatusStream) Context() context.Context { return s.ctx }

func (s *fakeStatusStream) Send(update *agentpbv1.SyncStatusUpdate) error {
	s.updates = append(s.updates, update)
	return nil
}
