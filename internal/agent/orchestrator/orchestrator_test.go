package orchestrator

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/example/datavault/internal/agent/pool"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// metaCaptureClient is a BackupServiceClient fake that records the context of
// the most recent GetQuotaUsage call so tests can assert on outbound metadata.
type metaCaptureClient struct {
	lastQuotaCtx context.Context
}

func (c *metaCaptureClient) GetChallenge(ctx context.Context, _ *backuppbv1.GetChallengeRequest, _ ...grpc.CallOption) (*backuppbv1.Challenge, error) {
	return &backuppbv1.Challenge{Nonce: []byte("nonce")}, nil
}

func (c *metaCaptureClient) GetGlobalConfig(ctx context.Context, _ *backuppbv1.GetGlobalConfigRequest, _ ...grpc.CallOption) (*backuppbv1.GlobalConfig, error) {
	return &backuppbv1.GlobalConfig{}, nil
}

func (c *metaCaptureClient) PushBackup(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck], error) {
	return nil, nil
}

func (c *metaCaptureClient) GetQuotaUsage(ctx context.Context, _ *backuppbv1.GetQuotaUsageRequest, _ ...grpc.CallOption) (*backuppbv1.QuotaUsage, error) {
	c.lastQuotaCtx = ctx
	return &backuppbv1.QuotaUsage{UsedBytes: 1, QuotaBytes: 100, Dataset: "tank/ds"}, nil
}

func (c *metaCaptureClient) PullRestore(ctx context.Context, _ *backuppbv1.PullRestoreRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[backuppbv1.RestoreBatch], error) {
	return nil, nil
}

func (c *metaCaptureClient) RegisterDelegationKey(ctx context.Context, _ *backuppbv1.RegisterDelegationKeyRequest, _ ...grpc.CallOption) (*backuppbv1.RegisterDelegationKeyResponse, error) {
	return nil, nil
}

func (c *metaCaptureClient) RemoveDelegationKey(ctx context.Context, _ *backuppbv1.RemoveDelegationKeyRequest, _ ...grpc.CallOption) (*backuppbv1.RemoveDelegationKeyResponse, error) {
	return nil, nil
}

func (c *metaCaptureClient) RegisterTaskGrant(ctx context.Context, _ *backuppbv1.RegisterTaskGrantRequest, _ ...grpc.CallOption) (*backuppbv1.RegisterTaskGrantResponse, error) {
	return nil, nil
}

// newMetaTestOrch builds an Orchestrator wired to a conn pool that returns
// fakeClient for the configured server address, so tests can call user-facing
// RPC methods without a live Server.
func newMetaTestOrch(t *testing.T, fakeClient backuppbv1.BackupServiceClient) (*Orchestrator, *pool.ConnPool) {
	t.Helper()
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.MigrateTasks(db); err != nil {
		t.Fatalf("migrate tasks: %v", err)
	}

	certFile, keyFile, caFile := writeTempCerts(t)
	connPool, err := pool.New(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(func() { connPool.Close() })
	connPool.SetClientForTest("server:8443\x00", fakeClient)

	cfg := &config.AgentConfig{
		Servers: []config.ServerEntry{{Address: "server:8443"}},
	}
	return New(cfg, connPool, db, nil), connPool
}

// TestGetQuotaUsageAttachesCallerMetadata verifies that GetQuotaUsage attaches
// x-caller-uid and x-caller-groups metadata to the outbound GetQuotaUsage RPC.
func TestGetQuotaUsageAttachesCallerMetadata(t *testing.T) {
	fake := &metaCaptureClient{}
	orch, _ := newMetaTestOrch(t, fake)

	uid := uint32(1020)
	groups := []string{"g1", "g2"}
	if _, err := orch.GetQuotaUsage("alice", "server:8443", uid, groups, []byte("nonce"), []byte("sig")); err != nil {
		t.Fatalf("GetQuotaUsage: %v", err)
	}
	if fake.lastQuotaCtx == nil {
		t.Fatal("GetQuotaUsage did not reach the fake client")
	}
	md, ok := metadata.FromOutgoingContext(fake.lastQuotaCtx)
	if !ok {
		t.Fatal("expected outgoing metadata on GetQuotaUsage ctx")
	}
	if got := md.Get("x-caller-uid"); len(got) != 1 || got[0] != "1020" {
		t.Fatalf("x-caller-uid = %v, want [\"1020\"]", got)
	}
	if got := md.Get("x-caller-groups"); len(got) != 1 || got[0] != "g1,g2" {
		t.Fatalf("x-caller-groups = %v, want [\"g1,g2\"]", got)
	}
}

// TestGetQuotaUsageOmitsGroupsHeaderWhenEmpty verifies that an empty groups
// slice produces no x-caller-groups header (uid is still forwarded).
func TestGetQuotaUsageOmitsGroupsHeaderWhenEmpty(t *testing.T) {
	fake := &metaCaptureClient{}
	orch, _ := newMetaTestOrch(t, fake)

	if _, err := orch.GetQuotaUsage("alice", "server:8443", 1020, nil, []byte("nonce"), []byte("sig")); err != nil {
		t.Fatalf("GetQuotaUsage: %v", err)
	}
	md, ok := metadata.FromOutgoingContext(fake.lastQuotaCtx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}
	if got := md.Get("x-caller-uid"); len(got) != 1 || got[0] != "1020" {
		t.Fatalf("x-caller-uid = %v, want [\"1020\"]", got)
	}
	if got := md.Get("x-caller-groups"); len(got) != 0 {
		t.Fatalf("x-caller-groups = %v, want none", got)
	}
}

// TestCallerMetaFormatsUIDAndJoinsGroups is a pure unit test on the helper.
func TestCallerMetaFormatsUIDAndJoinsGroups(t *testing.T) {
	md := CallerMeta(1020, []string{"g1", "g2"})
	if got := md.Get("x-caller-uid"); len(got) != 1 || got[0] != "1020" {
		t.Fatalf("x-caller-uid = %v, want [\"1020\"]", got)
	}
	if got := md.Get("x-caller-groups"); len(got) != 1 || got[0] != "g1,g2" {
		t.Fatalf("x-caller-groups = %v, want [\"g1,g2\"]", got)
	}
}
