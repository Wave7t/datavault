package svc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"io"
	"testing"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mustTestDB opens an in-memory DB with the nonce + task-grant migrations and
// arranges for it to be closed at the end of the test.
func mustTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.MigrateNonces(db); err != nil {
		t.Fatalf("migrate nonces: %v", err)
	}
	if err := store.MigrateTaskGrants(db); err != nil {
		t.Fatalf("migrate task grants: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newDelegationKeyLine generates a fresh ed25519 key and returns its
// authorized_keys-formatted public line.
func newDelegationKeyLine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

// fakeZFS implements ZFSPool for tests. Every method succeeds; GetUsed returns
// a configurable value and LatestSnapshot can be forced to fail via latestErr.
type fakeZFS struct {
	usedBytes    int64
	snapshotName string
	latestErr    error
	cloneMount   string
	datasets     []string
	snapshots    []string
}

func (f *fakeZFS) CreateDataset(name string) error {
	f.datasets = append(f.datasets, name)
	return nil
}
func (f *fakeZFS) EnsureDatasetMounted(string) error { return nil }
func (f *fakeZFS) SetQuota(string, int64) error      { return nil }
func (f *fakeZFS) GetUsed(string) (int64, error)     { return f.usedBytes, nil }
func (f *fakeZFS) CreateSnapshot(dataset string) (string, error) {
	f.snapshots = append(f.snapshots, dataset)
	if f.snapshotName == "" {
		return "snap-1", nil
	}
	return f.snapshotName, nil
}
func (f *fakeZFS) CleanupSnapshots(string, int, int, int64) error { return nil }
func (f *fakeZFS) LatestSnapshot(string) (string, error) {
	if f.latestErr != nil {
		return "", f.latestErr
	}
	return "snap-1", nil
}
func (f *fakeZFS) CreateRestoreClone(string) (string, string, error) {
	return "clone-1", f.cloneMount, nil
}
func (f *fakeZFS) DestroyRestoreClone(string) error { return nil }

// fakeServerStream is a minimal grpc.ServerStream used by the streaming fakes.
type fakeServerStream struct {
	ctx context.Context
}

func (f *fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeServerStream) SetTrailer(metadata.MD)       {}
func (f *fakeServerStream) Context() context.Context     { return f.ctx }
func (f *fakeServerStream) SendMsg(any) error            { return nil }
func (f *fakeServerStream) RecvMsg(any) error            { return nil }

type fakePushBackupStream struct {
	fakeServerStream
	batches []*backuppbv1.BackupBatch
	acks    []*backuppbv1.BatchAck
	recvErr error
}

func (f *fakePushBackupStream) Send(ack *backuppbv1.BatchAck) error {
	f.acks = append(f.acks, ack)
	return nil
}
func (f *fakePushBackupStream) Recv() (*backuppbv1.BackupBatch, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	if len(f.batches) == 0 {
		return nil, io.EOF
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, nil
}

type fakePullRestoreStream struct {
	fakeServerStream
	sent []*backuppbv1.RestoreBatch
}

func (f *fakePullRestoreStream) Send(b *backuppbv1.RestoreBatch) error {
	f.sent = append(f.sent, b)
	return nil
}

// hostVouchedTestCfg returns a config where `agent` runs in host_vouched mode
// with the given trust policy and capabilities. DefaultMode stays per_user_key
// so any agent not listed falls back to the signature path.
func hostVouchedTestCfg(agent string, trust config.TrustPolicy, caps []string) *config.ServerConfig {
	return &config.ServerConfig{
		AllowedHosts: []config.AllowedHost{{CN: agent}},
		UserAuth: config.UserAuth{
			DefaultMode: "per_user_key",
			Agents: []config.UserAuthAgentEntry{
				{Agent: agent, Mode: "host_vouched", Trust: trust, Capabilities: caps},
			},
		},
		UserPolicy: config.UserPolicyBlock{DefaultQuotaGB: 20},
	}
}

func callerCtx(agent string, uid int32) context.Context {
	ctx := middleware.ContextWithHostname(context.Background(), agent)
	return middleware.ContextWithCallerUID(ctx, uid)
}

// ---- GetQuotaUsage ----

func TestGetQuotaUsage_HostVouched_AllowsWithoutSignature(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"quota"})
	srv := &BackupServer{
		Cfg:     cfg,
		DB:      mustTestDB(t),
		ZFS:     &fakeZFS{usedBytes: 1234},
		KeysDir: t.TempDir(),
	}
	ctx := callerCtx("agent-01", 1020)
	resp, err := srv.GetQuotaUsage(ctx, &backuppbv1.GetQuotaUsageRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("expected allow without signature, got %v", err)
	}
	if resp.UsedBytes != 1234 {
		t.Fatalf("UsedBytes = %d, want 1234", resp.UsedBytes)
	}
}

func TestGetQuotaUsage_HostVouched_DeniesLowUID(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"quota"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	ctx := callerCtx("agent-01", 999)
	_, err := srv.GetQuotaUsage(ctx, &backuppbv1.GetQuotaUsageRequest{Username: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for low UID, got %v", err)
	}
}

func TestGetQuotaUsage_PerUserKey_RequiresSignature(t *testing.T) {
	// Default per_user_key mode: no caller metadata → RequireSig → missing
	// signature must surface as Unauthenticated, exactly as before.
	cfg := &config.ServerConfig{
		AllowedHosts: []config.AllowedHost{{CN: "agent-01"}},
		UserAuth:     config.UserAuth{DefaultMode: "per_user_key"},
	}
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	ctx := middleware.ContextWithHostname(context.Background(), "agent-01")
	_, err := srv.GetQuotaUsage(ctx, &backuppbv1.GetQuotaUsageRequest{Username: "alice"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated (signature required), got %v", err)
	}
}

// ---- RegisterDelegationKey ----

func TestRegisterDelegationKey_HostVouched_AllowsWithoutSignature(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"delegation"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), KeysDir: t.TempDir()}
	ctx := callerCtx("agent-01", 1020)

	// Build a delegation key + a request with NO nonce and NO signature.
	delPubLine := newDelegationKeyLine(t)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	req := &backuppbv1.RegisterDelegationKeyRequest{
		Username:         "alice",
		GatewayCn:        "agent-01",
		DelegationPubkey: delPubLine,
		ExpiresAt:        expiresAt,
	}
	if _, err := srv.RegisterDelegationKey(ctx, req); err != nil {
		t.Fatalf("expected allow without signature, got %v", err)
	}
}

func TestRegisterDelegationKey_HostVouched_DeniesLowUID(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"delegation"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), KeysDir: t.TempDir()}
	ctx := callerCtx("agent-01", 999)

	delPubLine := newDelegationKeyLine(t)
	req := &backuppbv1.RegisterDelegationKeyRequest{
		Username:         "alice",
		GatewayCn:        "agent-01",
		DelegationPubkey: delPubLine,
		ExpiresAt:        time.Now().Add(24 * time.Hour).Unix(),
	}
	_, err := srv.RegisterDelegationKey(ctx, req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// ---- PullRestore ----

func TestPullRestore_HostVouched_DeniesLowUID(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"restore"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	stream := &fakePullRestoreStream{fakeServerStream: fakeServerStream{ctx: callerCtx("agent-01", 999)}}
	err := srv.PullRestore(&backuppbv1.PullRestoreRequest{Username: "alice"}, stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestPullRestore_HostVouched_AllowsWithoutSignature(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"restore"})
	// fakeZFS.LatestSnapshot returns an error so the handler surfaces
	// FailedPrecondition — proving the signature gate was skipped.
	zfsFake := &fakeZFS{latestErr: status.Error(codes.FailedPrecondition, "no snapshot")}
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: zfsFake, KeysDir: t.TempDir()}
	stream := &fakePullRestoreStream{fakeServerStream: fakeServerStream{ctx: callerCtx("agent-01", 1020)}}
	err := srv.PullRestore(&backuppbv1.PullRestoreRequest{Username: "alice"}, stream)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition (signature skipped, reached ZFS), got %v", err)
	}
}

// ---- PushBackup ----

func TestPushBackup_HostVouched_AllowsWithoutSignature(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"backup"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	stream := &fakePushBackupStream{fakeServerStream: fakeServerStream{ctx: callerCtx("agent-01", 1020)}}
	// One user batch with NO nonce/signature and no files, then EOF.
	stream.batches = []*backuppbv1.BackupBatch{
		{Username: "alice", RuleType: "user"},
	}
	if err := srv.PushBackup(stream); err != nil {
		t.Fatalf("expected allow without signature, got %v", err)
	}
	if len(stream.acks) != 1 {
		t.Fatalf("expected 1 ack, got %d", len(stream.acks))
	}
}

func TestPushBackup_HostVouched_DeniesLowUID(t *testing.T) {
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"backup"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	stream := &fakePushBackupStream{fakeServerStream: fakeServerStream{ctx: callerCtx("agent-01", 999)}}
	stream.batches = []*backuppbv1.BackupBatch{
		{Username: "alice", RuleType: "user"},
	}
	err := srv.PushBackup(stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestPushBackup_PerUserKey_RequiresSignature(t *testing.T) {
	cfg := &config.ServerConfig{
		AllowedHosts: []config.AllowedHost{{CN: "agent-01"}},
		UserAuth:     config.UserAuth{DefaultMode: "per_user_key"},
	}
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	stream := &fakePushBackupStream{fakeServerStream: fakeServerStream{
		ctx: middleware.ContextWithHostname(context.Background(), "agent-01"),
	}}
	stream.batches = []*backuppbv1.BackupBatch{
		{Username: "alice", RuleType: "user"},
	}
	err := srv.PushBackup(stream)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated (signature required), got %v", err)
	}
}

func TestPushBackup_MachineRule_SkipsDecideAuth(t *testing.T) {
	// host_vouched cfg but a machine rule batch: DecideAuth must NOT be
	// consulted, and no caller UID is required.
	cfg := hostVouchedTestCfg("agent-01", config.TrustPolicy{MinUID: 1000}, []string{"backup"})
	srv := &BackupServer{Cfg: cfg, DB: mustTestDB(t), ZFS: &fakeZFS{}, KeysDir: t.TempDir()}
	stream := &fakePushBackupStream{fakeServerStream: fakeServerStream{
		ctx: middleware.ContextWithHostname(context.Background(), "agent-01"),
	}}
	stream.batches = []*backuppbv1.BackupBatch{
		{Username: "_machine", RuleType: "machine"},
	}
	if err := srv.PushBackup(stream); err != nil {
		t.Fatalf("machine rule should bypass DecideAuth, got %v", err)
	}
}
