// Package hostvouched contains an end-to-end integration test that exercises
// the full gRPC stack — mTLS handshake, auth interceptor, caller-metadata
// extraction, DecideAuth routing, and the handler — for the host_vouched
// user-auth mode.
//
// Unlike the unit tests in internal/server/svc, which call BackupServer
// methods directly with crafted contexts, this test spins up a real gRPC
// server on an in-memory bufconn listener and drives it with a real gRPC
// client. It therefore catches wiring bugs that unit tests miss: metadata
// keys spelled wrong in the interceptor, the interceptor not stashing caller
// UID into context, mTLS hostname extraction breaking, etc.
package hostvouched

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/internal/server/receiver"
	"github.com/example/datavault/internal/server/svc"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/pki"
	"github.com/example/datavault/pkg/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	bufSize    = 1 << 20
	agentCN    = "test-agent"
	serverName = "backup.example"
)

// fakeZFS is a copy of the in-package fake in internal/server/svc
// (hostvouched_test.go). It is duplicated here because _test.go files are not
// importable. Every method succeeds; GetUsed returns a configurable value.
// The receiver value (not pointer) must match the svc.ZFSPool interface.
type fakeZFS struct {
	usedBytes int64
}

func (f *fakeZFS) CreateDataset(name string) error                { return nil }
func (f *fakeZFS) EnsureDatasetMounted(name string) error         { return nil }
func (f *fakeZFS) SetQuota(dataset string, quotaGB int64) error   { return nil }
func (f *fakeZFS) GetUsed(dataset string) (int64, error)          { return f.usedBytes, nil }
func (f *fakeZFS) CreateSnapshot(dataset string) (string, error)  { return "snap-1", nil }
func (f *fakeZFS) CleanupSnapshots(string, int, int, int64) error { return nil }
func (f *fakeZFS) LatestSnapshot(dataset string) (string, error)  { return "snap-1", nil }
func (f *fakeZFS) CreateRestoreClone(string) (string, string, error) {
	return "clone-1", "", nil
}
func (f *fakeZFS) DestroyRestoreClone(string) error { return nil }

// newHarness generates a private CA + server cert + agent cert, wires up a
// BackupServer configured for host_vouched, starts it on a bufconn listener,
// and returns a connected gRPC client. The Receiver's mount point and KeysDir
// both live under t.TempDir(). All resources are cleaned up via t.Cleanup.
func newHarness(t *testing.T, zfs *fakeZFS) backuppbv1.BackupServiceClient {
	t.Helper()

	// --- Private PKI (CA + server cert + agent cert) ---
	caCertPEM, caKeyPEM, err := pki.CreateCA(pki.CAOptions{
		CommonName: "datavault host-vouched test CA",
		ValidFor:   time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	serverCertPEM, serverKeyPEM, err := pki.Issue(caCertPEM, caKeyPEM, pki.IssueOptions{
		CommonName: serverName,
		Server:     true,
		DNSNames:   []string{serverName},
		ValidFor:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue server cert: %v", err)
	}
	agentCertPEM, agentKeyPEM, err := pki.Issue(caCertPEM, caKeyPEM, pki.IssueOptions{
		CommonName: agentCN,
		Client:     true,
		ValidFor:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue agent cert: %v", err)
	}

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	agentCert, err := tls.X509KeyPair(agentCertPEM, agentKeyPEM)
	if err != nil {
		t.Fatalf("load agent cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("failed to add CA cert to pool")
	}

	// --- Config: one agent in host_vouched mode, trust min_uid 1000 ---
	cfg := &config.ServerConfig{
		Server:       config.ServerBlock{BackupPool: "tank"},
		AllowedHosts: []config.AllowedHost{{CN: agentCN}},
		UserAuth: config.UserAuth{
			DefaultMode: "per_user_key",
			Agents: []config.UserAuthAgentEntry{{
				Agent:        agentCN,
				Mode:         "host_vouched",
				Trust:        config.TrustPolicy{MinUID: 1000},
				Capabilities: []string{"backup", "quota"},
			}},
		},
		UserPolicy: config.UserPolicyBlock{DefaultQuotaGB: 20},
	}

	// --- In-memory DB with nonce + task-grant migrations ---
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if err := store.MigrateNonces(db); err != nil {
		t.Fatalf("MigrateNonces: %v", err)
	}
	if err := store.MigrateTaskGrants(db); err != nil {
		t.Fatalf("MigrateTaskGrants: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// --- Receiver writing into a temp dir (so PushBackup has a real landing zone) ---
	recv := receiver.New(t.TempDir())

	// --- Server: bufconn listener + mTLS + auth interceptors ---
	lis := bufconn.Listen(bufSize)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    caPool,
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(middleware.AuthInterceptor(cfg, db)),
		grpc.StreamInterceptor(middleware.AuthStreamInterceptor(cfg, db)),
	)
	backuppbv1.RegisterBackupServiceServer(srv, &svc.BackupServer{
		Cfg:      cfg,
		DB:       db,
		ZFS:      zfs,
		KeysDir:  t.TempDir(),
		Receiver: recv,
		Logger:   log.New(io.Discard, "", 0),
	})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	// --- Client over mTLS ---
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.Dial()
	}
	tlsClientCfg := &tls.Config{
		Certificates: []tls.Certificate{agentCert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := grpc.DialContext(dialCtx, "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsClientCfg)),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial bufnet: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return backuppbv1.NewBackupServiceClient(conn)
}

// callerCtx returns a context carrying x-caller-uid and x-caller-groups
// metadata, exactly as a real datavault agent attaches on the wire.
func callerCtx(uid string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(),
		"x-caller-uid", uid,
		"x-caller-groups", "backupusers",
	)
}

// --- Test cases ---

// TestHostVouched_GetQuotaUsage_AllowsWithoutSignature exercises the simplest
// unary RPC: a host_vouched agent with x-caller-uid 1020 must be able to query
// quota for a user without an SSH signature or nonce. If the interceptor fails
// to stash the caller UID, DecideAuth sees uid=0 (< 1000) and denies — so this
// test catches interceptor-wiring regressions.
func TestHostVouched_GetQuotaUsage_AllowsWithoutSignature(t *testing.T) {
	client := newHarness(t, &fakeZFS{usedBytes: 1234})

	ctx, cancel := context.WithTimeout(callerCtx("1020"), 5*time.Second)
	defer cancel()
	resp, err := client.GetQuotaUsage(ctx, &backuppbv1.GetQuotaUsageRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("expected allow without signature, got %v", err)
	}
	if resp.UsedBytes != 1234 {
		t.Fatalf("UsedBytes = %d, want 1234", resp.UsedBytes)
	}
}

// TestHostVouched_PushBackup_AllowsWithoutSignature drives the full streaming
// RPC: a host_vouched agent sends a user-rules batch with no signature/nonce
// and the server must accept it, ack, and complete the stream (snapshot created
// via the fake ZFS).
func TestHostVouched_PushBackup_AllowsWithoutSignature(t *testing.T) {
	client := newHarness(t, &fakeZFS{})

	ctx, cancel := context.WithTimeout(callerCtx("1020"), 5*time.Second)
	defer cancel()
	stream, err := client.PushBackup(ctx)
	if err != nil {
		t.Fatalf("open PushBackup stream: %v", err)
	}
	if err := stream.Send(&backuppbv1.BackupBatch{
		BatchId:  "e2e-allow",
		Username: "alice",
		RuleType: "user",
	}); err != nil {
		t.Fatalf("send batch: %v", err)
	}
	ack, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	if ack.Status != "OK" {
		t.Fatalf("ack status = %q, want OK", ack.Status)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	// Server creates a snapshot then closes the stream cleanly.
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("terminal stream result = %v, want io.EOF", err)
	}
}

// TestHostVouched_PushBackup_DeniesLowUID verifies that the same path rejects
// an agent vouching for a UID below the configured minimum (999 < 1000). The
// denial is emitted by DecideAuth inside the handler, so it surfaces on the
// stream as PermissionDenied — catching both interceptor-stash and DecideAuth
// wiring.
func TestHostVouched_PushBackup_DeniesLowUID(t *testing.T) {
	client := newHarness(t, &fakeZFS{})

	ctx, cancel := context.WithTimeout(callerCtx("999"), 5*time.Second)
	defer cancel()
	stream, err := client.PushBackup(ctx)
	if err != nil {
		t.Fatalf("open PushBackup stream: %v", err)
	}
	if err := stream.Send(&backuppbv1.BackupBatch{
		BatchId:  "e2e-deny",
		Username: "alice",
		RuleType: "user",
	}); err != nil {
		// Some transports surface the handler's terminal status on Send
		// rather than Recv. Accept PermissionDenied from either.
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("send batch: %v", err)
		}
		return
	}
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for low UID, got %v", err)
	}
}
