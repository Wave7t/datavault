package orchestrator

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/datavault/internal/agent/pool"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// fakeTaskKeyBackupClient is a fake BackupService client that captures
// received batches for verification.
type fakeTaskKeyBackupClient struct {
	stream *fakeTaskKeyPushStream
}

func (c *fakeTaskKeyBackupClient) GetChallenge(ctx context.Context, in *backuppbv1.GetChallengeRequest, opts ...grpc.CallOption) (*backuppbv1.Challenge, error) {
	return &backuppbv1.Challenge{Nonce: []byte("nonce")}, nil
}

func (c *fakeTaskKeyBackupClient) GetGlobalConfig(ctx context.Context, in *backuppbv1.GetGlobalConfigRequest, opts ...grpc.CallOption) (*backuppbv1.GlobalConfig, error) {
	return &backuppbv1.GlobalConfig{}, nil
}

func (c *fakeTaskKeyBackupClient) PushBackup(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck], error) {
	return c.stream, nil
}

func (c *fakeTaskKeyBackupClient) GetQuotaUsage(ctx context.Context, in *backuppbv1.GetQuotaUsageRequest, opts ...grpc.CallOption) (*backuppbv1.QuotaUsage, error) {
	return nil, nil
}

func (c *fakeTaskKeyBackupClient) PullRestore(ctx context.Context, in *backuppbv1.PullRestoreRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[backuppbv1.RestoreBatch], error) {
	return nil, nil
}

func (c *fakeTaskKeyBackupClient) RegisterDelegationKey(ctx context.Context, in *backuppbv1.RegisterDelegationKeyRequest, opts ...grpc.CallOption) (*backuppbv1.RegisterDelegationKeyResponse, error) {
	return nil, nil
}

func (c *fakeTaskKeyBackupClient) RemoveDelegationKey(ctx context.Context, in *backuppbv1.RemoveDelegationKeyRequest, opts ...grpc.CallOption) (*backuppbv1.RemoveDelegationKeyResponse, error) {
	return nil, nil
}

func (c *fakeTaskKeyBackupClient) RegisterTaskGrant(ctx context.Context, in *backuppbv1.RegisterTaskGrantRequest, opts ...grpc.CallOption) (*backuppbv1.RegisterTaskGrantResponse, error) {
	return nil, nil
}

type fakeTaskKeyPushStream struct {
	grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck]
	sent      []*backuppbv1.BackupBatch
	closed    bool
	recvCount int
}

func (s *fakeTaskKeyPushStream) Send(batch *backuppbv1.BackupBatch) error {
	s.sent = append(s.sent, batch)
	return nil
}

func (s *fakeTaskKeyPushStream) Recv() (*backuppbv1.BatchAck, error) {
	if s.recvCount < len(s.sent) {
		last := s.sent[s.recvCount]
		s.recvCount++
		var written int64
		for _, file := range last.Files {
			written += int64(len(file.Content))
		}
		return &backuppbv1.BatchAck{BatchId: last.BatchId, Status: "OK", WrittenBytes: written}, nil
	}
	if !s.closed {
		return nil, fmt.Errorf("recv called before stream was closed")
	}
	return nil, fmt.Errorf("EOF")
}

func (s *fakeTaskKeyPushStream) CloseSend() error {
	s.closed = true
	return nil
}

func writeTempCerts(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// Generate agent key
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTemplate, caTemplate, &agentKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentDER})
	certFile = filepath.Join(dir, "agent.crt")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	agentKeyDER, err := x509.MarshalECPrivateKey(agentKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: agentKeyDER})
	keyFile = filepath.Join(dir, "agent.key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return certFile, keyFile, caFile
}

func TestRunSyncWithTaskKeyUsesEphemeralSigner(t *testing.T) {
	root := t.TempDir()

	// Mock user lookup so we don't need a real "alice" user.
	oldLookup := userLookup
	userLookup = func(username string) (*user.User, error) {
		return &user.User{Username: username, HomeDir: root}, nil
	}
	defer func() { userLookup = oldLookup }()

	// Generate a real ed25519 key pair
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("create ssh signer: %v", err)
	}
	pub := signer.PublicKey().Marshal()

	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}

	db, err := store.OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateSnapshots(db); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateTasks(db); err != nil {
		t.Fatal(err)
	}

	stream := &fakeTaskKeyPushStream{}
	client := &fakeTaskKeyBackupClient{stream: stream}

	certFile, keyFile, caFile := writeTempCerts(t)
	connPool, err := pool.New(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer connPool.Close()

	ruleStore := rules.NewUserRuleStore(t.TempDir())
	if err := ruleStore.Add("alice", rules.Rule{Name: "test", Paths: []string{root}, Enabled: true}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	cfg := &config.AgentConfig{
		Servers: []config.ServerEntry{{Address: "server:8443"}},
	}
	orch := New(cfg, connPool, db, ruleStore)

	// Inject the fake client into the pool's cache so no real dial occurs.
	connPool.SetClientForTest("server:8443\x00", client)

	taskID, err := orch.RunSyncWithTaskKey("alice", "", signer, 1020, []string{"g1", "g2"})
	if err != nil {
		t.Fatalf("RunSyncWithTaskKey: %v", err)
	}

	// Wait for the sync to complete
	tracker, err := orch.GetTracker(taskID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if phase, _, _ := tracker.Snapshot(); phase == progress.PhaseCompleted || phase == progress.PhaseFailed {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if len(stream.sent) == 0 {
		phase, _, _ := tracker.Snapshot()
		t.Fatalf("expected at least one batch, tracker phase=%s", phase)
	}

	for i, batch := range stream.sent {
		// Assert SignerPubkey matches the task key
		if string(batch.SignerPubkey) != string(pub) {
			t.Fatalf("batch %d SignerPubkey mismatch: got %q, want %q", i, string(batch.SignerPubkey), string(pub))
		}

		// Verify signature against the task key
		// Mirror server hash reconstruction: clone batch, clear
		// Signature/Nonce/SignerPubkey, marshal, sha256, prepend nonce||"PushBackup"
		clone := &backuppbv1.BackupBatch{
			BatchId:  batch.BatchId,
			Username: batch.Username,
			RuleType: batch.RuleType,
			Files:    batch.Files,
		}
		data, err := proto.Marshal(clone)
		if err != nil {
			t.Fatalf("batch %d marshal clone: %v", i, err)
		}
		hash := sha256.Sum256(data)
		payload := make([]byte, 0, len(batch.Nonce)+len("PushBackup")+sha256.Size)
		payload = append(payload, batch.Nonce...)
		payload = append(payload, []byte("PushBackup")...)
		payload = append(payload, hash[:]...)

		var sig ssh.Signature
		if err := ssh.Unmarshal(batch.Signature, &sig); err != nil {
			t.Fatalf("batch %d unmarshal signature: %v", i, err)
		}

		if err := signer.PublicKey().Verify(payload, &sig); err != nil {
			t.Fatalf("batch %d signature verification failed: %v", i, err)
		}
	}
}

func TestRunSyncWithTaskKeyRejectsNilKey(t *testing.T) {
	cfg := &config.AgentConfig{
		Servers: []config.ServerEntry{{Address: "server:8443"}},
	}
	orch := New(cfg, nil, nil, nil)
	if _, err := orch.RunSyncWithTaskKey("alice", "", nil, 0, nil); err == nil {
		t.Fatal("expected RunSyncWithTaskKey with nil key to fail")
	}
}
