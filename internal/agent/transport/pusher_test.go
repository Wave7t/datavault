package transport

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/packager"
	"github.com/example/datavault/pkg/scanner"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type fakeBackupClient struct {
	stream         *fakePushStream
	challengeCalls int
}

func (c *fakeBackupClient) GetChallenge(ctx context.Context, in *backuppbv1.GetChallengeRequest, opts ...grpc.CallOption) (*backuppbv1.Challenge, error) {
	c.challengeCalls++
	return &backuppbv1.Challenge{Nonce: []byte("nonce")}, nil
}

func (c *fakeBackupClient) GetGlobalConfig(ctx context.Context, in *backuppbv1.GetGlobalConfigRequest, opts ...grpc.CallOption) (*backuppbv1.GlobalConfig, error) {
	return nil, nil
}

func (c *fakeBackupClient) PushBackup(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck], error) {
	return c.stream, nil
}

func (c *fakeBackupClient) GetQuotaUsage(ctx context.Context, in *backuppbv1.GetQuotaUsageRequest, opts ...grpc.CallOption) (*backuppbv1.QuotaUsage, error) {
	return nil, nil
}

func (c *fakeBackupClient) PullRestore(ctx context.Context, in *backuppbv1.PullRestoreRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[backuppbv1.RestoreBatch], error) {
	return nil, nil
}

type fakePushStream struct {
	grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck]
	sent []*backuppbv1.BackupBatch
}

func (s *fakePushStream) Send(batch *backuppbv1.BackupBatch) error {
	s.sent = append(s.sent, batch)
	return nil
}

func (s *fakePushStream) Recv() (*backuppbv1.BatchAck, error) {
	if len(s.sent) == 0 {
		return nil, io.EOF
	}
	last := s.sent[len(s.sent)-1]
	var written int64
	for _, file := range last.Files {
		written += int64(len(file.Content))
	}
	return &backuppbv1.BatchAck{BatchId: last.BatchId, Status: "OK", WrittenBytes: written}, nil
}

func (s *fakePushStream) CloseSend() error { return nil }

func TestPushBackupReadsContentsAndBatches(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("beta"), 0644); err != nil {
		t.Fatal(err)
	}

	stream := &fakePushStream{}
	client := &fakeBackupClient{stream: stream}
	diffs := []scanner.FileDiff{
		{Action: scanner.DiffAdd, File: scanner.FileInfo{Path: "a.txt", Mode: 0644}},
		{Action: scanner.DiffModify, File: scanner.FileInfo{Path: "b.txt", Mode: 0600}},
		{Action: scanner.DiffDelete, File: scanner.FileInfo{Path: "old.txt"}},
	}

	err := PushBackup(context.Background(), PushConfig{
		Client:   client,
		Username: "alice",
		RuleType: "user",
		RootPath: root,
		SignFunc: func(payload []byte) ([]byte, *ssh.Signature, error) {
			return nil, &ssh.Signature{Format: "ssh-rsa", Blob: []byte("sig")}, nil
		},
	}, diffs)
	if err != nil {
		t.Fatalf("PushBackup: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(stream.sent))
	}
	batch := stream.sent[0]
	if string(batch.Files[0].Content) != "alpha" || string(batch.Files[1].Content) != "beta" {
		t.Fatalf("file contents not sent: %#v", batch.Files)
	}
	if !batch.Files[2].Deleted {
		t.Fatal("expected delete marker")
	}
	if len(batch.Signature) == 0 || string(batch.Nonce) != "nonce" {
		t.Fatal("expected signed batch")
	}
	if client.challengeCalls != 1 {
		t.Fatalf("expected one user challenge, got %d", client.challengeCalls)
	}
}

func TestPushBackupMachineRuleDoesNotSign(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("config"), 0644); err != nil {
		t.Fatal(err)
	}

	stream := &fakePushStream{}
	client := &fakeBackupClient{stream: stream}
	err := PushBackup(context.Background(), PushConfig{
		Client:   client,
		Username: "_machine",
		RuleType: "machine",
		RootPath: root,
		SignFunc: func(payload []byte) ([]byte, *ssh.Signature, error) {
			t.Fatal("machine rule should not be SSH-signed")
			return nil, nil, nil
		},
	}, []scanner.FileDiff{{Action: scanner.DiffAdd, File: scanner.FileInfo{Path: "config.yaml", Mode: 0644}}})
	if err != nil {
		t.Fatalf("PushBackup: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(stream.sent))
	}
	batch := stream.sent[0]
	if batch.RuleType != "machine" || batch.Username != "_machine" {
		t.Fatalf("unexpected machine batch metadata: %#v", batch)
	}
	if len(batch.Signature) != 0 || len(batch.Nonce) != 0 {
		t.Fatal("machine batch should not carry SSH signature")
	}
	if client.challengeCalls != 0 {
		t.Fatalf("machine backup must not create a nonce, got %d challenge calls", client.challengeCalls)
	}
}

func TestPushBackupNamespacesArchivePathsButReadsSourceRelativePath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}

	stream := &fakePushStream{}
	client := &fakeBackupClient{stream: stream}
	err := PushBackup(context.Background(), PushConfig{
		Client:     client,
		Username:   "_machine",
		RuleType:   "machine",
		RootPath:   root,
		PathPrefix: "tmp/source-root",
	}, []scanner.FileDiff{{Action: scanner.DiffAdd, File: scanner.FileInfo{Path: "tmp/source-root/a.txt", Mode: 0644}}})
	if err != nil {
		t.Fatalf("PushBackup: %v", err)
	}
	if got := string(stream.sent[0].Files[0].Content); got != "alpha" {
		t.Fatalf("expected source-relative file contents, got %q", got)
	}
	if got := stream.sent[0].Files[0].Path; got != "tmp/source-root/a.txt" {
		t.Fatalf("unexpected archive path %q", got)
	}
}

func TestValidatePushConfigRejectsInvalidMachineIdentity(t *testing.T) {
	err := validatePushConfig(PushConfig{Username: "alice", RuleType: "machine"})
	if err == nil {
		t.Fatal("expected invalid machine identity to fail")
	}
}

func TestPushBackupRejectsOversizedFileBeforeRequestingChallenge(t *testing.T) {
	stream := &fakePushStream{}
	client := &fakeBackupClient{stream: stream}
	err := PushBackup(context.Background(), PushConfig{
		Client:   client,
		Username: "alice",
		RuleType: "user",
	}, []scanner.FileDiff{{Action: scanner.DiffAdd, File: scanner.FileInfo{Path: "large", Size: packager.MaxBatchContentBytes + 1}}})
	if err == nil {
		t.Fatal("expected oversized file to fail")
	}
	if client.challengeCalls != 0 || len(stream.sent) != 0 {
		t.Fatalf("oversized file should not open an authenticated transfer: challenges=%d sent=%d", client.challengeCalls, len(stream.sent))
	}
}
