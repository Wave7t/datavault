package loopzfs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const signedUserRestorePath = "e2e/user-snapshot.txt"

func TestSignedUserBackupCreatesRecoverySnapshot(t *testing.T) {
	if os.Getenv("DVAULT_LOOPZFS_RUN_SIGNED_USER_BACKUP") != "1" {
		t.Skip("set DVAULT_LOOPZFS_RUN_SIGNED_USER_BACKUP=1 with DVAULT_LOOPZFS_SSH_KEY")
	}
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	challenge, err := client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
	if err != nil {
		t.Fatalf("get backup challenge: %v", err)
	}
	batch := &backuppbv1.BackupBatch{
		BatchId:  fmt.Sprintf("loop-zfs-user-%d", time.Now().UnixNano()),
		Username: "root",
		RuleType: "user",
		Files: []*backuppbv1.FileEntry{{
			Path:    signedUserRestorePath,
			Content: []byte("durable-snapshot-content"),
			Mode:    0640,
		}},
	}
	if err := signProtoRequest(challenge.Nonce, "PushBackup", batch); err != nil {
		t.Fatalf("sign backup batch: %v", err)
	}

	stream, err := client.PushBackup(ctx)
	if err != nil {
		t.Fatalf("open backup stream: %v", err)
	}
	if err := stream.Send(batch); err != nil {
		t.Fatalf("send backup batch: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive backup acknowledgement: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close backup stream: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("terminal backup result = %v, want EOF", err)
	}
}

func TestSignedUserRestoreReadsLatestRecoverySnapshot(t *testing.T) {
	if os.Getenv("DVAULT_LOOPZFS_RUN_SIGNED_USER_RESTORE") != "1" {
		t.Skip("set DVAULT_LOOPZFS_RUN_SIGNED_USER_RESTORE=1 after creating a user backup and mutating its live file")
	}
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	challenge, err := client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
	if err != nil {
		t.Fatalf("get restore challenge: %v", err)
	}
	req := &backuppbv1.PullRestoreRequest{Username: "root"}
	if err := signProtoRequest(challenge.Nonce, "PullRestore", req); err != nil {
		t.Fatalf("sign restore request: %v", err)
	}

	stream, err := client.PullRestore(ctx, req)
	if err != nil {
		t.Fatalf("open restore stream: %v", err)
	}
	found := false
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			t.Fatal("restore stream ended without final batch")
		}
		if err != nil {
			t.Fatalf("receive restore batch: %v", err)
		}
		if batch.IsLast {
			break
		}
		for _, file := range batch.Files {
			if file.Path == signedUserRestorePath {
				found = true
				if got := string(file.Content); got != "durable-snapshot-content" {
					t.Fatalf("restore content = %q, want durable snapshot data", got)
				}
				if file.Mode != 0640 {
					t.Fatalf("restore mode = %#o, want 0640", file.Mode)
				}
			}
		}
	}
	if !found {
		t.Fatalf("restore did not contain %q", signedUserRestorePath)
	}

	replay, err := client.PullRestore(ctx, req)
	if err != nil {
		t.Fatalf("open replay restore stream: %v", err)
	}
	if _, err := replay.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed restore status = %v (%v), want Unauthenticated", status.Code(err), err)
	}
}

func TestSignedUserQuotaRejectsNonceReplay(t *testing.T) {
	if os.Getenv("DVAULT_LOOPZFS_RUN_SIGNED_USER_QUOTA") != "1" {
		t.Skip("set DVAULT_LOOPZFS_RUN_SIGNED_USER_QUOTA=1 with DVAULT_LOOPZFS_SSH_KEY")
	}
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	challenge, err := client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
	if err != nil {
		t.Fatalf("get quota challenge: %v", err)
	}
	req := &backuppbv1.GetQuotaUsageRequest{Username: "root"}
	if err := signProtoRequest(challenge.Nonce, "GetQuotaUsage", req); err != nil {
		t.Fatalf("sign quota request: %v", err)
	}
	if _, err := client.GetQuotaUsage(ctx, req); err != nil {
		t.Fatalf("first quota request: %v", err)
	}
	if _, err := client.GetQuotaUsage(ctx, req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed quota status = %v (%v), want Unauthenticated", status.Code(err), err)
	}
}

func signProtoRequest(nonce []byte, method string, message proto.Message) error {
	keyPath := os.Getenv("DVAULT_LOOPZFS_SSH_KEY")
	if keyPath == "" {
		return fmt.Errorf("DVAULT_LOOPZFS_SSH_KEY is required")
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("parse SSH key: %w", err)
	}
	clone := proto.Clone(message)
	switch request := clone.(type) {
	case *backuppbv1.BackupBatch:
		request.Nonce = nil
		request.Signature = nil
	case *backuppbv1.PullRestoreRequest:
		request.Nonce = nil
		request.Signature = nil
	case *backuppbv1.GetQuotaUsageRequest:
		request.Nonce = nil
		request.Signature = nil
	default:
		return fmt.Errorf("unsupported signed request %T", message)
	}
	encoded, err := proto.Marshal(clone)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	hash := sha256.Sum256(encoded)
	payload := append(append(append([]byte{}, nonce...), []byte(method)...), hash[:]...)
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		return fmt.Errorf("sign SSH payload: %w", err)
	}
	switch request := message.(type) {
	case *backuppbv1.BackupBatch:
		request.Nonce = nonce
		request.Signature = ssh.Marshal(sig)
	case *backuppbv1.PullRestoreRequest:
		request.Nonce = nonce
		request.Signature = ssh.Marshal(sig)
	case *backuppbv1.GetQuotaUsageRequest:
		request.Nonce = nonce
		request.Signature = ssh.Marshal(sig)
	}
	return nil
}
