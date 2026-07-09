// Package svc implements the PushBackup streaming RPC handler.
//
// PushBackup is a bidirectional streaming RPC that receives batches of file
// entries from an agent, verifies the SSH signature on the first batch, writes
// files atomically to a ZFS dataset, acks each batch, and creates a ZFS
// snapshot on completion.
package svc

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/pkg/zfs"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// PushBackup handles the bidirectional streaming RPC for file backup uploads.
//
// Flow:
//  1. First batch: Verify SSH signature, validate username, ensure ZFS dataset exists
//  2. Each batch: Write files atomically via Receiver, ack with written byte count
//  3. On stream close (io.EOF): Create ZFS snapshot and clean up old snapshots
//
//nolint:funlen // streaming RPC handler with multi-phase logic
func (s *BackupServer) PushBackup(stream backuppbv1.BackupService_PushBackupServer) error {
	hostname := middleware.HostnameFromContext(stream.Context())

	var username string
	var ruleType string
	firstBatch := true
	totalWritten := int64(0)

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// --- First-batch initialization: signature, dataset, quota ---
		if firstBatch {
			firstBatch = false
			username = batch.Username
			ruleType = batch.RuleType

			if err := zfs.ValidateUsername(username); err != nil {
				return status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
			}

			// SSH signature verification (incomplete — just compiles for now).
			// TODO: Complete verification with proper payload construction
			// and nonce replay protection against the stored nonce.
			if ruleType == "user" {
				pubKey, err := middleware.LoadAuthorizedKey(s.KeysDir, hostname, username)
				if err != nil {
					return status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s: %v", hostname, username, err)
				}

				// Construct verification payload: nonce || "PushBackup" || sha256(serialized batch)
				payload := append(batch.Nonce, []byte("PushBackup")...)
				batchHash := sha256.Sum256(mustMarshal(batch))
				payload = append(payload, batchHash[:]...)

				var sig ssh.Signature
				if err := ssh.Unmarshal(batch.Signature, &sig); err != nil {
					return status.Error(codes.Unauthenticated, "invalid signature format")
				}
				if err := pubKey.Verify(payload, &sig); err != nil {
					return status.Errorf(codes.Unauthenticated, "signature verification failed: %v", err)
				}
			}

			// Ensure ZFS dataset exists
			dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
			if err := s.ZFS.CreateDataset(dsName); err != nil {
				return status.Errorf(codes.Internal, "create dataset: %v", err)
			}

			// Set quota (default or per-user override)
			quota := s.Cfg.UserPolicy.DefaultQuotaGB
			if override, ok := s.Cfg.UserPolicy.PerUserOverrides[username]; ok {
				quota = override.QuotaGB
			}
			if err := s.ZFS.SetQuota(dsName, quota); err != nil {
				return status.Errorf(codes.Internal, "set quota: %v", err)
			}
		}

		// --- Write files from this batch ---
		written := int64(0)
		for _, f := range batch.Files {
			if f.Deleted {
				if err := s.Receiver.DeleteFile(hostname, username, f.Path); err != nil {
					return status.Errorf(codes.Internal, "delete %q: %v", f.Path, err)
				}
			} else {
				if err := s.Receiver.WriteFile(hostname, username, f.Path, f.Content, f.Mode); err != nil {
					return status.Errorf(codes.Internal, "write %q: %v", f.Path, err)
				}
				written += int64(len(f.Content))
			}
		}
		totalWritten += written

		// Ack this batch
		if err := stream.Send(&backuppbv1.BatchAck{
			BatchId:      batch.BatchId,
			Status:       "OK",
			WrittenBytes: written,
		}); err != nil {
			return err
		}
	}

	// --- Completion: snapshot and cleanup ---
	if username != "" {
		dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
		snapName, err := s.ZFS.CreateSnapshot(dsName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snapshot failed for %s/%s: %v\n", hostname, username, err)
		} else {
			fmt.Fprintf(os.Stderr, "snapshot created: %s (%d bytes written)\n", snapName, totalWritten)
			if err := s.ZFS.CleanupSnapshots(dsName,
				s.Cfg.SnapshotPolicy.MinSnapshots,
				s.Cfg.SnapshotPolicy.MaxSnapshots,
				s.Cfg.SnapshotPolicy.MinFreeGB,
			); err != nil {
				fmt.Fprintf(os.Stderr, "snapshot cleanup failed for %s/%s: %v\n", hostname, username, err)
			}
		}
	}

	return nil
}

// mustMarshal serializes a protobuf message to bytes, panicking on error.
// Only used for hashing where the message is known to be valid.
func mustMarshal(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(fmt.Sprintf("proto.Marshal: %v", err))
	}
	return b
}
