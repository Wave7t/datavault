// Package svc implements the PushBackup streaming RPC handler.
//
// PushBackup is a bidirectional streaming RPC that receives batches of file
// entries from an agent, verifies the SSH signature on the first batch, writes
// files atomically to a ZFS dataset, acks each batch, and creates a ZFS
// snapshot on completion.
package svc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/internal/server/receiver"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
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
	ctx, cancel := context.WithTimeout(stream.Context(), maxStreamDuration)
	defer cancel()

	var username string
	var ruleType string
	firstBatch := true
	nonceConsumed := false
	partialUploads := make(map[string]*partialUpload)
	defer func() {
		for _, upload := range partialUploads {
			upload.writer.Abort()
		}
	}()

	for {
		if err := ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}
		batch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := zfs.ValidateUsername(batch.Username); err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
		}
		if err := validateBackupIdentity(batch); err != nil {
			return err
		}

		if username != "" && batch.Username != username {
			return status.Error(codes.InvalidArgument, "username changed within stream")
		}
		if ruleType != "" && batch.RuleType != ruleType {
			return status.Error(codes.InvalidArgument, "rule type changed within stream")
		}

		if batch.RuleType == "user" {
			if err := s.verifyBatchSignature(hostname, batch); err != nil {
				return err
			}
			if !nonceConsumed {
				ok, err := store.ConsumeNonce(s.DB, hex.EncodeToString(batch.Nonce))
				if err != nil || !ok {
					return status.Error(codes.Unauthenticated, "invalid or expired nonce")
				}
				nonceConsumed = true
			}
		}

		// --- First-batch initialization: dataset and quota ---
		if firstBatch {
			firstBatch = false
			username = batch.Username
			ruleType = batch.RuleType

			// Ensure ZFS dataset exists
			dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
			if err := s.ZFS.CreateDataset(dsName); err != nil {
				return status.Errorf(codes.Internal, "create dataset: %v", err)
			}
			if err := s.ZFS.EnsureDatasetMounted(dsName); err != nil {
				return status.Errorf(codes.Internal, "mount dataset: %v", err)
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
			if f.Chunked {
				if f.Deleted {
					return status.Error(codes.InvalidArgument, "chunked file may not be a delete marker")
				}
				upload, err := s.writeChunk(hostname, username, f, partialUploads)
				if err != nil {
					return status.Errorf(codes.Internal, "write chunk %q: %v", f.Path, err)
				}
				if f.FinalChunk {
					if err := upload.writer.Commit(f.Mode); err != nil {
						return status.Errorf(codes.Internal, "commit chunked file %q: %v", f.Path, err)
					}
					delete(partialUploads, f.Path)
				}
				written += int64(len(f.Content))
				continue
			}
			if _, exists := partialUploads[f.Path]; exists {
				return status.Errorf(codes.InvalidArgument, "file %q has an unfinished chunked upload", f.Path)
			}
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
	if len(partialUploads) != 0 {
		return status.Error(codes.InvalidArgument, "backup stream ended with incomplete chunked upload")
	}
	if username != "" {
		if err := ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}
		dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
		snapName, err := s.ZFS.CreateSnapshot(dsName)
		if err != nil {
			return status.Errorf(codes.Internal, "create recovery snapshot %q: %v", dsName, err)
		}
		if err := s.ZFS.CleanupSnapshots(dsName,
			s.Cfg.SnapshotPolicy.MinSnapshots,
			s.Cfg.SnapshotPolicy.MaxSnapshots,
			s.Cfg.SnapshotPolicy.MinFreeGB,
		); err != nil {
			return status.Errorf(codes.Internal, "clean up recovery snapshots %q: %v", snapName, err)
		}
	}

	return nil
}

type partialUpload struct {
	writer     *receiver.ChunkWriter
	nextOffset uint64
	mode       uint32
}

func (s *BackupServer) writeChunk(hostname, username string, file *backuppbv1.FileEntry, uploads map[string]*partialUpload) (*partialUpload, error) {
	upload, exists := uploads[file.Path]
	if !exists {
		if file.ChunkOffset != 0 {
			return nil, fmt.Errorf("first chunk offset is %d, want 0", file.ChunkOffset)
		}
		writer, err := s.Receiver.NewChunkWriter(hostname, username, file.Path)
		if err != nil {
			return nil, err
		}
		upload = &partialUpload{writer: writer, mode: file.Mode}
		uploads[file.Path] = upload
	}
	if file.ChunkOffset != upload.nextOffset {
		return nil, fmt.Errorf("chunk offset is %d, want %d", file.ChunkOffset, upload.nextOffset)
	}
	if file.Mode != upload.mode {
		return nil, fmt.Errorf("chunk mode changed from %#o to %#o", upload.mode, file.Mode)
	}
	if err := upload.writer.Write(file.Content); err != nil {
		return nil, err
	}
	upload.nextOffset += uint64(len(file.Content))
	return upload, nil
}

func validateBackupIdentity(batch *backuppbv1.BackupBatch) error {
	switch batch.RuleType {
	case "user":
		if batch.Username == "_machine" {
			return status.Error(codes.PermissionDenied, "_machine dataset accepts machine rules only")
		}
	case "machine":
		if batch.Username != "_machine" {
			return status.Error(codes.PermissionDenied, "machine rules may write only to _machine")
		}
		if len(batch.Nonce) != 0 || len(batch.Signature) != 0 {
			return status.Error(codes.InvalidArgument, "machine rules must not include SSH credentials")
		}
	default:
		return status.Errorf(codes.InvalidArgument, "invalid rule type %q", batch.RuleType)
	}
	return nil
}

func (s *BackupServer) verifyBatchSignature(hostname string, batch *backuppbv1.BackupBatch) error {
	if len(batch.Nonce) == 0 || len(batch.Signature) == 0 {
		return status.Error(codes.Unauthenticated, "missing batch signature")
	}

	pubKey, err := middleware.LoadAuthorizedKey(s.KeysDir, hostname, batch.Username)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s: %v", hostname, batch.Username, err)
	}

	batchForHash := proto.Clone(batch).(*backuppbv1.BackupBatch)
	batchForHash.Signature = nil
	batchForHash.Nonce = nil

	payload := append(batch.Nonce, []byte("PushBackup")...)
	batchHash := sha256.Sum256(mustMarshal(batchForHash))
	payload = append(payload, batchHash[:]...)

	var sig ssh.Signature
	if err := ssh.Unmarshal(batch.Signature, &sig); err != nil {
		return status.Error(codes.Unauthenticated, "invalid signature format")
	}
	if err := pubKey.Verify(payload, &sig); err != nil {
		return status.Errorf(codes.Unauthenticated, "signature verification failed: %v", err)
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
