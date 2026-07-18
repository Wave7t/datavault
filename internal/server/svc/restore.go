package svc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const restoreChunkContentBytes = 4 * 1024 * 1024

// PullRestore is a server-streaming RPC that sends all files for a user's
// dataset in batches. The hostname is extracted from the mTLS context,
// the username comes from the request and is validated. Files are read
// via receiver.ReadAll and sent one per RestoreBatch. A final batch with
// IsLast=true signals completion.
func (s *BackupServer) PullRestore(req *backuppbv1.PullRestoreRequest, stream backuppbv1.BackupService_PullRestoreServer) error {
	hostname := middleware.HostnameFromContext(stream.Context())
	username := req.Username
	ctx, cancel := context.WithTimeout(stream.Context(), maxStreamDuration)
	defer cancel()

	if err := zfs.ValidateUsername(username); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}
	if err := s.verifyPullRestoreSignature(hostname, req); err != nil {
		return err
	}
	ok, err := store.ConsumeNonce(s.DB, hex.EncodeToString(req.Nonce))
	if err != nil || !ok {
		return status.Error(codes.Unauthenticated, "invalid or expired nonce")
	}

	dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
	snapshot, err := s.ZFS.LatestSnapshot(dsName)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "find recovery snapshot: %v", err)
	}
	clone, mountpoint, err := s.ZFS.CreateRestoreClone(snapshot)
	if err != nil {
		return status.Errorf(codes.Internal, "create recovery clone: %v", err)
	}

	batchID := 0
	err = s.Receiver.ReadAllChunksFrom(mountpoint, restoreChunkContentBytes, func(path string, content []byte, mode uint32, offset uint64, chunked, final bool) error {
		if err := ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}
		batchID++
		return stream.Send(&backuppbv1.RestoreBatch{
			BatchId: fmt.Sprintf("restore-%d", batchID),
			Files: []*backuppbv1.FileEntry{
				{Path: path, Content: content, Mode: mode, Chunked: chunked, ChunkOffset: offset, FinalChunk: final},
			},
			IsLast: false,
		})
	})
	if err != nil {
		cleanupErr := s.ZFS.DestroyRestoreClone(clone)
		if status.Code(err) == codes.DeadlineExceeded || status.Code(err) == codes.Canceled {
			if cleanupErr != nil {
				return status.Errorf(codes.Internal, "restore canceled and destroy recovery clone: %v", cleanupErr)
			}
			return err
		}
		if cleanupErr != nil {
			return status.Errorf(codes.Internal, "read files: %v; destroy recovery clone: %v", err, cleanupErr)
		}
		return status.Errorf(codes.Internal, "read files: %v", err)
	}
	if err := s.ZFS.DestroyRestoreClone(clone); err != nil {
		return status.Errorf(codes.Internal, "destroy recovery clone: %v", err)
	}
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}

	// Send final batch to signal completion
	return stream.Send(&backuppbv1.RestoreBatch{
		BatchId: fmt.Sprintf("restore-%d", batchID+1),
		IsLast:  true,
	})
}

func (s *BackupServer) verifyPullRestoreSignature(hostname string, req *backuppbv1.PullRestoreRequest) error {
	if len(req.Nonce) == 0 || len(req.Signature) == 0 {
		return status.Error(codes.Unauthenticated, "missing restore signature")
	}

	pubKey, err := middleware.LoadAuthorizedKey(s.KeysDir, hostname, req.Username)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s: %v", hostname, req.Username, err)
	}

	requestForHash := proto.Clone(req).(*backuppbv1.PullRestoreRequest)
	requestForHash.Signature = nil
	requestForHash.Nonce = nil

	data, err := proto.Marshal(requestForHash)
	if err != nil {
		return status.Errorf(codes.Internal, "marshal restore request: %v", err)
	}
	hash := sha256.Sum256(data)

	payload := append(req.Nonce, []byte("PullRestore")...)
	payload = append(payload, hash[:]...)

	var sig ssh.Signature
	if err := ssh.Unmarshal(req.Signature, &sig); err != nil {
		return status.Error(codes.Unauthenticated, "invalid signature format")
	}
	if err := pubKey.Verify(payload, &sig); err != nil {
		return status.Errorf(codes.Unauthenticated, "signature verification failed: %v", err)
	}
	return nil
}
