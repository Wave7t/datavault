package svc

import (
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

// PullRestore is a server-streaming RPC that sends all files for a user's
// dataset in batches. The hostname is extracted from the mTLS context,
// the username comes from the request and is validated. Files are read
// via receiver.ReadAll and sent one per RestoreBatch. A final batch with
// IsLast=true signals completion.
func (s *BackupServer) PullRestore(req *backuppbv1.PullRestoreRequest, stream backuppbv1.BackupService_PullRestoreServer) error {
	hostname := middleware.HostnameFromContext(stream.Context())
	username := req.Username

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

	batchID := 0
	err = s.Receiver.ReadAll(hostname, username, func(path string, content []byte, mode uint32) error {
		batchID++
		return stream.Send(&backuppbv1.RestoreBatch{
			BatchId: fmt.Sprintf("restore-%d", batchID),
			Files: []*backuppbv1.FileEntry{
				{Path: path, Content: content, Mode: mode},
			},
			IsLast: false,
		})
	})
	if err != nil {
		return status.Errorf(codes.Internal, "read files: %v", err)
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
