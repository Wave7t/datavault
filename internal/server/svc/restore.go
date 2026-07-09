package svc

import (
	"fmt"

	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/zfs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	batchID := 0
	err := s.Receiver.ReadAll(hostname, username, func(path string, content []byte, mode uint32) error {
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
