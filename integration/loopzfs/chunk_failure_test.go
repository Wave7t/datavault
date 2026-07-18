package loopzfs

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMachineBackupRejectsIncompleteChunkedUpload exercises the server's
// stream-finalization guard against a real loop-backed ZFS instance. The
// harness additionally checks the dataset for the promised absence of both
// the target file and its .dvault-chunk staging file after this RPC returns.
func TestMachineBackupRejectsIncompleteChunkedUpload(t *testing.T) {
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.PushBackup(ctx)
	if err != nil {
		t.Fatalf("open backup stream: %v", err)
	}
	if err := stream.Send(&backuppbv1.BackupBatch{
		BatchId:  fmt.Sprintf("loop-zfs-incomplete-chunk-%d", time.Now().UnixNano()),
		Username: "_machine",
		RuleType: "machine",
		Files: []*backuppbv1.FileEntry{{
			Path:        "e2e/incomplete-chunk.bin",
			Content:     []byte("first chunk only"),
			Mode:        0600,
			Chunked:     true,
			ChunkOffset: 0,
		}},
	}); err != nil {
		t.Fatalf("send partial chunk: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive partial chunk acknowledgement: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close backup stream: %v", err)
	}
	if _, err := stream.Recv(); err == io.EOF || status.Code(err) != codes.InvalidArgument {
		t.Fatalf("incomplete chunk terminal status = %v (%v), want InvalidArgument", status.Code(err), err)
	}
}
