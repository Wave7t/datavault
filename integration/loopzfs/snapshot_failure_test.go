package loopzfs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMachineBackupReportsSnapshotFailure(t *testing.T) {
	if os.Getenv("DVAULT_LOOPZFS_INJECT_SNAPSHOT_FAILURE") != "1" {
		t.Skip("set DVAULT_LOOPZFS_INJECT_SNAPSHOT_FAILURE=1 after installing the test ZFS failure shim")
	}
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.PushBackup(ctx)
	if err != nil {
		t.Fatalf("open backup stream: %v", err)
	}
	if err := stream.Send(&backuppbv1.BackupBatch{
		BatchId:  fmt.Sprintf("loop-zfs-snapshot-failure-%d", time.Now().UnixNano()),
		Username: "_machine",
		RuleType: "machine",
		Files: []*backuppbv1.FileEntry{{
			Path:    "e2e/snapshot-failure.txt",
			Content: []byte("must not be reported as durable"),
			Mode:    0600,
		}},
	}); err != nil {
		t.Fatalf("send batch: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive batch acknowledgement: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close backup send stream: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Internal {
		t.Fatalf("terminal backup status = %v (%v), want Internal snapshot failure", status.Code(err), err)
	}
}
