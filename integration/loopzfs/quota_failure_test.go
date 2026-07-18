package loopzfs

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMachineBackupReportsZFSCapacityFailure(t *testing.T) {
	if os.Getenv("DVAULT_LOOPZFS_EXPECT_CAPACITY_FAILURE") != "1" {
		t.Skip("set DVAULT_LOOPZFS_EXPECT_CAPACITY_FAILURE=1 on a deliberately small test pool")
	}
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	// The loop-backed parent dataset is capped at 100 MiB. Each entry remains
	// below the protocol's per-file limit; a later independent stream must fail
	// from real ZFS capacity enforcement rather than being acknowledged.
	content := make([]byte, 13*1024*1024)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("create incompressible test content: %v", err)
	}
	for i := 0; i < 10; i++ {
		err := pushMachineFileExpectTerminal(t, client, fmt.Sprintf("e2e/quota/%02d.bin", i), content)
		if err == nil {
			continue
		}
		if status.Code(err) != codes.Internal {
			t.Fatalf("capacity failure status = %v (%v), want Internal", status.Code(err), err)
		}
		return
	}
	t.Fatal("expected the deliberately small ZFS pool to reject an upload")
}

func pushMachineFileExpectTerminal(t *testing.T, client backuppbv1.BackupServiceClient, path string, content []byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	stream, err := client.PushBackup(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&backuppbv1.BackupBatch{
		BatchId:  fmt.Sprintf("loop-zfs-capacity-%d", time.Now().UnixNano()),
		Username: "_machine",
		RuleType: "machine",
		Files: []*backuppbv1.FileEntry{{
			Path:    path,
			Content: content,
			Mode:    0600,
		}},
	}); err != nil {
		return err
	}
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	_, err = stream.Recv()
	if err == io.EOF {
		return nil
	}
	return err
}
