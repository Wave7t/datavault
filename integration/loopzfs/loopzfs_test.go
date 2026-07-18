// Package loopzfs exercises a running datavault-server against a disposable
// ZFS pool. It is deliberately opt-in: the test runner must supply a server
// address and the mTLS certificate directory.
package loopzfs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestMachineBackupCreatesTerminallySuccessfulSnapshots(t *testing.T) {
	client, closeClient := loopZFSClient(t)
	defer closeClient()

	for i := 0; i < 5; i++ {
		pushMachineFile(t, client, "e2e/snapshot-retention.txt", []byte(fmt.Sprintf("revision-%d", i)), 0600)
	}
}

func loopZFSClient(t *testing.T) (backuppbv1.BackupServiceClient, func()) {
	conn := loopZFSConn(t)
	return backuppbv1.NewBackupServiceClient(conn), func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	}
}

func loopZFSConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	addr := os.Getenv("DVAULT_LOOPZFS_ADDR")
	certDir := os.Getenv("DVAULT_LOOPZFS_CERT_DIR")
	if addr == "" || certDir == "" {
		t.Skip("set DVAULT_LOOPZFS_ADDR and DVAULT_LOOPZFS_CERT_DIR to run loop-ZFS integration tests")
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"))
	if err != nil {
		t.Fatalf("load client certificate: %v", err)
	}
	pemData, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		t.Fatal("add CA certificate to trust store")
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
		ServerName:   "server",
		MinVersion:   tls.VersionTLS13,
	})))
	if err != nil {
		t.Fatalf("dial backup server: %v", err)
	}
	return conn
}

func pushMachineFile(t *testing.T, client backuppbv1.BackupServiceClient, path string, content []byte, mode uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := client.PushBackup(ctx)
	if err != nil {
		t.Fatalf("open backup stream: %v", err)
	}
	if err := stream.Send(&backuppbv1.BackupBatch{
		BatchId:  fmt.Sprintf("loop-zfs-%d", time.Now().UnixNano()),
		Username: "_machine",
		RuleType: "machine",
		Files: []*backuppbv1.FileEntry{{
			Path:    path,
			Content: content,
			Mode:    mode,
		}},
	}); err != nil {
		t.Fatalf("send batch: %v", err)
	}
	ack, err := stream.Recv()
	if err != nil {
		t.Fatalf("receive batch acknowledgement: %v", err)
	}
	if ack.Status != "OK" || ack.WrittenBytes != int64(len(content)) {
		t.Fatalf("unexpected acknowledgement: %#v", ack)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close backup send stream: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("terminal backup result = %v, want EOF", err)
	}
}
