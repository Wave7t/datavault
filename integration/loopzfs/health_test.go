package loopzfs

import (
	"context"
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestMTLSHealthCheckReportsServing(t *testing.T) {
	conn := loopZFSConn(t)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: "backup.v1.BackupService"})
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	if response.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health status = %s, want SERVING", response.Status)
	}
}
