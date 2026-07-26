package middleware

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestHealthCheckIsWhitelistedAfterMTLS(t *testing.T) {
	if !MethodWhitelist["/grpc.health.v1.Health/Check"] {
		t.Fatal("health check must skip SSH metadata verification after mTLS host authorization")
	}
}

func TestExtractCallerMetadata_ABSENT(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.New(nil))
	uid, groups, err := extractCallerMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 0 || groups != nil {
		t.Fatalf("expected zero values, got %d/%v", uid, groups)
	}
}

func TestExtractCallerMetadata_Valid(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-caller-uid", "1020",
		"x-caller-groups", "backupusers, operators",
	))
	uid, groups, err := extractCallerMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1020 {
		t.Fatalf("uid: %d", uid)
	}
	want := []string{"backupusers", "operators"}
	if len(groups) != 2 || groups[0] != "backupusers" || groups[1] != "operators" {
		t.Fatalf("groups: %v want %v", groups, want)
	}
}

func TestExtractCallerMetadata_InvalidUID(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-caller-uid", "not-a-number"))
	_, _, err := extractCallerMetadata(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
}
