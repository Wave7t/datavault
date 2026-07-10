package svc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// GetQuotaUsage returns the current disk usage and quota for a user's dataset.
// The hostname is extracted from the mTLS peer certificate (set by auth interceptor).
// The username is taken from the request and validated against strict naming rules.
// Quota bytes are resolved from per-user overrides, falling back to the default.
func (s *BackupServer) GetQuotaUsage(ctx context.Context, req *backuppbv1.GetQuotaUsageRequest) (*backuppbv1.QuotaUsage, error) {
	hostname := middleware.HostnameFromContext(ctx)
	username := req.Username

	if err := zfs.ValidateUsername(username); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}
	if err := s.verifyQuotaSignature(hostname, req); err != nil {
		return nil, err
	}
	ok, err := store.ConsumeNonce(s.DB, hex.EncodeToString(req.Nonce))
	if err != nil || !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired nonce")
	}

	dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
	used, err := s.ZFS.GetUsed(dsName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get usage: %v", err)
	}

	quota := s.Cfg.UserPolicy.DefaultQuotaGB
	if override, ok := s.Cfg.UserPolicy.PerUserOverrides[username]; ok {
		quota = override.QuotaGB
	}

	return &backuppbv1.QuotaUsage{
		UsedBytes:  used,
		QuotaBytes: quota * 1024 * 1024 * 1024,
		Dataset:    dsName,
	}, nil
}

func (s *BackupServer) verifyQuotaSignature(hostname string, req *backuppbv1.GetQuotaUsageRequest) error {
	if len(req.Nonce) == 0 || len(req.Signature) == 0 {
		return status.Error(codes.Unauthenticated, "missing quota signature")
	}

	pubKey, err := middleware.LoadAuthorizedKey(s.KeysDir, hostname, req.Username)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s: %v", hostname, req.Username, err)
	}

	requestForHash := proto.Clone(req).(*backuppbv1.GetQuotaUsageRequest)
	requestForHash.Signature = nil
	requestForHash.Nonce = nil

	data, err := proto.Marshal(requestForHash)
	if err != nil {
		return status.Errorf(codes.Internal, "marshal quota request: %v", err)
	}
	hash := sha256.Sum256(data)

	payload := append(req.Nonce, []byte("GetQuotaUsage")...)
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
