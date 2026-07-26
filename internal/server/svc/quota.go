package svc

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	uid, _ := middleware.CallerUIDFromContext(ctx)
	groups, _ := middleware.CallerGroupsFromContext(ctx)
	const method = "/backup.v1.BackupService/GetQuotaUsage"
	decision, derr := middleware.DecideAuth(s.Cfg, hostname, uid, username, groups, method)
	if derr != nil {
		LogAuthDecision(s.Logger, method, hostname, username, uid, middleware.DecisionDeny)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	}
	switch decision {
	case middleware.DecisionDeny:
		LogAuthDecision(s.Logger, method, hostname, username, uid, decision)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	case middleware.DecisionRequireSig:
		if err := s.verifyQuotaSignature(hostname, req); err != nil {
			return nil, err
		}
		ok, err := store.ConsumeNonce(s.DB, hex.EncodeToString(req.Nonce))
		if err != nil || !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired nonce")
		}
	case middleware.DecisionAllow:
		// host_vouched: signature and nonce consumption are skipped.
	}
	LogAuthDecision(s.Logger, method, hostname, username, uid, decision)

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

	keys, err := middleware.LoadSigningKeys(s.KeysDir, hostname, req.Username, time.Now())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s: %v", hostname, req.Username, err)
	}

	payload, err := auth.ServerRequestPayload("GetQuotaUsage", req.Nonce, req)
	if err != nil {
		return status.Errorf(codes.Internal, "build quota payload: %v", err)
	}

	var sig ssh.Signature
	if err := ssh.Unmarshal(req.Signature, &sig); err != nil {
		return status.Error(codes.Unauthenticated, "invalid signature format")
	}
	if !middleware.VerifyAnyKey(keys, payload, &sig) {
		return status.Error(codes.Unauthenticated, "signature verification failed")
	}
	return nil
}
