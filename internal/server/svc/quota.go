package svc

import (
	"context"

	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/zfs"
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
