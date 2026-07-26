package svc

import (
	"context"
	"database/sql"
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

const (
	maxDelegationLifetime = 90 * 24 * time.Hour
	maxTaskGrantLifetime  = 24 * time.Hour
)

func parseSSHSignature(sigBytes []byte) (*ssh.Signature, error) {
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid signature format")
	}
	return &sig, nil
}

func consumeServerNonce(db *sql.DB, nonce []byte) error {
	ok, err := store.ConsumeNonce(db, hex.EncodeToString(nonce))
	if err != nil || !ok {
		return status.Error(codes.Unauthenticated, "invalid or expired nonce")
	}
	return nil
}

func (s *BackupServer) RegisterDelegationKey(ctx context.Context, req *backuppbv1.RegisterDelegationKeyRequest) (*backuppbv1.RegisterDelegationKeyResponse, error) {
	hostname := middleware.HostnameFromContext(ctx)
	if err := zfs.ValidateUsername(req.Username); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}
	now := time.Now()
	expires := time.Unix(req.ExpiresAt, 0)
	if !expires.After(now) || expires.After(now.Add(maxDelegationLifetime)) {
		return nil, status.Error(codes.InvalidArgument, "delegation expiry out of range")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.DelegationPubkey)); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid delegation public key")
	}
	uid, _ := middleware.CallerUIDFromContext(ctx)
	groups, _ := middleware.CallerGroupsFromContext(ctx)
	const method = "/backup.v1.BackupService/RegisterDelegationKey"
	decision, derr := middleware.DecideAuth(s.Cfg, hostname, uid, req.Username, groups, method)
	if derr != nil {
		LogAuthDecision(s.Logger, method, hostname, req.Username, uid, middleware.DecisionDeny)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	}
	switch decision {
	case middleware.DecisionDeny:
		LogAuthDecision(s.Logger, method, hostname, req.Username, uid, decision)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	case middleware.DecisionRequireSig:
		payload := auth.DelegationConsentPayload(req.Nonce, req.Username, req.GatewayCn, req.DelegationPubkey, req.ExpiresAt)
		sig, err := parseSSHSignature(req.Signature)
		if err != nil {
			return nil, err
		}
		primary, err := middleware.LoadAuthorizedKey(s.KeysDir, hostname, req.Username)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s", hostname, req.Username)
		}
		if err := primary.Verify(payload, sig); err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "consent signature verification failed: %v", err)
		}
		if err := consumeServerNonce(s.DB, req.Nonce); err != nil {
			return nil, err
		}
	case middleware.DecisionAllow:
		// host_vouched: signature and nonce consumption are skipped.
	}
	LogAuthDecision(s.Logger, method, hostname, req.Username, uid, decision)
	meta := middleware.DelegationMeta{GatewayCN: req.GatewayCn, ExpiresAt: req.ExpiresAt}
	if err := middleware.SaveDelegationKey(s.KeysDir, hostname, req.Username, req.DelegationPubkey, meta); err != nil {
		return nil, status.Errorf(codes.Internal, "save delegation key: %v", err)
	}
	return &backuppbv1.RegisterDelegationKeyResponse{}, nil
}

func (s *BackupServer) RemoveDelegationKey(ctx context.Context, req *backuppbv1.RemoveDelegationKeyRequest) (*backuppbv1.RemoveDelegationKeyResponse, error) {
	hostname := middleware.HostnameFromContext(ctx)
	if err := zfs.ValidateUsername(req.Username); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}
	delegationPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.DelegationPubkey))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid delegation public key")
	}
	uid, _ := middleware.CallerUIDFromContext(ctx)
	groups, _ := middleware.CallerGroupsFromContext(ctx)
	const method = "/backup.v1.BackupService/RemoveDelegationKey"
	decision, derr := middleware.DecideAuth(s.Cfg, hostname, uid, req.Username, groups, method)
	if derr != nil {
		LogAuthDecision(s.Logger, method, hostname, req.Username, uid, middleware.DecisionDeny)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	}
	switch decision {
	case middleware.DecisionDeny:
		LogAuthDecision(s.Logger, method, hostname, req.Username, uid, decision)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	case middleware.DecisionRequireSig:
		payload := auth.DelegationRemovalPayload(req.Nonce, req.Username, req.GatewayCn, req.DelegationPubkey)
		sig, err := parseSSHSignature(req.Signature)
		if err != nil {
			return nil, err
		}

		// Try primary key first
		primary, primaryErr := middleware.LoadAuthorizedKey(s.KeysDir, hostname, req.Username)
		verified := false
		if primaryErr == nil && primary.Verify(payload, sig) == nil {
			verified = true
		}

		// Then try the named delegation key itself
		if !verified {
			if delegationPub.Verify(payload, sig) != nil {
				return nil, status.Error(codes.Unauthenticated, "removal signature verification failed")
			}
			verified = true
		}

		if err := consumeServerNonce(s.DB, req.Nonce); err != nil {
			return nil, err
		}
	case middleware.DecisionAllow:
		// host_vouched: signature and nonce consumption are skipped.
	}
	LogAuthDecision(s.Logger, method, hostname, req.Username, uid, decision)
	fp := middleware.DelegationFingerprint(delegationPub)
	if err := middleware.RemoveDelegationKeyFile(s.KeysDir, hostname, req.Username, fp); err != nil {
		return nil, status.Errorf(codes.Internal, "remove delegation key: %v", err)
	}
	return &backuppbv1.RemoveDelegationKeyResponse{}, nil
}

func (s *BackupServer) RegisterTaskGrant(ctx context.Context, req *backuppbv1.RegisterTaskGrantRequest) (*backuppbv1.RegisterTaskGrantResponse, error) {
	hostname := middleware.HostnameFromContext(ctx)
	if err := zfs.ValidateUsername(req.Username); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}
	if req.Method != "PushBackup" {
		return nil, status.Error(codes.InvalidArgument, "method must be PushBackup")
	}
	now := time.Now()
	expires := time.Unix(req.ExpiresAt, 0)
	if !expires.After(now) || expires.After(now.Add(maxTaskGrantLifetime)) {
		return nil, status.Error(codes.InvalidArgument, "task grant expiry out of range")
	}
	ephemeralPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.EphemeralPubkey))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ephemeral public key")
	}
	uid, _ := middleware.CallerUIDFromContext(ctx)
	groups, _ := middleware.CallerGroupsFromContext(ctx)
	const method = "/backup.v1.BackupService/RegisterTaskGrant"
	decision, derr := middleware.DecideAuth(s.Cfg, hostname, uid, req.Username, groups, method)
	if derr != nil {
		LogAuthDecision(s.Logger, method, hostname, req.Username, uid, middleware.DecisionDeny)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	}
	switch decision {
	case middleware.DecisionDeny:
		LogAuthDecision(s.Logger, method, hostname, req.Username, uid, decision)
		return nil, status.Error(codes.PermissionDenied, "authorization denied")
	case middleware.DecisionRequireSig:
		payload := auth.TaskGrantPayload(req.Nonce, req.Username, req.Method, req.EphemeralPubkey, req.ExpiresAt)
		sig, err := parseSSHSignature(req.Signature)
		if err != nil {
			return nil, err
		}

		// Verify against unexpired delegation keys only — never the primary key
		delegationKeys, err := middleware.LoadDelegationKeys(s.KeysDir, hostname, req.Username, now)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "load delegation keys: %v", err)
		}
		if len(delegationKeys) == 0 {
			return nil, status.Error(codes.Unauthenticated, "no delegation keys found")
		}
		if !middleware.VerifyAnyKey(delegationKeys, payload, sig) {
			return nil, status.Error(codes.Unauthenticated, "task grant signature verification failed")
		}
		if err := consumeServerNonce(s.DB, req.Nonce); err != nil {
			return nil, err
		}
	case middleware.DecisionAllow:
		// host_vouched: signature and nonce consumption are skipped.
	}
	LogAuthDecision(s.Logger, method, hostname, req.Username, uid, decision)
	grant := store.TaskGrant{
		Hostname:             hostname,
		Username:             req.Username,
		Method:               req.Method,
		EphemeralFingerprint: middleware.DelegationFingerprint(ephemeralPub),
		EphemeralPubKey:      req.EphemeralPubkey,
		ExpiresAt:            expires,
	}
	if err := store.InsertTaskGrant(s.DB, grant); err != nil {
		return nil, status.Errorf(codes.Internal, "insert task grant: %v", err)
	}
	return &backuppbv1.RegisterTaskGrantResponse{}, nil
}
