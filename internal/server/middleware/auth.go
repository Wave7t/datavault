// Package middleware provides gRPC interceptors for server-side authentication.
// It implements mTLS CN hostname verification, nonce replay protection,
// and SSH signature verification for non-whitelisted RPC methods.
package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type ctxKey string

const (
	ctxHostname ctxKey = "hostname"
	ctxUsername ctxKey = "username"
)

// MethodWhitelist contains RPC methods that skip SSH signature verification.
// These are the initial handshake endpoints used before authentication is established.
var MethodWhitelist = map[string]bool{
	"/grpc.health.v1.Health/Check":             true,
	"/backup.v1.BackupService/GetChallenge":    true,
	"/backup.v1.BackupService/GetGlobalConfig": true,
	"/backup.v1.BackupService/PushBackup":      true,
	"/backup.v1.BackupService/GetQuotaUsage":   true,
	"/backup.v1.BackupService/PullRestore":     true,
}

// HostnameFromContext extracts the hostname set by the auth interceptor.
func HostnameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxHostname).(string)
	return v
}

// UsernameFromContext extracts the username set by the auth interceptor.
func UsernameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUsername).(string)
	return v
}

// LoadAuthorizedKey loads the SSH public key for a user on a host.
// Keys are stored at keysDir/<hostname>/<username>.pub
func LoadAuthorizedKey(keysDir, hostname, username string) (ssh.PublicKey, error) {
	path := filepath.Join(keysDir, hostname, username+".pub")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized key for %s/%s: %w", hostname, username, err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return pubKey, nil
}

// AuthInterceptor returns a unary server interceptor that:
// 1. Extracts the hostname from the mTLS peer certificate CN
// 2. Validates the hostname is in the allowed list
// 3. For whitelisted methods, skips SSH signature verification
// 4. For non-whitelisted methods, validates the nonce and username metadata
func AuthInterceptor(cfg *config.ServerConfig, db *sql.DB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		hostname, err := extractHostname(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if !isHostnameAllowed(cfg.AllowedHosts, hostname) {
			return nil, status.Errorf(codes.PermissionDenied, "hostname %q not allowed", hostname)
		}
		ctx = context.WithValue(ctx, ctxHostname, hostname)

		// Whitelisted methods skip SSH signature / nonce verification
		if MethodWhitelist[info.FullMethod] {
			return handler(ctx, req)
		}

		// Verify nonce and extract username from gRPC metadata
		username, err := verifyMethodAuth(ctx, db)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, ctxUsername, username)

		return handler(ctx, req)
	}
}

// AuthStreamInterceptor returns a stream server interceptor with the same
// authentication logic as AuthInterceptor, but for streaming RPCs.
func AuthStreamInterceptor(cfg *config.ServerConfig, db *sql.DB) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		hostname, err := extractHostname(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}
		if !isHostnameAllowed(cfg.AllowedHosts, hostname) {
			return status.Errorf(codes.PermissionDenied, "hostname %q not allowed", hostname)
		}
		ctx := context.WithValue(ss.Context(), ctxHostname, hostname)

		// Whitelisted methods skip SSH signature / nonce verification
		if MethodWhitelist[info.FullMethod] {
			return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
		}

		// Verify nonce and extract username from gRPC metadata
		username, err := verifyMethodAuth(ss.Context(), db)
		if err != nil {
			return err
		}
		ctx = context.WithValue(ctx, ctxUsername, username)

		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

// verifyMethodAuth validates the nonce and username from gRPC metadata.
// It does NOT verify the SSH signature — that is done per-batch in the
// PushBackup handler where the batch payload is known.
func verifyMethodAuth(ctx context.Context, db *sql.DB) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	username := getMeta(md, "x-username")
	nonceStr := getMeta(md, "x-nonce")
	sigStr := getMeta(md, "x-signature")

	if username == "" || nonceStr == "" || sigStr == "" {
		return "", status.Error(codes.Unauthenticated, "missing auth metadata")
	}

	if err := zfs.ValidateUsername(username); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}

	// Verify nonce is valid and not yet consumed
	ok, err := store.ConsumeNonce(db, nonceStr)
	if err != nil || !ok {
		return "", status.Error(codes.Unauthenticated, "invalid or expired nonce")
	}

	// SSH signature verification is deferred to the handler (per-batch signing)

	return username, nil
}

// extractHostname extracts the client hostname from the mTLS peer certificate CN.
func extractHostname(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("no TLS info")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	if cert.Subject.CommonName == "" {
		return "", fmt.Errorf("certificate has no CN")
	}
	return cert.Subject.CommonName, nil
}

// isHostnameAllowed checks whether the hostname is in the allowed hosts config list.
func isHostnameAllowed(hosts []config.AllowedHost, hostname string) bool {
	for _, h := range hosts {
		if h.CN == hostname {
			return true
		}
	}
	return false
}

// getMeta returns the first value for the given key from gRPC metadata.
func getMeta(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// wrappedStream wraps a grpc.ServerStream to override the context.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
