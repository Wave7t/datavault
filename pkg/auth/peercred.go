// Package auth provides authentication utilities for the datavault service,
// including SO_PEERCRED extraction and SSH agent signing.
package auth

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"syscall"
)

// peercredCtxKey is the context key for storing the peer UID.
type peercredCtxKey struct{}

// ContextWithPeerUID stores the peer UID in the context.
func ContextWithPeerUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, peercredCtxKey{}, uid)
}

// GetPeerUIDFromContext extracts the peer UID from context.
func GetPeerUIDFromContext(ctx context.Context) (uint32, error) {
	uid, ok := ctx.Value(peercredCtxKey{}).(uint32)
	if !ok {
		return 0, fmt.Errorf("peer UID not found in context")
	}
	return uid, nil
}

// GetPeerUID extracts the Unix socket peer's UID via SO_PEERCRED.
func GetPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket connection")
	}
	f, err := unixConn.File()
	if err != nil {
		return 0, fmt.Errorf("get socket file descriptor: %w", err)
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	return cred.Uid, nil
}

// LookupUsername returns the username for the given UID.
func LookupUsername(uid uint32) (string, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "", fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	return u.Username, nil
}
