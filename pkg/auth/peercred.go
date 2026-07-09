// Package auth provides authentication utilities for the datavault service,
// including SO_PEERCRED extraction and SSH agent signing.
package auth

import (
	"fmt"
	"net"
	"os/user"
	"syscall"
)

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
