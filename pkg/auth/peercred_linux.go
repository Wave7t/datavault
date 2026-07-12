//go:build linux

package auth

import (
	"fmt"
	"net"
	"syscall"
)

// GetPeerUID returns the UID reported by Linux SO_PEERCRED for a Unix-domain
// socket peer. The Agent relies on this value instead of caller-supplied user
// identity.
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
