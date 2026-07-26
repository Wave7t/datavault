//go:build linux

package auth

import (
	"fmt"
	"net"
	"syscall"
)

// GetPeerUID is retained for backward compatibility (enrollment socket uses it).
func GetPeerUID(conn net.Conn) (uint32, error) {
	_, uid, _, err := GetPeerCred(conn)
	return uid, err
}

// GetPeerCred returns the full SO_PEERCRED tuple (pid, uid, gid).
func GetPeerCred(conn net.Conn) (pid int32, uid uint32, gid uint32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, 0, fmt.Errorf("not a unix socket connection")
	}
	f, err := unixConn.File()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("get socket file descriptor: %w", err)
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	return int32(cred.Pid), cred.Uid, cred.Gid, nil
}
