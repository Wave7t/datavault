//go:build !linux

package auth

import (
	"fmt"
	"net"
)

// GetPeerUID is retained for backward compatibility; delegates to GetPeerCred.
func GetPeerUID(conn net.Conn) (uint32, error) {
	_, uid, _, err := GetPeerCred(conn)
	return uid, err
}

// GetPeerCred is unavailable off Linux; the Agent's local authorization model
// depends on Linux SO_PEERCRED semantics.
func GetPeerCred(conn net.Conn) (pid int32, uid uint32, gid uint32, err error) {
	return 0, 0, 0, fmt.Errorf("peer credential lookup is supported only on Linux")
}
