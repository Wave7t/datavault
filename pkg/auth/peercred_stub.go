//go:build !linux

package auth

import (
	"fmt"
	"net"
)

// GetPeerUID is intentionally unavailable outside Linux because the Agent's
// local authorization model depends on Linux SO_PEERCRED semantics.
func GetPeerUID(conn net.Conn) (uint32, error) {
	return 0, fmt.Errorf("peer credential lookup is supported only on Linux")
}
