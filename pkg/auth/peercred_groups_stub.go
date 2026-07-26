//go:build !linux

package auth

import "fmt"

// ReadPeerGroups is unavailable off Linux: the source (/proc/<pid>/status)
// is Linux-specific. The Agent binary is Linux-only and never calls this.
// ParseProcStatusGroups, being a pure parser, is available everywhere via
// the untagged peercred_groups.go.
func ReadPeerGroups(pid int32) ([]uint32, error) {
	return nil, fmt.Errorf("peer groups available only on Linux")
}
