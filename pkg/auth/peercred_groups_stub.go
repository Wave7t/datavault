//go:build !linux

package auth

import (
	"fmt"
	"strconv"
	"strings"
)

// ReadPeerGroups is unavailable off Linux: the source (/proc/<pid>/status)
// is Linux-specific. The Agent binary is Linux-only and never calls this.
func ReadPeerGroups(pid int32) ([]uint32, error) {
	return nil, fmt.Errorf("peer groups available only on Linux")
}

// ParseProcStatusGroups is a pure string parser with no OS dependencies, so
// it is implemented identically on non-Linux for test symmetry. Only
// ReadPeerGroups (which touches /proc) is Linux-only.
func ParseProcStatusGroups(procStatus []byte) ([]uint32, error) {
	for _, line := range strings.Split(string(procStatus), "\n") {
		if !strings.HasPrefix(line, "Groups:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "Groups:"))
		if rest == "" {
			return nil, nil
		}
		fields := strings.Fields(rest)
		gids := make([]uint32, 0, len(fields))
		for _, f := range fields {
			g, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parse group id %q: %w", f, err)
			}
			gids = append(gids, uint32(g))
		}
		return gids, nil
	}
	return nil, fmt.Errorf("Groups: line not found")
}
