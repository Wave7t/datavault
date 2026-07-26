//go:build linux

package auth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadPeerGroups reads /proc/<pid>/status and returns the supplementary GIDs.
// On Linux the Agent calls this from peerCredListener.Accept (so the PID is
// still valid). Failures are fatal: the caller falls back to no-groups,
// which conservative trust policies will deny.
func ReadPeerGroups(pid int32) ([]uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	return ParseProcStatusGroups(data)
}

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
