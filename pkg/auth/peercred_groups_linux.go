//go:build linux

package auth

import (
	"fmt"
	"os"
)

// ReadPeerGroups reads /proc/<pid>/status and returns the supplementary GIDs.
// On Linux the Agent calls this from peerCredListener.Accept (so the PID is
// still valid). Failures cause the caller to fall back to no-groups;
// min_uid-only trust policies still work, group-based policies will deny.
func ReadPeerGroups(pid int32) ([]uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	return ParseProcStatusGroups(data)
}
