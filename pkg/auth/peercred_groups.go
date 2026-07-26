package auth

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseProcStatusGroups extracts the supplementary GIDs from the contents of
// /proc/<pid>/status. It is a pure string parser with no OS dependencies, so
// it lives in an untagged file and is available on every platform; only
// ReadPeerGroups (which actually opens /proc) is Linux-only.
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
