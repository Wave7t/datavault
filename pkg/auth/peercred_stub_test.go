//go:build !linux

package auth

import (
	"strings"
	"testing"
)

func TestGetPeerUIDUnsupported(t *testing.T) {
	_, err := GetPeerUID(nil)
	if err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Fatalf("GetPeerUID error = %v, want Linux-only error", err)
	}
}
