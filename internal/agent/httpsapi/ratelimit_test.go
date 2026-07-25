package httpsapi

import (
	"testing"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(2, 2) // 2 rps, burst 2
	for i := 0; i < 2; i++ {
		if !rl.allow("gw") {
			t.Fatalf("burst %d should be allowed", i)
		}
	}
	if rl.allow("gw") {
		t.Fatal("third immediate request must be limited")
	}
	if !rl.allow("other-gw") {
		t.Fatal("limits are per key")
	}
}
