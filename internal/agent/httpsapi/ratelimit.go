package httpsapi

import (
	"sync"
	"time"
)

// rateLimiter is a per-key token bucket. It intentionally trades exactness
// for simplicity: buckets are refilled lazily on each request.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time // for tests
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(ratePerSec, burst float64) *rateLimiter {
	return &rateLimiter{
		rate: ratePerSec, burst: burst,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.burst, last: rl.now()}
		rl.buckets[key] = b
	}
	elapsed := rl.now().Sub(b.last).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = rl.now()
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
