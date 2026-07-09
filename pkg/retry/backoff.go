// pkg/retry/backoff.go
package retry

import (
	"math"
	"math/rand"
	"time"
)

type Config struct {
	Initial    time.Duration
	Max        time.Duration
	Multiplier float64
	Jitter     float64
	MaxElapsed time.Duration
}

type Backoff struct {
	cfg     Config
	attempt int
	elapsed time.Duration
	start   time.Time
}

func New(cfg Config) *Backoff {
	return &Backoff{
		cfg:   cfg,
		start: time.Now(),
	}
}

// Next returns the next backoff duration, or 0 if MaxElapsed is exceeded.
func (b *Backoff) Next() time.Duration {
	if b.cfg.MaxElapsed > 0 && b.elapsed >= b.cfg.MaxElapsed {
		return 0
	}

	interval := float64(b.cfg.Initial) * math.Pow(b.cfg.Multiplier, float64(b.attempt))
	if interval > float64(b.cfg.Max) {
		interval = float64(b.cfg.Max)
	}

	// Apply jitter
	if b.cfg.Jitter > 0 {
		jitterRange := interval * b.cfg.Jitter
		interval = interval - jitterRange/2 + rand.Float64()*jitterRange
	}

	b.attempt++
	d := time.Duration(interval)
	b.elapsed += d
	return d
}

func (b *Backoff) Reset() {
	b.attempt = 0
	b.elapsed = 0
	b.start = time.Now()
}

func (b *Backoff) Attempt() int {
	return b.attempt
}
