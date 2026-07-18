// pkg/retry/backoff.go
package retry

import (
	"errors"
	"math"
	"math/rand"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if b.cfg.MaxElapsed > 0 && b.elapsed+d > b.cfg.MaxElapsed {
		return 0
	}
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

// permanentError marks an error that can only be resolved by changing local
// configuration, credentials, input files, or server-side policy. Retrying
// it would delay a useful failure notification without improving availability.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent prevents IsRetryable from treating err as a transient failure.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err: err}
}

// IsRetryable classifies transport and server-overload failures that may
// recover without changing the task. Authentication, validation and local
// filesystem errors must be surfaced immediately.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var permanent permanentError
	if errors.As(err, &permanent) {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted, codes.Internal:
		return true
	case codes.OK, codes.Unknown:
		// Continue below: a raw network error has no gRPC status.
	default:
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}
	return false
}
