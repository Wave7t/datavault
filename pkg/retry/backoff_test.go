// pkg/retry/backoff_test.go
package retry

import (
	"testing"
	"time"
)

func TestBackoffIncreases(t *testing.T) {
	b := New(Config{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	})

	prev := time.Duration(0)
	for i := 0; i < 10; i++ {
		next := b.Next()
		if next <= prev {
			t.Fatalf("attempt %d: %v <= %v (not increasing)", i, next, prev)
		}
		prev = next
	}
}

func TestBackoffMaxCapped(t *testing.T) {
	b := New(Config{
		Initial:    1 * time.Second,
		Max:        5 * time.Second,
		Multiplier: 10.0,
	})

	// Skip to high attempt count
	for i := 0; i < 5; i++ {
		b.Next()
	}
	next := b.Next()
	if next > 5*time.Second {
		t.Fatalf("expected cap at 5s, got %v", next)
	}
}

func TestBackoffMaxElapsed(t *testing.T) {
	b := New(Config{
		Initial:    200 * time.Millisecond,
		Max:        10 * time.Second,
		Multiplier: 2.0,
		MaxElapsed: 500 * time.Millisecond,
	})

	for {
		d := b.Next()
		if d == 0 {
			return // exceeded, test passes
		}
	}
}

func TestBackoffReset(t *testing.T) {
	b := New(Config{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	})

	b.Next()
	b.Next()
	b.Reset()

	if b.Attempt() != 0 {
		t.Fatal("attempt should be 0 after reset")
	}
}

func TestBackoffJitter(t *testing.T) {
	// With jitter, values should vary
	intervals := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		b := New(Config{
			Initial:    1 * time.Second,
			Max:        60 * time.Second,
			Multiplier: 2.0,
			Jitter:     0.5,
		})
		intervals[b.Next()] = true
	}
	if len(intervals) < 2 {
		t.Fatal("jitter should produce varying intervals")
	}
}
