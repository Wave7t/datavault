package scheduler

import (
	"testing"
	"time"
)

func TestWithinWindow(t *testing.T) {
	at := func(hour, minute int) time.Time {
		return time.Date(2026, time.January, 1, hour, minute, 0, 0, time.Local)
	}
	for _, test := range []struct {
		name       string
		start, end string
		now        time.Time
		want       bool
	}{
		{"day-inside", "09:00", "17:00", at(12, 0), true},
		{"day-end-exclusive", "09:00", "17:00", at(17, 0), false},
		{"overnight-evening", "22:00", "06:00", at(23, 0), true},
		{"overnight-morning", "22:00", "06:00", at(5, 59), true},
		{"overnight-day", "22:00", "06:00", at(12, 0), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := WithinWindow(test.now, test.start, test.end)
			if err != nil || got != test.want {
				t.Fatalf("WithinWindow=%v, %v; want %v", got, err, test.want)
			}
		})
	}
}
