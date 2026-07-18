package main

import "testing"

func TestQuotaWarningReached(t *testing.T) {
	for _, test := range []struct {
		used, quota, percent int64
		want                 bool
	}{
		{89, 100, 90, false},
		{90, 100, 90, true},
		{1, 3, 34, false},
		{2, 3, 34, true},
		{100, 0, 90, false},
	} {
		if got := quotaWarningReached(test.used, test.quota, test.percent); got != test.want {
			t.Fatalf("quotaWarningReached(%d,%d,%d)=%v, want %v", test.used, test.quota, test.percent, got, test.want)
		}
	}
}
