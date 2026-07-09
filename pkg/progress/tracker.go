// Package progress provides a thread-safe progress tracker for backup sync operations.
package progress

import (
	"sync"
	"time"
)

// Phase represents the current phase of a sync operation.
type Phase string

const (
	PhaseScanning     Phase = "SCANNING"
	PhaseTransferring Phase = "TRANSFERRING"
	PhaseCompleted    Phase = "COMPLETED"
	PhaseFailed       Phase = "FAILED"
)

// Stats holds the current sync progress statistics.
type Stats struct {
	TotalFiles       int64
	ScannedFiles     int64
	ChangedFiles     int64
	TransferredFiles int64
	TransferredBytes int64
	CurrentRateBPS   int64
}

// Tracker is a thread-safe progress tracker for backup sync operations.
// It tracks scanning progress, file transfer progress, and computes
// the current transfer rate.
type Tracker struct {
	mu           sync.RWMutex
	Phase        Phase
	Stats        Stats
	CurrentFiles []string
	startTime    time.Time
	lastBytes    int64
	lastTime     time.Time
}

// NewTracker creates a new Tracker initialized in the SCANNING phase.
func NewTracker() *Tracker {
	now := time.Now()
	return &Tracker{Phase: PhaseScanning, startTime: now, lastTime: now}
}

// SetPhase updates the current phase.
func (t *Tracker) SetPhase(p Phase) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Phase = p
}

// SetCurrentFiles updates the list of files currently being processed.
func (t *Tracker) SetCurrentFiles(files []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.CurrentFiles = files
}

// AddScanned increments the scanned files counter by n.
func (t *Tracker) AddScanned(n int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Stats.ScannedFiles += n
}

// AddTransferred increments the transferred files and bytes counters, and
// recalculates the transfer rate at most once per second.
func (t *Tracker) AddTransferred(files, bytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Stats.TransferredFiles += files
	t.Stats.TransferredBytes += bytes

	now := time.Now()
	elapsed := now.Sub(t.lastTime)
	if elapsed >= time.Second {
		delta := t.Stats.TransferredBytes - t.lastBytes
		t.Stats.CurrentRateBPS = int64(float64(delta) / elapsed.Seconds())
		t.lastBytes = t.Stats.TransferredBytes
		t.lastTime = now
	}
}

// SetTotals updates the total files and changed files counts.
func (t *Tracker) SetTotals(total, changed int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Stats.TotalFiles = total
	t.Stats.ChangedFiles = changed
}

// Snapshot returns a consistent read of the current phase, stats, and
// current files list. The returned slice is a copy, so it is safe to
// use without holding the lock.
func (t *Tracker) Snapshot() (Phase, Stats, []string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	files := make([]string, len(t.CurrentFiles))
	copy(files, t.CurrentFiles)
	return t.Phase, t.Stats, files
}
