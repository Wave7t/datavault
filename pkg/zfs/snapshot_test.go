package zfs

import (
	"strings"
	"testing"
)

// --- Unit tests (no ZFS required) ---

func TestSnapshotNameFormat(t *testing.T) {
	z, err := New("tank/backups")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	name := z.SnapshotName("tank/backups/web-01/alice")

	// Expected format: tank/backups/web-01/alice@sync-YYYYMMDD-HHMMSS
	if !strings.HasPrefix(name, "tank/backups/web-01/alice@sync-") {
		t.Fatalf("unexpected snapshot name format: %q", name)
	}

	// Verify timestamp portion is 15 chars: YYYYMMDD-HHMMSS
	parts := strings.SplitN(name, "@sync-", 2)
	if len(parts) != 2 {
		t.Fatalf("expected @sync- separator in %q", name)
	}
	ts := parts[1]
	if len(ts) != 15 {
		t.Fatalf("expected timestamp length 15 (YYYYMMDD-HHMMSS), got %d: %q", len(ts), ts)
	}
	// Verify format: 8 digits + "-" + 6 digits
	if ts[8] != '-' {
		t.Fatalf("expected dash at position 8 in timestamp: %q", ts)
	}
}

// --- ZFS integration tests (skip if ZFS unavailable) ---

func TestSnapshot_CreateSnapshot(t *testing.T) {
	if !zfsAvailable() {
		t.Skip("ZFS not available")
	}
	z, _ := New("tank/backups")

	// Try to create a snapshot on a non-existent dataset - should fail
	_, err := z.CreateSnapshot("tank/nonexistent-dataset-99999")
	if err == nil {
		t.Fatal("expected error creating snapshot on non-existent dataset")
	}
}

func TestSnapshot_ListSnapshots_NonexistentDataset(t *testing.T) {
	if !zfsAvailable() {
		t.Skip("ZFS not available")
	}
	z, _ := New("tank/backups")

	snaps, err := z.ListSnapshots("tank/nonexistent-dataset-99999")
	if err != nil {
		t.Fatalf("ListSnapshots on non-existent dataset should return nil, got err: %v", err)
	}
	if snaps != nil {
		t.Fatalf("expected nil snapshots for non-existent dataset, got %v", snaps)
	}
}

func TestSnapshot_DestroySnapshot_Nonexistent(t *testing.T) {
	if !zfsAvailable() {
		t.Skip("ZFS not available")
	}
	z, _ := New("tank/backups")

	err := z.DestroySnapshot("tank/nonexistent-dataset-99999@nonexistent-snap")
	if err == nil {
		t.Fatal("expected error destroying non-existent snapshot")
	}
}

func TestSnapshot_CleanupSnapshots_NonexistentDataset(t *testing.T) {
	if !zfsAvailable() {
		t.Skip("ZFS not available")
	}
	z, _ := New("tank/backups")

	// CleanupSnapshots on a non-existent dataset should return nil error
	err := z.CleanupSnapshots("tank/nonexistent-dataset-99999", 2, 7, 1000)
	if err != nil {
		t.Fatalf("CleanupSnapshots on non-existent dataset: %v", err)
	}
}
