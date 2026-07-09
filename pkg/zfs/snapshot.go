package zfs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SnapshotName generates a timestamp-based snapshot name for a dataset.
// Format: dataset@sync-YYYYMMDD-HHMMSS (UTC)
func (z *ZFS) SnapshotName(dataset string) string {
	ts := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("%s@sync-%s", dataset, ts)
}

// CreateSnapshot creates a ZFS snapshot for the given dataset and returns
// the full snapshot name (dataset@snapshot).
func (z *ZFS) CreateSnapshot(dataset string) (string, error) {
	name := z.SnapshotName(dataset)
	_, err := z.zfs("snapshot", name)
	return name, err
}

// ListSnapshots returns all snapshot names under the given dataset (recursively).
// Returns nil if the dataset does not exist.
func (z *ZFS) ListSnapshots(dataset string) ([]string, error) {
	out, err := z.zfs("list", "-H", "-o", "name", "-t", "snapshot", "-r", dataset)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, nil
		}
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// DestroySnapshot destroys a ZFS snapshot.
func (z *ZFS) DestroySnapshot(snapshot string) error {
	_, err := z.zfs("destroy", snapshot)
	return err
}

// CleanupSnapshots prunes old snapshots keeping at least minKeep.
// It also ensures at least minFreeGB of free space.
func (z *ZFS) CleanupSnapshots(dataset string, minKeep, maxKeep int, minFreeGB int64) error {
	snaps, err := z.ListSnapshots(dataset)
	if err != nil {
		return err
	}
	if len(snaps) <= minKeep {
		return nil
	}

	for i := 0; i < len(snaps) && len(snaps)-i > minKeep && len(snaps)-i > maxKeep; i++ {
		if err := z.DestroySnapshot(snaps[i]); err != nil {
			return fmt.Errorf("destroy snapshot %q: %w", snaps[i], err)
		}
	}

	// Check free space and prune more if needed
	used, _ := z.GetUsed(dataset)
	// Get pool free space
	out, err := z.zfs("get", "-Hp", "-o", "value", "available", dataset)
	if err != nil {
		return nil // can't check, skip
	}
	freeBytes, _ := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	freeGB := freeBytes / (1024 * 1024 * 1024)

	remaining := snaps
	if len(snaps) > minKeep {
		remaining = snaps[:minKeep]
	}
	for freeGB < minFreeGB && len(remaining) > 1 {
		if err := z.DestroySnapshot(remaining[0]); err != nil {
			return fmt.Errorf("cleanup destroy: %w", err)
		}
		remaining = remaining[1:]
		freeGB += used / int64(len(remaining)+1) // rough estimate
	}

	return nil
}
