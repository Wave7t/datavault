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
	// Multiple configured roots can finish in the same second. Nanoseconds make
	// the snapshot name unique without relying on retrying an ambiguous failure.
	ts := time.Now().UTC().Format("20060102-150405.000000000")
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
	out, err := z.zfs("list", "-H", "-o", "name", "-t", "snapshot", "-s", "creation", "-r", dataset)
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

// LatestSnapshot returns the newest snapshot for dataset in creation order.
// A restore must use this durable point-in-time state rather than files that
// may be changing in the live dataset during the restore stream.
func (z *ZFS) LatestSnapshot(dataset string) (string, error) {
	snaps, err := z.ListSnapshots(dataset)
	if err != nil {
		return "", err
	}
	if len(snaps) == 0 {
		return "", fmt.Errorf("no snapshots available for %q", dataset)
	}
	return snaps[len(snaps)-1], nil
}

// CreateRestoreClone creates a temporary clone of a snapshot and returns the
// clone name plus its mount point. Clones provide a stable, read-only restore
// view even when the live backup dataset is receiving new uploads.
func (z *ZFS) CreateRestoreClone(snapshot string) (string, string, error) {
	if !strings.Contains(snapshot, "@") {
		return "", "", fmt.Errorf("invalid snapshot name %q", snapshot)
	}
	clone := fmt.Sprintf("%s/_restore-%d", z.poolPath, time.Now().UTC().UnixNano())
	if _, err := z.zfs("clone", snapshot, clone); err != nil {
		return "", "", fmt.Errorf("clone snapshot %q: %w", snapshot, err)
	}
	mountpoint, err := z.zfs("get", "-Hp", "-o", "value", "mountpoint", clone)
	if err != nil {
		_ = z.DestroyRestoreClone(clone)
		return "", "", fmt.Errorf("get clone mountpoint %q: %w", clone, err)
	}
	if mountpoint == "" || mountpoint == "none" || mountpoint == "legacy" {
		_ = z.DestroyRestoreClone(clone)
		return "", "", fmt.Errorf("clone %q has unusable mountpoint %q", clone, mountpoint)
	}
	return clone, mountpoint, nil
}

// DestroyRestoreClone removes a temporary restore clone. ZFS generally
// unmounts it with -f; the retry covers implementations that require an
// explicit unmount before destruction.
func (z *ZFS) DestroyRestoreClone(clone string) error {
	if _, err := z.zfs("destroy", "-f", clone); err == nil {
		return nil
	}
	// Some ZFS implementations report an already-unmounted clone here even
	// though a second destroy succeeds, so the unmount is best effort.
	_, _ = z.zfs("unmount", clone)
	if _, err := z.zfs("destroy", "-f", clone); err != nil {
		return fmt.Errorf("destroy restore clone %q after unmount: %w", clone, err)
	}
	return nil
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

	// Check free space and prune more if needed. Re-read ZFS state after every
	// destroy rather than estimating reclaimed space from a stale snapshot list.
	remaining := snaps
	for len(remaining) > minKeep && len(remaining) > maxKeep {
		if err := z.DestroySnapshot(remaining[0]); err != nil {
			return fmt.Errorf("destroy snapshot %q: %w", remaining[0], err)
		}
		remaining = remaining[1:]
	}
	for {
		out, err := z.zfs("get", "-Hp", "-o", "value", "available", dataset)
		if err != nil {
			return fmt.Errorf("get available space for %q: %w", dataset, err)
		}
		freeBytes, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if err != nil {
			return fmt.Errorf("parse available space for %q: %w", dataset, err)
		}
		freeGB := freeBytes / (1024 * 1024 * 1024)
		if freeGB >= minFreeGB {
			break
		}
		if len(remaining) <= minKeep {
			return fmt.Errorf("available space is %d GiB, below required %d GiB while preserving %d snapshots", freeGB, minFreeGB, minKeep)
		}
		if err := z.DestroySnapshot(remaining[0]); err != nil {
			return fmt.Errorf("cleanup destroy: %w", err)
		}
		remaining = remaining[1:]
	}

	return nil
}
