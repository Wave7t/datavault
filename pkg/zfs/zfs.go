package zfs

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ZFS wraps ZFS command operations against a specific pool.
// All commands are executed via exec.Command with individual args (never sh -c).
type ZFS struct {
	poolPath string // e.g., "tank/backups"
	runZFS   func(args ...string) (string, error)
}

// New creates a new ZFS manager for the given pool path.
// The pool path is validated against dataset naming rules.
func New(poolPath string) (*ZFS, error) {
	if err := ValidateDatasetName(poolPath); err != nil {
		return nil, fmt.Errorf("invalid pool path: %w", err)
	}
	return &ZFS{poolPath: poolPath}, nil
}

// zfs executes a ZFS command with the given arguments and returns trimmed stdout.
// Individual args are passed directly to exec.Command (never via sh -c).
func (z *ZFS) zfs(args ...string) (string, error) {
	if z.runZFS != nil {
		return z.runZFS(args...)
	}
	cmd := exec.Command("zfs", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("zfs %v: %s (%w)", args, strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// EnsureDatasetMounted mounts name and every dataset between the configured
// backup pool and name. A dataset's mountpoint property alone is insufficient:
// ZFS may retain a valid mountpoint property while the filesystem is not
// currently mounted, which would make the Receiver write into an obscured
// parent-directory path or leave completed backup data inaccessible.
func (z *ZFS) EnsureDatasetMounted(name string) error {
	if err := ValidateDatasetName(name); err != nil {
		return err
	}
	if name != z.poolPath && !strings.HasPrefix(name, z.poolPath+"/") {
		return fmt.Errorf("dataset %q is outside backup pool %q", name, z.poolPath)
	}

	dataset := z.poolPath
	if err := z.ensureMounted(dataset); err != nil {
		return err
	}
	if name == z.poolPath {
		return nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, z.poolPath+"/"), "/") {
		if part == "" {
			continue
		}
		dataset += "/" + part
		if err := z.ensureMounted(dataset); err != nil {
			return err
		}
	}
	return nil
}

func (z *ZFS) ensureMounted(dataset string) error {
	mounted, err := z.zfs("get", "-Hp", "-o", "value", "mounted", dataset)
	if err != nil {
		return fmt.Errorf("get mounted state for %q: %w", dataset, err)
	}
	switch mounted {
	case "yes":
		return nil
	case "no":
		if _, err := z.zfs("mount", dataset); err != nil {
			return fmt.Errorf("mount %q: %w", dataset, err)
		}
		mounted, err = z.zfs("get", "-Hp", "-o", "value", "mounted", dataset)
		if err != nil {
			return fmt.Errorf("verify mounted state for %q: %w", dataset, err)
		}
		if mounted == "yes" {
			return nil
		}
		return fmt.Errorf("dataset %q remained unmounted after zfs mount (state %q)", dataset, mounted)
	default:
		return fmt.Errorf("unexpected mounted state %q for dataset %q", mounted, dataset)
	}
}

// CreateDataset creates a new ZFS dataset. It is idempotent: if the dataset
// already exists, no error is returned.
func (z *ZFS) CreateDataset(name string) error {
	if err := ValidateDatasetName(name); err != nil {
		return err
	}
	// A backup dataset is nested below the pool by hostname and username. The
	// hostname-level parent does not exist on a first backup, so creation must
	// create intermediate datasets as well.
	_, err := z.zfs("create", "-p", name)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil // idempotent
		}
		return err
	}
	return nil
}

// SetQuota sets the ZFS quota on a dataset in gigabytes.
func (z *ZFS) SetQuota(dataset string, quotaGB int64) error {
	if err := ValidateDatasetName(dataset); err != nil {
		return err
	}
	_, err := z.zfs("set", "quota="+strconv.FormatInt(quotaGB, 10)+"G", dataset)
	return err
}

// GetUsed returns the used bytes for a dataset.
func (z *ZFS) GetUsed(dataset string) (int64, error) {
	if err := ValidateDatasetName(dataset); err != nil {
		return 0, err
	}
	out, err := z.zfs("get", "-Hp", "-o", "value", "used", dataset)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(out, 10, 64)
}

// Mountpoint returns the mounted filesystem path for the configured backup
// dataset. The receiver must use this ZFS property rather than deriving a
// path from the dataset name, because production pools are often mounted
// outside the default /<pool>/<dataset> hierarchy.
func (z *ZFS) Mountpoint() (string, error) {
	out, err := z.zfs("get", "-Hp", "-o", "value", "mountpoint", z.poolPath)
	if err != nil {
		return "", fmt.Errorf("get mountpoint for %q: %w", z.poolPath, err)
	}
	mountpoint := filepath.Clean(strings.TrimSpace(out))
	if !filepath.IsAbs(mountpoint) || mountpoint == "/" || mountpoint == "." {
		return "", fmt.Errorf("backup pool %q has unusable mountpoint %q", z.poolPath, out)
	}
	return mountpoint, nil
}

// DatasetExists checks whether a ZFS dataset exists.
func (z *ZFS) DatasetExists(name string) (bool, error) {
	if err := ValidateDatasetName(name); err != nil {
		return false, err
	}
	cmd := exec.Command("zfs", "list", "-H", name)
	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
