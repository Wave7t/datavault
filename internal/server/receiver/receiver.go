package receiver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Receiver handles reading and writing files to/from ZFS dataset mount points.
// All operations include path traversal protection.
type Receiver struct {
	MountPoint string // ZFS dataset mount point root
}

// New creates a new Receiver for the given mount point.
func New(mountPoint string) *Receiver {
	return &Receiver{MountPoint: mountPoint}
}

// ReadAll reads all files for a hostname/username combination and yields
// each file's path, content, and mode to the callback. Errors during walk
// of individual files are skipped; only fatal directory-level errors stop
// the iteration.
func (r *Receiver) ReadAll(hostname, username string, yield func(path string, content []byte, mode uint32) error) error {
	baseDir := filepath.Join(r.MountPoint, hostname, username)

	return filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk dataset: %w", err)
		}
		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return nil // skip
		}

		info, err := d.Info()
		if err != nil {
			return nil // skip
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		return yield(relPath, data, uint32(info.Mode().Perm()))
	})
}

// WriteFile atomically writes a file to the dataset, with path traversal protection.
func (r *Receiver) WriteFile(hostname, username, relPath string, content []byte, mode uint32) error {
	targetPath, err := r.targetPath(hostname, username, relPath)
	if err != nil {
		return err
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Atomic write: temp file -> rename
	tmpFile, err := os.CreateTemp(filepath.Dir(targetPath), ".dvault-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Chmod(tmpFile.Name(), os.FileMode(mode&0777)); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), targetPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}

// DeleteFile removes a file from the dataset.
func (r *Receiver) DeleteFile(hostname, username, relPath string) error {
	targetPath, err := r.targetPath(hostname, username, relPath)
	if err != nil {
		return err
	}

	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (r *Receiver) targetPath(hostname, username, relPath string) (string, error) {
	cleanPath := filepath.Clean(relPath)
	if relPath == "" || cleanPath == "." || filepath.IsAbs(relPath) || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid dataset-relative path: %q", relPath)
	}

	baseDir := filepath.Clean(filepath.Join(r.MountPoint, hostname, username))
	targetPath := filepath.Join(baseDir, cleanPath)
	if !strings.HasPrefix(targetPath, baseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected: %q escapes %q", relPath, baseDir)
	}
	return targetPath, nil
}
