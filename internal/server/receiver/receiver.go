package receiver

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Receiver handles reading and writing files to/from ZFS dataset mount points.
// All operations include path traversal protection.
type Receiver struct {
	MountPoint string // ZFS dataset mount point root
}

// ChunkWriter stages one large-file upload. The final rename is atomic, so a
// stream failure never exposes a partially assembled backup file.
type ChunkWriter struct {
	targetPath string
	tmpFile    *os.File
	committed  bool
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
	return r.ReadAllFrom(baseDir, yield)
}

// ReadAllFrom reads every regular file below a trusted dataset mount point.
// It is used for temporary ZFS clone mounts during restore, while ReadAll
// retains the normal host/user dataset layout used by live backup writes.
func (r *Receiver) ReadAllFrom(baseDir string, yield func(path string, content []byte, mode uint32) error) error {
	if !filepath.IsAbs(baseDir) {
		return fmt.Errorf("dataset mount point must be absolute: %q", baseDir)
	}
	baseDir = filepath.Clean(baseDir)

	return filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk dataset: %w", err)
		}
		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return fmt.Errorf("make dataset-relative path for %q: %w", path, err)
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat backup file %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read backup file %q: %w", path, err)
		}

		return yield(relPath, data, uint32(info.Mode().Perm()))
	})
}

// ReadAllChunksFrom yields large regular files in bounded chunks while small
// files remain a single entry. It is used by restore so a valid large backup
// never has to fit in one gRPC message or one server allocation.
func (r *Receiver) ReadAllChunksFrom(baseDir string, maxChunkBytes int, yield func(path string, content []byte, mode uint32, offset uint64, chunked, final bool) error) error {
	if !filepath.IsAbs(baseDir) {
		return fmt.Errorf("dataset mount point must be absolute: %q", baseDir)
	}
	if maxChunkBytes <= 0 {
		return fmt.Errorf("chunk size must be positive")
	}
	baseDir = filepath.Clean(baseDir)

	return filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk dataset: %w", err)
		}
		if d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return fmt.Errorf("make dataset-relative path for %q: %w", path, err)
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat backup file %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open backup file %q: %w", path, err)
		}
		defer file.Close()
		if info.Size() <= int64(maxChunkBytes) {
			data, err := io.ReadAll(file)
			if err != nil {
				return fmt.Errorf("read backup file %q: %w", path, err)
			}
			return yield(relPath, data, uint32(info.Mode().Perm()), 0, false, true)
		}

		buf := make([]byte, maxChunkBytes)
		var offset int64
		for offset < info.Size() {
			want := int64(len(buf))
			if remaining := info.Size() - offset; remaining < want {
				want = remaining
			}
			n, readErr := io.ReadFull(file, buf[:want])
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				return fmt.Errorf("read backup file %q: %w", path, readErr)
			}
			if n == 0 || (readErr != nil && offset+int64(n) != info.Size()) {
				return fmt.Errorf("backup file %q changed while restoring", path)
			}
			final := offset+int64(n) == info.Size()
			if err := yield(relPath, append([]byte(nil), buf[:n]...), uint32(info.Mode().Perm()), uint64(offset), true, final); err != nil {
				return err
			}
			offset += int64(n)
		}
		return nil
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

// NewChunkWriter creates an atomic staging file for a chunked upload.
func (r *Receiver) NewChunkWriter(hostname, username, relPath string) (*ChunkWriter, error) {
	targetPath, err := r.targetPath(hostname, username, relPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(targetPath), ".dvault-chunk-*")
	if err != nil {
		return nil, fmt.Errorf("create chunk staging file: %w", err)
	}
	return &ChunkWriter{targetPath: targetPath, tmpFile: tmpFile}, nil
}

// Write appends one ordered chunk to the staged file.
func (w *ChunkWriter) Write(content []byte) error {
	if w == nil || w.tmpFile == nil {
		return fmt.Errorf("chunk writer is closed")
	}
	if _, err := w.tmpFile.Write(content); err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}
	return nil
}

// Commit closes, applies mode, and atomically publishes the full file.
func (w *ChunkWriter) Commit(mode uint32) error {
	if w == nil || w.tmpFile == nil {
		return fmt.Errorf("chunk writer is closed")
	}
	if err := w.tmpFile.Close(); err != nil {
		return fmt.Errorf("close chunk staging file: %w", err)
	}
	if err := os.Chmod(w.tmpFile.Name(), os.FileMode(mode&0777)); err != nil {
		return fmt.Errorf("chmod chunk staging file: %w", err)
	}
	if err := os.Rename(w.tmpFile.Name(), w.targetPath); err != nil {
		return fmt.Errorf("rename chunk staging file: %w", err)
	}
	w.tmpFile = nil
	w.committed = true
	return nil
}

// Abort removes an incomplete staging file. It is safe to call after Commit.
func (w *ChunkWriter) Abort() {
	if w == nil || w.tmpFile == nil || w.committed {
		return
	}
	name := w.tmpFile.Name()
	_ = w.tmpFile.Close()
	_ = os.Remove(name)
	w.tmpFile = nil
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
