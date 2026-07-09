package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/example/datavault/pkg/glob"
)

// FileInfo holds metadata for a scanned file.
type FileInfo struct {
	Path   string
	Size   int64
	Mtime  int64 // nanoseconds since Unix epoch
	Mode   uint32
	SHA256 []byte
}

// ScanResult contains the results of a directory scan.
type ScanResult struct {
	Files  []FileInfo
	Errors []error
}

// scanMaxFilesPerSegment handles directories with >10000 files in segments.
const scanMaxFilesPerSegment = 10000

// Scan recursively walks rootPath and collects file metadata and SHA256
// hashes for all regular files. Files matching any exclude pattern in the
// glob.Matcher are skipped (directories matching an exclude pattern are
// skipped entirely via filepath.SkipDir).
func Scan(rootPath string, excludes *glob.Matcher) (*ScanResult, error) {
	result := &ScanResult{}

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("walk %q: %w", path, err))
			return nil // skip files with errors, don't stop
		}

		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("rel path %q: %w", path, err))
			return nil
		}

		// Check exclude patterns
		if excludes != nil && excludes.Match(relPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("stat %q: %w", path, err))
			return nil
		}

		// Skip non-regular files
		if !info.Mode().IsRegular() {
			return nil
		}

		fi := FileInfo{
			Path:  relPath,
			Size:  info.Size(),
			Mtime: info.ModTime().UnixNano(),
			Mode:  uint32(info.Mode().Perm()),
		}

		// Compute SHA256
		h, err := fileHash(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("hash %q: %w", path, err))
			// Still include the file; SHA256 will be nil (triggers re-transfer)
		} else {
			fi.SHA256 = h
		}

		result.Files = append(result.Files, fi)
		return nil
	})

	return result, err
}

// fileHash computes the SHA-256 hash of the file at the given path.
func fileHash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
