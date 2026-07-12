package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// NamespaceFiles turns paths relative to one scanned root into stable archive
// paths. For example, /home/alice/docs/report.txt is stored as
// home/alice/docs/report.txt. This prevents identically named files from two
// configured roots from overwriting one another on the backup server.
func NamespaceFiles(rootPath string, files []FileInfo) (string, []FileInfo, error) {
	rootPrefix, err := ArchiveRootPrefix(rootPath)
	if err != nil {
		return "", nil, err
	}

	namespaced := make([]FileInfo, len(files))
	for i, file := range files {
		relPath := filepath.Clean(file.Path)
		if relPath == "." || filepath.IsAbs(relPath) || relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
			return "", nil, fmt.Errorf("invalid path relative to backup root: %q", file.Path)
		}
		namespaced[i] = file
		namespaced[i].Path = filepath.Join(rootPrefix, relPath)
	}
	return rootPrefix, namespaced, nil
}

// ArchiveRootPrefix returns the relative storage prefix for a source root.
// Paths are made absolute before normalizing so relative rule paths remain
// stable within the agent process.
func ArchiveRootPrefix(rootPath string) (string, error) {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return "", fmt.Errorf("make backup root absolute: %w", err)
	}
	cleanRoot := filepath.Clean(absRoot)
	prefix := strings.TrimPrefix(cleanRoot, string(filepath.Separator))
	if prefix == "" {
		return "_root", nil
	}
	return prefix, nil
}
