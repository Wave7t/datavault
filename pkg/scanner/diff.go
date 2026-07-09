package scanner

import (
	"bytes"
	"database/sql"
	"fmt"

	"github.com/example/datavault/pkg/store"
)

// DiffAction classifies how a scanned file differs from its previous snapshot.
type DiffAction int

const (
	DiffSkip   DiffAction = iota // file unchanged
	DiffAdd                       // new file not previously backed up
	DiffModify                    // file metadata or content changed
	DiffDelete                    // file existed before but removed on disk
)

// FileDiff pairs a scanned FileInfo with the action that should be taken.
type FileDiff struct {
	File   FileInfo
	Action DiffAction
}

// ComputeDiff compares scanned files against the snapshot DB for a given
// server/user pair. It returns the list of files that need action (add,
// modify, or delete) and any per-step errors that were encountered.
//
// Files are classified as:
//   - DiffAdd:    present in the scan but not in the database
//   - DiffModify: present in both but mtime/size changed and SHA256 differs
//   - DiffDelete: present in the database but missing from the scan
//   - DiffSkip:   present in both with matching mtime, size and SHA256 (not returned)
func ComputeDiff(scanned []FileInfo, db *sql.DB, serverID, username string) ([]FileDiff, []error) {
	var diffs []FileDiff
	var errs []error

	// Build set of scanned paths for O(1) lookup.
	scannedPaths := make(map[string]FileInfo, len(scanned))
	for _, f := range scanned {
		scannedPaths[f.Path] = f
	}

	// Check existing snapshots for deletes and modifications.
	existing, err := store.ListUserSnapshots(db, serverID, username)
	if err != nil {
		errs = append(errs, fmt.Errorf("list snapshots: %w", err))
		return diffs, errs
	}

	for _, snap := range existing {
		scannedFile, found := scannedPaths[snap.FilePath]
		if !found {
			// File existed before but is not in the current scan → deleted.
			diffs = append(diffs, FileDiff{
				File:   FileInfo{Path: snap.FilePath},
				Action: DiffDelete,
			})
			continue
		}

		// File exists in both — check for changes.
		if scannedFile.Mtime != snap.Mtime || scannedFile.Size != snap.Size {
			// Metadata changed; verify content via SHA256.
			if !bytes.Equal(scannedFile.SHA256, snap.SHA256) {
				diffs = append(diffs, FileDiff{
					File:   scannedFile,
					Action: DiffModify,
				})
			}
		}
		// Remove from scanned set so we do not report it as new.
		delete(scannedPaths, snap.FilePath)
	}

	// Remaining scanned paths are new files.
	for _, f := range scannedPaths {
		diffs = append(diffs, FileDiff{
			File:   f,
			Action: DiffAdd,
		})
	}

	return diffs, errs
}
