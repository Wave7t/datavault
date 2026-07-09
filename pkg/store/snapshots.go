package store

import (
	"database/sql"
	"fmt"
	"time"
)

// FileSnapshot represents a single file's backup state in the local tracking DB.
type FileSnapshot struct {
	ServerID string
	Username string
	FilePath string
	Mtime    int64  // nanoseconds
	Size     int64  // bytes
	SHA256   []byte
	SyncedAt int64  // unix timestamp
}

// MigrateSnapshots creates the file_snapshots table if it does not exist.
func MigrateSnapshots(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS file_snapshots (
			server_id TEXT NOT NULL,
			username  TEXT NOT NULL,
			file_path TEXT NOT NULL,
			mtime_ns  INTEGER NOT NULL,
			size_bytes INTEGER NOT NULL,
			sha256    BLOB,
			synced_at INTEGER NOT NULL,
			PRIMARY KEY (server_id, username, file_path)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate file_snapshots: %w", err)
	}
	return nil
}

// UpsertSnapshot inserts or replaces a file snapshot in the database.
// It sets SyncedAt to the current time before writing.
func UpsertSnapshot(db *sql.DB, s FileSnapshot) error {
	s.SyncedAt = time.Now().Unix()
	_, err := db.Exec(`
		INSERT OR REPLACE INTO file_snapshots
			(server_id, username, file_path, mtime_ns, size_bytes, sha256, synced_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, s.ServerID, s.Username, s.FilePath, s.Mtime, s.Size, s.SHA256, s.SyncedAt)
	return err
}

// GetSnapshot retrieves a single file snapshot by its composite key.
// Returns nil, nil if no matching row exists.
func GetSnapshot(db *sql.DB, serverID, username, filePath string) (*FileSnapshot, error) {
	row := db.QueryRow(`
		SELECT server_id, username, file_path, mtime_ns, size_bytes, sha256, synced_at
		FROM file_snapshots
		WHERE server_id = ? AND username = ? AND file_path = ?
	`, serverID, username, filePath)

	var s FileSnapshot
	err := row.Scan(&s.ServerID, &s.Username, &s.FilePath, &s.Mtime, &s.Size, &s.SHA256, &s.SyncedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteSnapshot removes a file snapshot from the database.
func DeleteSnapshot(db *sql.DB, serverID, username, filePath string) error {
	_, err := db.Exec(`
		DELETE FROM file_snapshots
		WHERE server_id = ? AND username = ? AND file_path = ?
	`, serverID, username, filePath)
	return err
}

// ListUserSnapshots returns all file snapshots for a given user on a server.
func ListUserSnapshots(db *sql.DB, serverID, username string) ([]FileSnapshot, error) {
	rows, err := db.Query(`
		SELECT server_id, username, file_path, mtime_ns, size_bytes, sha256, synced_at
		FROM file_snapshots
		WHERE server_id = ? AND username = ?
	`, serverID, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snaps []FileSnapshot
	for rows.Next() {
		var s FileSnapshot
		if err := rows.Scan(&s.ServerID, &s.Username, &s.FilePath, &s.Mtime, &s.Size, &s.SHA256, &s.SyncedAt); err != nil {
			return nil, err
		}
		snaps = append(snaps, s)
	}
	return snaps, rows.Err()
}
