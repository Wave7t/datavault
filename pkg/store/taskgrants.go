package store

import (
	"database/sql"
	"fmt"
	"time"
)

// TaskGrant authorizes one ephemeral key to sign batches for one
// host/user/method until ExpiresAt. Created only via RegisterTaskGrant,
// which requires a gateway delegation signature.
type TaskGrant struct {
	Hostname             string
	Username             string
	Method               string
	EphemeralFingerprint string
	EphemeralPubKey      string
	ExpiresAt            time.Time
}

func MigrateTaskGrants(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS task_grants (
			hostname              TEXT NOT NULL,
			username              TEXT NOT NULL,
			method                TEXT NOT NULL,
			ephemeral_fingerprint TEXT NOT NULL,
			ephemeral_pubkey      TEXT NOT NULL,
			expires_at            INTEGER NOT NULL,
			PRIMARY KEY (hostname, username, ephemeral_fingerprint)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate task_grants: %w", err)
	}
	return nil
}

func InsertTaskGrant(db *sql.DB, g TaskGrant) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO task_grants
			(hostname, username, method, ephemeral_fingerprint, ephemeral_pubkey, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, g.Hostname, g.Username, g.Method, g.EphemeralFingerprint, g.EphemeralPubKey, g.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("insert task grant: %w", err)
	}
	return nil
}

// GetTaskGrant returns the unexpired grant for the key, or (nil, nil).
func GetTaskGrant(db *sql.DB, hostname, username, fingerprint string, now time.Time) (*TaskGrant, error) {
	var g TaskGrant
	var expiresAt int64
	err := db.QueryRow(`
		SELECT hostname, username, method, ephemeral_fingerprint, ephemeral_pubkey, expires_at
		FROM task_grants
		WHERE hostname = ? AND username = ? AND ephemeral_fingerprint = ? AND expires_at > ?
	`, hostname, username, fingerprint, now.Unix()).
		Scan(&g.Hostname, &g.Username, &g.Method, &g.EphemeralFingerprint, &g.EphemeralPubKey, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get task grant: %w", err)
	}
	g.ExpiresAt = time.Unix(expiresAt, 0)
	return &g, nil
}

func GCExpiredTaskGrants(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM task_grants WHERE expires_at < ?", time.Now().Unix())
	if err != nil {
		return fmt.Errorf("gc task_grants: %w", err)
	}
	return nil
}
