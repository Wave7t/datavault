package store

import (
	"database/sql"
	"fmt"
	"time"
)

// MigrateNonces creates the nonces table if it does not exist.
func MigrateNonces(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS nonces (
			nonce      TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL,
			used       INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate nonces: %w", err)
	}
	return nil
}

// InsertNonce stores a new nonce with its expiration time.
func InsertNonce(db *sql.DB, nonce string, expiresAt time.Time) error {
	_, err := db.Exec(
		"INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)",
		nonce, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("insert nonce: %w", err)
	}
	return nil
}

// ConsumeNonce marks a nonce as used if it exists, is not expired, and not yet used.
// Returns true if the nonce was successfully consumed (valid and first use).
// Uses a transaction to prevent race conditions on concurrent consumption.
func ConsumeNonce(db *sql.DB, nonce string) (bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	var used int
	err = tx.QueryRow(
		"SELECT used FROM nonces WHERE nonce = ? AND expires_at > ?",
		nonce, now,
	).Scan(&used)
	if err == sql.ErrNoRows {
		return false, nil // nonce doesn't exist or expired
	}
	if err != nil {
		return false, fmt.Errorf("query nonce: %w", err)
	}
	if used != 0 {
		return false, nil // already consumed
	}

	_, err = tx.Exec("UPDATE nonces SET used = 1 WHERE nonce = ?", nonce)
	if err != nil {
		return false, fmt.Errorf("mark used: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// GCExpiredNonces removes all nonces that have passed their expiration time.
func GCExpiredNonces(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM nonces WHERE expires_at < ?", time.Now().Unix())
	if err != nil {
		return fmt.Errorf("gc nonces: %w", err)
	}
	return nil
}
