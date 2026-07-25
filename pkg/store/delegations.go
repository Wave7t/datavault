package store

import (
	"database/sql"
	"fmt"
	"time"
)

// WebDelegation records that a Unix user has authorized one HTTPS gateway
// (identified by its client-certificate CN) to act on their behalf until
// ExpiresAt. Rows are created only by the local enrollment ceremony and are
// never modifiable through the HTTPS API itself.
type WebDelegation struct {
	Username         string
	GatewayCN        string
	DelegationPubKey string
	ExpiresAt        time.Time
	CreatedAt        time.Time
	RevokedAt        *time.Time
}

// MigrateWebDelegations creates the web_delegations table if it does not exist.
func MigrateWebDelegations(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS web_delegations (
			username           TEXT NOT NULL,
			gateway_cn         TEXT NOT NULL,
			delegation_pubkey  TEXT NOT NULL,
			expires_at         INTEGER NOT NULL,
			created_at         INTEGER NOT NULL,
			revoked_at         INTEGER,
			PRIMARY KEY (username, gateway_cn)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate web_delegations: %w", err)
	}
	return nil
}

// UpsertWebDelegation inserts or replaces a delegation (re-enrollment
// refreshes the key and expiry and clears any revocation).
func UpsertWebDelegation(db *sql.DB, d WebDelegation) error {
	_, err := db.Exec(`
		INSERT INTO web_delegations (username, gateway_cn, delegation_pubkey, expires_at, created_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, NULL)
		ON CONFLICT (username, gateway_cn) DO UPDATE SET
			delegation_pubkey = excluded.delegation_pubkey,
			expires_at        = excluded.expires_at,
			created_at        = excluded.created_at,
			revoked_at        = NULL
	`, d.Username, d.GatewayCN, d.DelegationPubKey, d.ExpiresAt.Unix(), d.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("upsert web delegation: %w", err)
	}
	return nil
}

// GetWebDelegation returns the delegation for (username, gatewayCN), or
// (nil, nil) when none exists. Revoked and expired rows are still returned;
// callers decide how to treat them.
func GetWebDelegation(db *sql.DB, username, gatewayCN string) (*WebDelegation, error) {
	row := db.QueryRow(`
		SELECT username, gateway_cn, delegation_pubkey, expires_at, created_at, revoked_at
		FROM web_delegations WHERE username = ? AND gateway_cn = ?
	`, username, gatewayCN)
	return scanWebDelegation(row)
}

// RevokeWebDelegation marks a delegation revoked. It is idempotent.
func RevokeWebDelegation(db *sql.DB, username, gatewayCN string) error {
	_, err := db.Exec(`
		UPDATE web_delegations SET revoked_at = ?
		WHERE username = ? AND gateway_cn = ? AND revoked_at IS NULL
	`, time.Now().Unix(), username, gatewayCN)
	if err != nil {
		return fmt.Errorf("revoke web delegation: %w", err)
	}
	return nil
}

// ListWebDelegations returns all delegations (including revoked) for a user.
func ListWebDelegations(db *sql.DB, username string) ([]WebDelegation, error) {
	rows, err := db.Query(`
		SELECT username, gateway_cn, delegation_pubkey, expires_at, created_at, revoked_at
		FROM web_delegations WHERE username = ? ORDER BY gateway_cn
	`, username)
	if err != nil {
		return nil, fmt.Errorf("list web delegations: %w", err)
	}
	defer rows.Close()
	var out []WebDelegation
	for rows.Next() {
		d, err := scanWebDelegationRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanWebDelegation(row rowScanner) (*WebDelegation, error) {
	d, err := scanWebDelegationRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return d, err
}

func scanWebDelegationRow(row rowScanner) (*WebDelegation, error) {
	var d WebDelegation
	var expiresAt, createdAt int64
	var revokedAt sql.NullInt64
	if err := row.Scan(&d.Username, &d.GatewayCN, &d.DelegationPubKey, &expiresAt, &createdAt, &revokedAt); err != nil {
		return nil, err
	}
	d.ExpiresAt = time.Unix(expiresAt, 0)
	d.CreatedAt = time.Unix(createdAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		d.RevokedAt = &t
	}
	return &d, nil
}
