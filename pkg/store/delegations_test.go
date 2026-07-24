package store

import (
	"database/sql"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := MigrateWebDelegations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestWebDelegationRoundTrip(t *testing.T) {
	db := openTestDB(t)
	d := WebDelegation{
		Username: "alice", GatewayCN: "backup-web-01",
		DelegationPubKey: "ssh-ed25519 AAAA gw",
		ExpiresAt:        time.Now().Add(time.Hour).Truncate(time.Second),
		CreatedAt:        time.Now().Truncate(time.Second),
	}
	if err := UpsertWebDelegation(db, d); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := GetWebDelegation(db, "alice", "backup-web-01")
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.DelegationPubKey != d.DelegationPubKey || !got.ExpiresAt.Equal(d.ExpiresAt) || got.RevokedAt != nil {
		t.Fatalf("mismatch: %+v", got)
	}
	// Upsert replaces (re-enroll refreshes expiry).
	d.ExpiresAt = d.ExpiresAt.Add(time.Hour)
	if err := UpsertWebDelegation(db, d); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = GetWebDelegation(db, "alice", "backup-web-01")
	if !got.ExpiresAt.Equal(d.ExpiresAt) {
		t.Fatalf("expiry not refreshed: %+v", got)
	}
}

func TestWebDelegationRevokeAndList(t *testing.T) {
	db := openTestDB(t)
	for _, cn := range []string{"gw-a", "gw-b"} {
		if err := UpsertWebDelegation(db, WebDelegation{
			Username: "alice", GatewayCN: cn, DelegationPubKey: "ssh-ed25519 AAAA " + cn,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("upsert %s: %v", cn, err)
		}
	}
	if err := RevokeWebDelegation(db, "alice", "gw-a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ := GetWebDelegation(db, "alice", "gw-a")
	if got == nil || got.RevokedAt == nil {
		t.Fatalf("expected revoked: %+v", got)
	}
	list, err := ListWebDelegations(db, "alice")
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	missing, err := GetWebDelegation(db, "alice", "no-such")
	if err != nil || missing != nil {
		t.Fatalf("missing should be (nil,nil): %v %v", missing, err)
	}
}
