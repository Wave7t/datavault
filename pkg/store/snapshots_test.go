package store

import (
	"database/sql"
	"testing"
)

// testDB opens an in-memory SQLite database for testing.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func TestUpsertAndGetSnapshot(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	s := FileSnapshot{
		ServerID: "backup01:8443",
		Username: "alice",
		FilePath: "docs/report.pdf",
		Mtime:    1690000000000000000,
		Size:     12345,
		SHA256:   []byte("abcdef0123456789"),
	}

	if err := UpsertSnapshot(db, s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := GetSnapshot(db, "backup01:8443", "alice", "docs/report.pdf")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected snapshot, got nil")
	}
	if got.Size != 12345 {
		t.Fatalf("size: expected 12345, got %d", got.Size)
	}
}

func TestGetSnapshotNotFound(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	got, err := GetSnapshot(db, "nobody", "nobody", "nothing")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for not found")
	}
}

func TestDeleteSnapshot(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	UpsertSnapshot(db, FileSnapshot{
		ServerID: "srv", Username: "u", FilePath: "f",
	})
	if err := DeleteSnapshot(db, "srv", "u", "f"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ := GetSnapshot(db, "srv", "u", "f")
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestListUserSnapshots(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "alice", FilePath: "a.txt"})
	UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "alice", FilePath: "b.txt"})
	UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "bob", FilePath: "c.txt"})

	list, err := ListUserSnapshots(db, "srv", "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 snapshots for alice, got %d", len(list))
	}
}
