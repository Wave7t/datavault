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
		Mode:     0640,
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
	if got.Mode != 0640 {
		t.Fatalf("mode: expected 0640, got %#o", got.Mode)
	}
}

func TestMigrateSnapshotsAddsModeToExistingDatabase(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE file_snapshots (
			server_id TEXT NOT NULL,
			username TEXT NOT NULL,
			file_path TEXT NOT NULL,
			mtime_ns INTEGER NOT NULL,
			size_bytes INTEGER NOT NULL,
			sha256 BLOB,
			synced_at INTEGER NOT NULL,
			PRIMARY KEY (server_id, username, file_path)
		)`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateSnapshots(db); err != nil {
		t.Fatalf("MigrateSnapshots: %v", err)
	}
	if err := UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "alice", FilePath: "file", Mode: 0600}); err != nil {
		t.Fatalf("UpsertSnapshot after migration: %v", err)
	}
	got, err := GetSnapshot(db, "srv", "alice", "file")
	if err != nil || got == nil || got.Mode != 0600 {
		t.Fatalf("snapshot after migration: %#v, %v", got, err)
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
