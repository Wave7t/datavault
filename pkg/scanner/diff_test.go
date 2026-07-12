package scanner

import (
	"database/sql"
	"testing"

	"github.com/example/datavault/pkg/store"
)

// testStoreDB opens an in-memory SQLite database for testing diff operations.
func testStoreDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func TestDiffNewFile(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	scanned := []FileInfo{
		{Path: "new.txt", Size: 100, Mtime: 1000, SHA256: []byte("abc")},
	}

	diffs, errs := ComputeDiff(scanned, db, "srv", "alice")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(diffs) != 1 || diffs[0].Action != DiffAdd {
		t.Fatalf("expected 1 DiffAdd, got %d diffs", len(diffs))
	}
}

func TestDiffUnchanged(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "same.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("abc"),
	})

	scanned := []FileInfo{
		{Path: "same.txt", Size: 100, Mtime: 1000, SHA256: []byte("abc")},
	}

	diffs, _ := ComputeDiff(scanned, db, "srv", "alice")
	if len(diffs) != 0 {
		t.Fatalf("expected 0 diffs for unchanged file, got %d", len(diffs))
	}
}

func TestDiffModified(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "changed.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("oldhash"),
	})

	scanned := []FileInfo{
		{Path: "changed.txt", Size: 200, Mtime: 2000, SHA256: []byte("newhash")},
	}

	diffs, _ := ComputeDiff(scanned, db, "srv", "alice")
	if len(diffs) != 1 || diffs[0].Action != DiffModify {
		t.Fatalf("expected 1 DiffModify, got %d diffs", len(diffs))
	}
}

func TestDiffDeleted(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "deleted.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("hash"),
	})

	// Empty scan means file was deleted.
	diffs, _ := ComputeDiff([]FileInfo{}, db, "srv", "alice")
	if len(diffs) != 1 || diffs[0].Action != DiffDelete {
		t.Fatalf("expected 1 DiffDelete, got %d diffs", len(diffs))
	}
}

func TestDiffMixed(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	// Existing snapshots: file_a (unchanged), file_b (deleted), file_c (modified)
	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "file_a.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("hash_a"),
	})
	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "file_b.txt",
		Mtime: 2000, Size: 200, SHA256: []byte("hash_b"),
	})
	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "file_c.txt",
		Mtime: 3000, Size: 300, SHA256: []byte("hash_c_old"),
	})

	// Scanned files: file_a (unchanged), file_c (modified), file_d (new)
	scanned := []FileInfo{
		{Path: "file_a.txt", Size: 100, Mtime: 1000, SHA256: []byte("hash_a")},
		{Path: "file_c.txt", Size: 400, Mtime: 4000, SHA256: []byte("hash_c_new")},
		{Path: "file_d.txt", Size: 500, Mtime: 5000, SHA256: []byte("hash_d")},
	}

	diffs, errs := ComputeDiff(scanned, db, "srv", "alice")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	actionCounts := map[DiffAction]int{}
	for _, d := range diffs {
		actionCounts[d.Action]++
	}

	if actionCounts[DiffAdd] != 1 {
		t.Fatalf("expected 1 DiffAdd, got %d", actionCounts[DiffAdd])
	}
	if actionCounts[DiffModify] != 1 {
		t.Fatalf("expected 1 DiffModify, got %d", actionCounts[DiffModify])
	}
	if actionCounts[DiffDelete] != 1 {
		t.Fatalf("expected 1 DiffDelete, got %d", actionCounts[DiffDelete])
	}
	if actionCounts[DiffSkip] != 0 {
		t.Fatalf("expected 0 DiffSkip, got %d", actionCounts[DiffSkip])
	}
	if len(diffs) != 3 {
		t.Fatalf("expected 3 total diffs, got %d", len(diffs))
	}
}

func TestDiffDetectsModeOrHashChange(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "file.txt",
		Mtime: 1000, Size: 100, Mode: 0644, SHA256: []byte("old"),
	})

	for _, file := range []FileInfo{
		{Path: "file.txt", Mtime: 1000, Size: 100, Mode: 0600, SHA256: []byte("old")},
		{Path: "file.txt", Mtime: 1000, Size: 100, Mode: 0644, SHA256: []byte("new")},
	} {
		diffs, errs := ComputeDiff([]FileInfo{file}, db, "srv", "alice")
		if len(errs) != 0 || len(diffs) != 1 || diffs[0].Action != DiffModify {
			t.Fatalf("file %#v: diffs=%#v errs=%v", file, diffs, errs)
		}
	}
}

func TestDiffUnderRootDoesNotDeleteAnotherRoot(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	for _, path := range []string{"home/alice/docs/report.txt", "home/alice/projects/readme.txt"} {
		if err := store.UpsertSnapshot(db, store.FileSnapshot{ServerID: "srv", Username: "alice", FilePath: path}); err != nil {
			t.Fatal(err)
		}
	}

	diffs, errs := ComputeDiffUnderRoot(nil, db, "srv", "alice", "home/alice/docs")
	if len(errs) != 0 || len(diffs) != 1 || diffs[0].File.Path != "home/alice/docs/report.txt" || diffs[0].Action != DiffDelete {
		t.Fatalf("diffs=%#v errs=%v", diffs, errs)
	}
}
