package store

import (
	"path/filepath"
	"testing"
)

func TestOpenDBCreatesMissingParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	if err := MigrateNonces(db); err != nil {
		t.Fatalf("database in created directory is unusable: %v", err)
	}
}
