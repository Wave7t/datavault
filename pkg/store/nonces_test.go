package store

import (
	"testing"
	"time"
)

func TestConsumeValidNonce(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	if err := InsertNonce(db, "nonce-abc", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	ok, err := ConsumeNonce(db, "nonce-abc")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if !ok {
		t.Fatal("expected nonce to be valid")
	}

	// Second consume should fail (already used)
	ok, err = ConsumeNonce(db, "nonce-abc")
	if err != nil {
		t.Fatalf("second consume: %v", err)
	}
	if ok {
		t.Fatal("expected nonce to be already used")
	}
}

func TestConsumeExpiredNonce(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	if err := InsertNonce(db, "expired", time.Now().Add(-1*time.Minute)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	ok, err := ConsumeNonce(db, "expired")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ok {
		t.Fatal("expected expired nonce to fail")
	}
}

func TestConsumeNonexistentNonce(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	ok, err := ConsumeNonce(db, "nonexistent")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ok {
		t.Fatal("expected nonexistent nonce to fail")
	}
}

func TestGCNonces(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	InsertNonce(db, "old", time.Now().Add(-1*time.Hour))
	InsertNonce(db, "new", time.Now().Add(5*time.Minute))

	if err := GCExpiredNonces(db); err != nil {
		t.Fatalf("gc: %v", err)
	}

	ok, _ := ConsumeNonce(db, "new")
	if !ok {
		t.Fatal("new nonce should survive GC")
	}
	ok, _ = ConsumeNonce(db, "old")
	if ok {
		t.Fatal("old nonce should be removed by GC")
	}
}
