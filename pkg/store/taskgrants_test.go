package store

import (
	"testing"
	"time"
)

func TestTaskGrantLifecycle(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := MigrateTaskGrants(db); err != nil {
		t.Fatal(err)
	}
	g := TaskGrant{
		Hostname: "agent-01", Username: "alice", Method: "PushBackup",
		EphemeralFingerprint: "fp1", EphemeralPubKey: "ssh-ed25519 AAAA",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := InsertTaskGrant(db, g); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := GetTaskGrant(db, "agent-01", "alice", "fp1", time.Now())
	if err != nil || got == nil || got.Method != "PushBackup" {
		t.Fatalf("get: %v %v", got, err)
	}
	expired, err := GetTaskGrant(db, "agent-01", "alice", "fp1", time.Now().Add(2*time.Hour))
	if err != nil || expired != nil {
		t.Fatalf("expired must be (nil,nil): %v %v", expired, err)
	}
	missing, err := GetTaskGrant(db, "agent-01", "bob", "fp1", time.Now())
	if err != nil || missing != nil {
		t.Fatalf("wrong user must miss: %v %v", missing, err)
	}
	if err := GCExpiredTaskGrants(db); err != nil {
		t.Fatal(err)
	}
}
