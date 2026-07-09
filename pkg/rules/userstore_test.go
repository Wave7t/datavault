package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUserRuleStoreAddAndLoad(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)

	if err := s.Add("alice", Rule{Name: "docs", Paths: []string{"/home/alice/docs"}}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	rules, err := s.Load("alice")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if !rules[0].Enabled {
		t.Fatal("new rule should be enabled by default")
	}
}

func TestUserRuleStoreRemove(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)

	s.Add("alice", Rule{Name: "docs", Paths: []string{"/tmp"}})
	s.Add("alice", Rule{Name: "photos", Paths: []string{"/tmp"}})

	if err := s.Remove("alice", "docs"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	rules, _ := s.Load("alice")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after remove, got %d", len(rules))
	}
}

func TestUserRuleStoreDisable(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)
	s.Add("alice", Rule{Name: "docs", Paths: []string{"/tmp"}})

	if err := s.SetEnabled("alice", "docs", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	rules, _ := s.Load("alice")
	if rules[0].Enabled {
		t.Fatal("rule should be disabled")
	}
}

func TestUserRuleStoreLoadNonexistent(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)
	rules, err := s.Load("nobody")
	if err != nil {
		t.Fatalf("Load nonexistent: %v", err)
	}
	if rules != nil {
		t.Fatal("expected nil for nonexistent user")
	}
}

func TestUserRuleStoreFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)
	s.Add("alice", Rule{Name: "test", Paths: []string{"/tmp"}})

	info, err := os.Stat(filepath.Join(dir, "alice.yaml"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %04o", info.Mode().Perm())
	}
}
