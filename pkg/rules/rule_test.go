package rules

import "testing"

func TestRuleValidateEmptyName(t *testing.T) {
	r := Rule{Name: "", Paths: []string{"/tmp"}}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestRuleValidateNoPaths(t *testing.T) {
	r := Rule{Name: "test"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for no paths")
	}
}

func TestRuleValidateOK(t *testing.T) {
	r := Rule{Name: "ok", Paths: []string{"/tmp"}}
	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
