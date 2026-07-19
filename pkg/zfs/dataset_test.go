package zfs

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// zfsAvailable returns true if the "zfs" binary is in PATH.
func zfsAvailable() bool {
	_, err := exec.LookPath("zfs")
	return err == nil
}

// --- Validation tests (always run) ---

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"web-01.example.com", true},
		{"db-01", true},
		{"a", true},
		{"A", true},
		{"host123", true},
		{"valid-host.name", true},
		{"", false},
		{"-badstart", false},
		{"badend-", false},
		{"../../../etc", false},
		{"host; rm -rf /", false},
		{"host with spaces", false},
		{"a.b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.name)
			if tt.valid && err != nil {
				t.Errorf("%q should be valid: %v", tt.name, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("%q should be invalid", tt.name)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	valid := []string{"alice", "bob_smith", "user-01", "_daemon", "u"}
	invalid := []string{"", "Alice", "../root", "invalid!", "user name", "-notvalid"}

	for _, name := range valid {
		t.Run("valid_"+name, func(t *testing.T) {
			if err := ValidateUsername(name); err != nil {
				t.Errorf("%q should be valid: %v", name, err)
			}
		})
	}
	for _, name := range invalid {
		t.Run("invalid_"+name, func(t *testing.T) {
			if err := ValidateUsername(name); err == nil {
				t.Errorf("%q should be invalid", name)
			}
		})
	}
}

func TestValidateDatasetName(t *testing.T) {
	valid := []string{
		"tank/backups",
		"tank/backups/web-01/alice",
		"pool0/sub-dataset/data",
		"rpool/ROOT/ubuntu",
	}
	invalid := []string{
		"",
		"bad dataset name",
		"../../../etc/passwd",
		"pool; rm -rf /",
	}

	for _, name := range valid {
		t.Run("valid_"+name, func(t *testing.T) {
			if err := ValidateDatasetName(name); err != nil {
				t.Errorf("%q should be valid: %v", name, err)
			}
		})
	}
	for _, name := range invalid {
		t.Run("invalid_"+name, func(t *testing.T) {
			if err := ValidateDatasetName(name); err == nil {
				t.Errorf("%q should be invalid", name)
			}
		})
	}
}

func TestDatasetPath(t *testing.T) {
	path := DatasetPath("tank/backups", "web-01", "alice")
	if path != "tank/backups/web-01/alice" {
		t.Fatalf("unexpected path: got %q, want %q", path, "tank/backups/web-01/alice")
	}
}

func TestNewInvalidPoolPath(t *testing.T) {
	_, err := New("invalid pool path")
	if err == nil {
		t.Fatal("expected error for invalid pool path")
	}
}

func TestEnsureDatasetMountedMountsMissingAncestors(t *testing.T) {
	mounted := map[string]string{
		"backup_pool":                  "yes",
		"backup_pool/cad52-agent":      "no",
		"backup_pool/cad52-agent/want": "no",
	}
	var calls []string
	z := &ZFS{
		poolPath: "backup_pool",
		runZFS: func(args ...string) (string, error) {
			calls = append(calls, strings.Join(args, " "))
			switch args[0] {
			case "get":
				return mounted[args[len(args)-1]], nil
			case "mount":
				mounted[args[1]] = "yes"
				return "", nil
			default:
				return "", errors.New("unexpected ZFS command")
			}
		},
	}

	if err := z.EnsureDatasetMounted("backup_pool/cad52-agent/want"); err != nil {
		t.Fatalf("EnsureDatasetMounted: %v", err)
	}
	want := []string{
		"get -Hp -o value mounted backup_pool",
		"get -Hp -o value mounted backup_pool/cad52-agent",
		"mount backup_pool/cad52-agent",
		"get -Hp -o value mounted backup_pool/cad52-agent",
		"get -Hp -o value mounted backup_pool/cad52-agent/want",
		"mount backup_pool/cad52-agent/want",
		"get -Hp -o value mounted backup_pool/cad52-agent/want",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("ZFS commands = %#v, want %#v", calls, want)
	}
}

func TestEnsureDatasetMountedRejectsDatasetOutsidePool(t *testing.T) {
	z := &ZFS{poolPath: "backup_pool"}
	if err := z.EnsureDatasetMounted("other_pool/cad52-agent/want"); err == nil {
		t.Fatal("expected dataset outside backup pool to be rejected")
	}
}

func TestEnsureDatasetMountedAllowsBackupPoolItself(t *testing.T) {
	var calls []string
	z := &ZFS{
		poolPath: "backup_pool",
		runZFS: func(args ...string) (string, error) {
			calls = append(calls, strings.Join(args, " "))
			return "yes", nil
		},
	}

	if err := z.EnsureDatasetMounted("backup_pool"); err != nil {
		t.Fatalf("EnsureDatasetMounted: %v", err)
	}
	want := []string{"get -Hp -o value mounted backup_pool"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("ZFS commands = %#v, want %#v", calls, want)
	}
}

// --- ZFS command tests (skip if ZFS unavailable) ---

func TestZFS_New(t *testing.T) {
	if !zfsAvailable() {
		t.Skip("ZFS not available")
	}
	z, err := New("tank/backups")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if z.poolPath != "tank/backups" {
		t.Fatalf("unexpected poolPath: %q", z.poolPath)
	}
}

func TestZFS_DatasetExists_NotFound(t *testing.T) {
	if !zfsAvailable() {
		t.Skip("ZFS not available")
	}
	z, err := New("tank/backups")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exists, err := z.DatasetExists("tank/nonexistent-dataset-99999")
	if err != nil {
		t.Fatalf("DatasetExists: %v", err)
	}
	if exists {
		t.Fatal("expected dataset to not exist")
	}
}
