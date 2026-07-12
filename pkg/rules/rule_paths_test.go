package rules

import "testing"

func TestValidateUserPaths(t *testing.T) {
	for _, paths := range [][]string{
		{"/home/alice"},
		{"/home/alice/docs", "/home/alice/projects/app"},
	} {
		if err := ValidateUserPaths(paths, "/home/alice"); err != nil {
			t.Fatalf("ValidateUserPaths(%v): %v", paths, err)
		}
	}

	for _, path := range []string{"relative", "/home/alice-archive/file", "/etc/shadow", "/home/alice/../../etc/passwd"} {
		if err := ValidateUserPaths([]string{path}, "/home/alice"); err == nil {
			t.Fatalf("ValidateUserPaths(%q) unexpectedly succeeded", path)
		}
	}
}
