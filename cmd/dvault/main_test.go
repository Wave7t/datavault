package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDelegationKeyInput(t *testing.T) {
	validKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6YlMf4bXLG1wYbH5CjVxgByHRto2KUg64tQJntaapk comment"
	// Inline line is used as-is.
	got, err := resolveDelegationKeyInput(validKey)
	if err != nil || got != validKey {
		t.Fatalf("inline: %v %v", got, err)
	}
	// @file reads the file, trims whitespace.
	f := filepath.Join(t.TempDir(), "key.pub")
	os.WriteFile(f, []byte(validKey+"\n"), 0600)
	got, err = resolveDelegationKeyInput("@" + f)
	if err != nil || got != validKey {
		t.Fatalf("file: %v %v", got, err)
	}
}
