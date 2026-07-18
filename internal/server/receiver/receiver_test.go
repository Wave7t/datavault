package receiver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAndReadAll(t *testing.T) {
	mount := t.TempDir()
	r := New(mount)
	if err := r.WriteFile("host", "alice", "docs/report.txt", []byte("report"), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(filepath.Join(mount, "host", "alice", "docs", "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0640 {
		t.Fatalf("mode = %#o, want 0640", got)
	}

	var paths []string
	if err := r.ReadAll("host", "alice", func(path string, content []byte, mode uint32) error {
		paths = append(paths, path)
		if string(content) != "report" || mode != 0640 {
			t.Fatalf("unexpected restored file: path=%q content=%q mode=%#o", path, content, mode)
		}
		return nil
	}); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(paths) != 1 || paths[0] != "docs/report.txt" {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func TestReceiverRejectsUnsafePaths(t *testing.T) {
	mount := t.TempDir()
	r := New(mount)

	for _, path := range []string{"", ".", "..", "../outside", "/absolute"} {
		if err := r.WriteFile("host", "alice", path, []byte("x"), 0644); err == nil {
			t.Fatalf("WriteFile(%q) unexpectedly succeeded", path)
		}
		if err := r.DeleteFile("host", "alice", path); err == nil {
			t.Fatalf("DeleteFile(%q) unexpectedly succeeded", path)
		}
	}
}

func TestReadAllReportsMissingDataset(t *testing.T) {
	err := New(t.TempDir()).ReadAll("host", "alice", func(string, []byte, uint32) error { return nil })
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadAll error = %v, want not-exist error", err)
	}
}

func TestReadAllFromRequiresAbsoluteMount(t *testing.T) {
	err := New(t.TempDir()).ReadAllFrom("relative", func(string, []byte, uint32) error { return nil })
	if err == nil {
		t.Fatal("expected relative clone mount point to fail")
	}
}

func TestChunkWriterCommitsAtomically(t *testing.T) {
	mount := t.TempDir()
	r := New(mount)
	writer, err := r.NewChunkWriter("host", "alice", "large/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write([]byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write([]byte("beta")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mount, "host", "alice", "large", "data.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete chunk file became visible: %v", err)
	}
	if err := writer.Commit(0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(mount, "host", "alice", "large", "data.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "alphabeta" {
		t.Fatalf("chunked content=%q", data)
	}
}
