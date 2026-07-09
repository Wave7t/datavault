package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/datavault/pkg/glob"
)

func TestScanSimpleDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world"), 0644)

	result, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(result.Files))
	}
}

func TestScanWithExcludes(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "a.tmp"), []byte("temp"), 0644)

	m, _ := glob.Compile([]string{"*.tmp"})
	result, _ := Scan(dir, m)
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file after exclude, got %d", len(result.Files))
	}
}

func TestScanExcludeDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("js"), 0644)
	os.MkdirAll(filepath.Join(dir, "src"), 0755)
	os.WriteFile(filepath.Join(dir, "src", "main.go"), []byte("go"), 0644)

	m, _ := glob.Compile([]string{"node_modules"})
	result, _ := Scan(dir, m)

	// Only src/main.go should be included
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(result.Files))
	}
}

func TestScanSHA256Computed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("test content"), 0644)

	result, _ := Scan(dir, nil)
	if len(result.Files) != 1 {
		t.Fatal("expected 1 file")
	}
	if result.Files[0].SHA256 == nil {
		t.Fatal("expected SHA256 to be computed")
	}
}
