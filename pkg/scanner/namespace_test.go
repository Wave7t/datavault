package scanner

import "testing"

func TestNamespaceFilesIncludesRootPrefix(t *testing.T) {
	prefix, files, err := NamespaceFiles("/home/alice/docs", []FileInfo{{Path: "report.txt"}, {Path: "nested/todo.txt"}})
	if err != nil {
		t.Fatalf("NamespaceFiles: %v", err)
	}
	if prefix != "home/alice/docs" {
		t.Fatalf("prefix = %q", prefix)
	}
	if files[0].Path != "home/alice/docs/report.txt" || files[1].Path != "home/alice/docs/nested/todo.txt" {
		t.Fatalf("unexpected namespaced files: %#v", files)
	}
}

func TestNamespaceFilesRejectsUnsafeRelativePath(t *testing.T) {
	if _, _, err := NamespaceFiles("/home/alice/docs", []FileInfo{{Path: "../escape"}}); err == nil {
		t.Fatal("expected unsafe relative path to fail")
	}
}
