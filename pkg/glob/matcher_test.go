package glob

import "testing"

func TestMatcherExactMatch(t *testing.T) {
	m, _ := Compile([]string{"*.tmp"})
	if !m.Match("foo.tmp") {
		t.Fatal("expected match")
	}
}

func TestMatcherNoMatch(t *testing.T) {
	m, _ := Compile([]string{"*.tmp"})
	if m.Match("foo.txt") {
		t.Fatal("expected no match")
	}
}

func TestMatcherDeepMatch(t *testing.T) {
	m, _ := Compile([]string{"*.tmp"})
	// *.tmp matches any file named *.tmp at any depth via **/ prefix
	if !m.Match("a/b/c/foo.tmp") {
		t.Fatal("expected deep match via **/ prefix")
	}
}

func TestMatcherDirPattern(t *testing.T) {
	m, _ := Compile([]string{"node_modules"})
	if !m.Match("a/node_modules/package.json") {
		t.Fatal("expected node_modules match at any depth")
	}
}

func TestMatcherDoubleStar(t *testing.T) {
	m, _ := Compile([]string{"**/*.mp4"})
	if !m.Match("videos/ lectures/recording.mp4") {
		t.Fatal("expected **/*.mp4 match")
	}
}

func TestMatcherEmptyPatterns(t *testing.T) {
	m, _ := Compile(nil)
	if m.Match("anything") {
		t.Fatal("empty patterns should never match")
	}
}

func TestCompileEmptyPattern(t *testing.T) {
	_, err := Compile([]string{""})
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
}
