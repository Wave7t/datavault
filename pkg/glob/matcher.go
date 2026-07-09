package glob

import (
	"path/filepath"
	"strings"
)

// Matcher filters file paths against exclude patterns.
// Patterns use standard glob syntax matching against relative paths.
type Matcher struct {
	patterns []string
}

// Compile validates and creates a Matcher from the given glob patterns.
// Returns an error if any pattern is invalid (e.g., empty string).
func Compile(patterns []string) (*Matcher, error) {
	for _, p := range patterns {
		if p == "" {
			return nil, filepath.ErrBadPattern
		}
		if _, err := filepath.Match(p, ""); err != nil {
			return nil, err
		}
	}
	return &Matcher{patterns: patterns}, nil
}

// Match returns true if the relative path matches any exclude pattern.
//
// Matching rules:
//   - Direct match via filepath.Match is tried first.
//   - Patterns starting with "**/" (globstar) match at any depth: the
//     remainder is matched against every suffix of the path, and also
//     against individual path components when the remainder contains
//     no separator.
//   - Patterns without a path separator are matched against each
//     path component in isolation (e.g. "*.tmp" matches "a/b/foo.tmp"
//     because the component "foo.tmp" matches).
func (m *Matcher) Match(relativePath string) bool {
	for _, p := range m.patterns {
		if matchPattern(p, relativePath) {
			return true
		}
	}
	return false
}

func matchPattern(pattern, relativePath string) bool {
	// Direct match first.
	if ok, _ := filepath.Match(pattern, relativePath); ok {
		return true
	}

	sep := string(filepath.Separator)

	// Handle **/ prefix (globstar): match remainder at any depth.
	if rest, ok := strings.CutPrefix(pattern, "**"+sep); ok {
		parts := strings.Split(relativePath, sep)
		// Try remainder against every suffix of the path.
		for i := 0; i < len(parts); i++ {
			suffix := strings.Join(parts[i:], sep)
			if ok, _ := filepath.Match(rest, suffix); ok {
				return true
			}
		}
		// If remainder has no separator, also try matching against
		// individual components (handles "**/node_modules" against
		// "a/node_modules/package.json").
		if !strings.Contains(rest, sep) {
			for _, component := range parts {
				if ok, _ := filepath.Match(rest, component); ok {
					return true
				}
			}
		}
		return false
	}

	// Patterns without a separator match against individual path components.
	if !strings.Contains(pattern, sep) {
		for _, component := range strings.Split(relativePath, sep) {
			if ok, _ := filepath.Match(pattern, component); ok {
				return true
			}
		}
	}

	return false
}
