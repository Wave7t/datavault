package rules

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Rule struct {
	Name     string   `yaml:"name"     json:"name"`
	Paths    []string `yaml:"paths"    json:"paths"`
	Exclude  []string `yaml:"exclude"  json:"exclude,omitempty"`
	Schedule string   `yaml:"schedule" json:"schedule,omitempty"`
	Enabled  bool     `yaml:"enabled"  json:"enabled"`
}

func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("rule %q: at least one path is required", r.Name)
	}
	return nil
}

// ValidateUserPaths ensures an unprivileged user's rules cannot cause the
// root-run agent to read outside that user's home directory. Rules must use
// absolute paths because the daemon's working directory is not the CLI user's
// working directory.
func ValidateUserPaths(paths []string, homeDir string) error {
	cleanHome := filepath.Clean(homeDir)
	if !filepath.IsAbs(cleanHome) {
		return fmt.Errorf("user home must be an absolute path: %q", homeDir)
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("user backup path must be absolute: %q", path)
		}
		cleanPath := filepath.Clean(path)
		if cleanPath != cleanHome && !strings.HasPrefix(cleanPath, cleanHome+string(filepath.Separator)) {
			return fmt.Errorf("user backup path must be inside %s: %q", cleanHome, path)
		}
	}
	return nil
}
