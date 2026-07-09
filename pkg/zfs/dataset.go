package zfs

import (
	"fmt"
	"regexp"
)

var (
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?$`)
	usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	datasetRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:\/-]*$`)
)

// ValidateHostname checks that the given name matches hostname naming rules:
// alphanumeric, hyphens allowed internally, 1-63 characters.
func ValidateHostname(name string) error {
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("invalid hostname: %q", name)
	}
	return nil
}

// ValidateUsername checks that the given name matches username naming rules:
// lowercase letters, digits, underscores, hyphens; starts with letter or underscore; max 31 chars.
func ValidateUsername(name string) error {
	if !usernameRe.MatchString(name) {
		return fmt.Errorf("invalid username: %q", name)
	}
	return nil
}

// ValidateDatasetName checks that the given name matches ZFS dataset naming rules:
// alphanumeric with allowed special characters (._:/-).
func ValidateDatasetName(name string) error {
	if !datasetRe.MatchString(name) {
		return fmt.Errorf("invalid dataset name: %q", name)
	}
	return nil
}

// DatasetPath returns the full dataset path for a given pool, hostname, and username.
// Format: pool/hostname/username
func DatasetPath(pool, hostname, username string) string {
	return fmt.Sprintf("%s/%s/%s", pool, hostname, username)
}
