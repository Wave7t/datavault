// Package enrollment implements the root-owned write path for self-service
// SSH public-key enrollment. The caller identity is intentionally supplied by
// a trusted OS boundary (a Unix socket peer credential), never by CLI
// arguments.
package enrollment

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/zfs"
	"golang.org/x/crypto/ssh"
)

const MaxPublicKeyBytes = 16 * 1024

// OSIdentity is the authenticated local account supplied by the trusted OS
// invocation boundary.
type OSIdentity struct {
	Username string
	UID      int
}

// Result is safe to show in audit logs and command output. It never includes
// the complete public key.
type Result struct {
	Path        string
	Fingerprint string
}

// Enroll validates a self-enrollment request against the configured trust
// policy and atomically replaces the caller's key for the selected Agent.
func Enroll(cfg *config.ServerConfig, identity OSIdentity, agentCN string, keyData []byte, keysDir string) (*Result, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server configuration is required")
	}
	if err := authorize(cfg.KeyEnrollment, identity, agentCN); err != nil {
		return nil, err
	}
	if err := zfs.ValidateUsername(identity.Username); err != nil {
		return nil, fmt.Errorf("invalid OS username: %w", err)
	}
	if err := zfs.ValidateHostname(agentCN); err != nil {
		return nil, fmt.Errorf("invalid agent CN: %w", err)
	}
	if len(keyData) == 0 || len(keyData) > MaxPublicKeyBytes {
		return nil, fmt.Errorf("public key must contain between 1 and %d bytes", MaxPublicKeyBytes)
	}
	keyLine := strings.TrimSpace(string(keyData))
	if keyLine == "" || strings.ContainsAny(keyLine, "\r\n") {
		return nil, fmt.Errorf("exactly one single-line public key is required")
	}

	// ParseAuthorizedKey returns a trailing comment as rest. The preceding
	// single-line check has already ruled out a second authorized-key record,
	// so accept a normal optional comment while canonicalizing it away below.
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	if err := validatePublicKey(pubKey); err != nil {
		return nil, err
	}

	canonical := ssh.MarshalAuthorizedKey(pubKey)
	dir := filepath.Join(keysDir, agentCN)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create authorized-key directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, "."+identity.Username+".pub-")
	if err != nil {
		return nil, fmt.Errorf("create temporary key file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0644); err != nil {
		temp.Close()
		return nil, fmt.Errorf("set temporary key mode: %w", err)
	}
	if _, err := temp.Write(canonical); err != nil {
		temp.Close()
		return nil, fmt.Errorf("write public key: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return nil, fmt.Errorf("sync public key: %w", err)
	}
	if err := temp.Close(); err != nil {
		return nil, fmt.Errorf("close public key: %w", err)
	}

	path := filepath.Join(dir, identity.Username+".pub")
	if err := os.Rename(tempPath, path); err != nil {
		return nil, fmt.Errorf("install public key: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return nil, fmt.Errorf("sync authorized-key directory: %w", err)
	}

	return &Result{Path: path, Fingerprint: ssh.FingerprintSHA256(pubKey)}, nil
}

func authorize(policy config.KeyEnrollmentPolicy, identity OSIdentity, agentCN string) error {
	if policy.Mode != "server_os_login" {
		return fmt.Errorf("self-enrollment is disabled by key_enrollment.mode=%q", policy.Mode)
	}
	if !contains(policy.ServerOSLogin.AllowedAgents, agentCN) {
		return fmt.Errorf("agent %q is not allowed for self-enrollment", agentCN)
	}
	if identity.UID < 0 {
		return fmt.Errorf("invalid OS UID")
	}
	if len(policy.ServerOSLogin.AllowedUsers) > 0 {
		if !contains(policy.ServerOSLogin.AllowedUsers, identity.Username) {
			return fmt.Errorf("OS account %q is not allowed for self-enrollment", identity.Username)
		}
		return nil
	}
	if identity.UID < policy.ServerOSLogin.MinUID {
		return fmt.Errorf("OS account %q has UID below the self-enrollment minimum", identity.Username)
	}
	return nil
}

func validatePublicKey(pubKey ssh.PublicKey) error {
	if _, ok := pubKey.(*ssh.Certificate); ok {
		return fmt.Errorf("SSH certificates cannot be enrolled as public keys")
	}
	cryptoKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("unsupported SSH public key type %q", pubKey.Type())
	}
	switch key := cryptoKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 3072 {
			return fmt.Errorf("RSA public keys must be at least 3072 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return fmt.Errorf("ECDSA public keys must be at least 256 bits")
		}
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported SSH public key type %q", pubKey.Type())
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
