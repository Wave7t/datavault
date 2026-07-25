package middleware

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// DelegationMeta is stored next to each delegation public key and scopes it
// to one gateway CN with an expiry.
type DelegationMeta struct {
	GatewayCN string `json:"gateway_cn"`
	ExpiresAt int64  `json:"expires_at"`
}

// DelegationFingerprint returns a filename-safe key fingerprint:
// base64url(raw SHA-256 of the marshalled public key), no padding.
func DelegationFingerprint(pubKey ssh.PublicKey) string {
	sum := sha256.Sum256(pubKey.Marshal())
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func delegationDir(keysDir, hostname, username string) string {
	return filepath.Join(keysDir, hostname, username+".delegations")
}

// SaveDelegationKey atomically writes a delegation public key and its meta.
func SaveDelegationKey(keysDir, hostname, username, pubKeyLine string, meta DelegationMeta) error {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyLine))
	if err != nil {
		return fmt.Errorf("parse delegation key: %w", err)
	}
	dir := delegationDir(keysDir, hostname, username)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create delegation dir: %w", err)
	}
	fp := DelegationFingerprint(pubKey)
	metaData, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal delegation meta: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, fp+".pub"), []byte(pubKeyLine), 0600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, fp+".meta"), metaData, 0600); err != nil {
		return err
	}
	return nil
}

// RemoveDelegationKeyFile deletes a delegation key and meta. Missing files
// are not an error (idempotent revocation).
func RemoveDelegationKeyFile(keysDir, hostname, username, fingerprint string) error {
	dir := delegationDir(keysDir, hostname, username)
	for _, ext := range []string{".pub", ".meta"} {
		if err := os.Remove(filepath.Join(dir, fingerprint+ext)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove delegation %s: %w", ext, err)
		}
	}
	return nil
}

// LoadDelegationKeys returns the unexpired delegation keys for host/user.
func LoadDelegationKeys(keysDir, hostname, username string, now time.Time) ([]ssh.PublicKey, error) {
	dir := delegationDir(keysDir, hostname, username)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read delegation dir: %w", err)
	}
	var keys []ssh.PublicKey
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".meta" {
			continue
		}
		metaData, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var meta DelegationMeta
		if err := json.Unmarshal(metaData, &meta); err != nil || meta.ExpiresAt <= now.Unix() {
			continue
		}
		pubData, err := os.ReadFile(filepath.Join(dir, e.Name()[:len(e.Name())-len(".meta")]+".pub"))
		if err != nil {
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
		if err != nil {
			continue
		}
		keys = append(keys, pubKey)
	}
	return keys, nil
}

// LoadSigningKeys returns the primary authorized key followed by all
// unexpired delegation keys. An unreadable primary key is an error.
func LoadSigningKeys(keysDir, hostname, username string, now time.Time) ([]ssh.PublicKey, error) {
	primary, err := LoadAuthorizedKey(keysDir, hostname, username)
	if err != nil {
		return nil, err
	}
	delegations, err := LoadDelegationKeys(keysDir, hostname, username, now)
	if err != nil {
		return nil, err
	}
	return append([]ssh.PublicKey{primary}, delegations...), nil
}

// VerifyAnyKey reports whether sig verifies payload under any of keys.
func VerifyAnyKey(keys []ssh.PublicKey, payload []byte, sig *ssh.Signature) bool {
	for _, k := range keys {
		if k.Verify(payload, sig) == nil {
			return true
		}
	}
	return false
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}
