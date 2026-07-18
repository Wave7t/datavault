package enrollment

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/pkg/config"
	"golang.org/x/crypto/ssh"
)

func TestEnrollWritesCanonicalKeyForEligibleOSAccount(t *testing.T) {
	publicKey := testED25519PublicKey(t)
	keysDir := t.TempDir()
	cfg := testConfig()

	result, err := Enroll(cfg, OSIdentity{Username: "alice", UID: 1020}, "relay-01", ssh.MarshalAuthorizedKey(publicKey), keysDir)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	keyPath := filepath.Join(keysDir, "relay-01", "alice.pub")
	if result.Path != keyPath {
		t.Fatalf("path: got %q, want %q", result.Path, keyPath)
	}
	if result.Fingerprint != ssh.FingerprintSHA256(publicKey) {
		t.Fatalf("fingerprint: got %q", result.Fingerprint)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("parse stored key: %v", err)
	}
	if string(stored.Marshal()) != string(publicKey.Marshal()) {
		t.Fatal("stored key differs from enrolled key")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("mode: got %o, want 0644", info.Mode().Perm())
	}
}

func TestEnrollAcceptsACommentOnOnePublicKeyLine(t *testing.T) {
	publicKey := testED25519PublicKey(t)
	keyWithComment := []byte(strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(publicKey)), "\n") + " alice@relay")
	keysDir := t.TempDir()

	if _, err := Enroll(testConfig(), OSIdentity{Username: "alice", UID: 1020}, "relay-01", keyWithComment, keysDir); err != nil {
		t.Fatalf("Enroll key with comment: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(keysDir, "relay-01", "alice.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "alice@relay") {
		t.Fatalf("stored key unexpectedly retains caller comment: %q", data)
	}
}

func TestEnrolledKeyVerifiesAUserOperationSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	keysDir := t.TempDir()
	if _, err := Enroll(testConfig(), OSIdentity{Username: "alice", UID: 1020}, "relay-01", ssh.MarshalAuthorizedKey(sshKey), keysDir); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	loaded, err := middleware.LoadAuthorizedKey(keysDir, "relay-01", "alice")
	if err != nil {
		t.Fatalf("LoadAuthorizedKey: %v", err)
	}
	payload := []byte("nonceGetQuotaUsagepayload-hash")
	signature, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(payload, signature); err != nil {
		t.Fatalf("enrolled key did not verify signed user operation: %v", err)
	}
}

func TestEnrollRejectsDisabledPolicyAndForeignAgent(t *testing.T) {
	publicKey := ssh.MarshalAuthorizedKey(testED25519PublicKey(t))
	identity := OSIdentity{Username: "alice", UID: 1020}

	disabled := testConfig()
	disabled.KeyEnrollment.Mode = "admin_only"
	if _, err := Enroll(disabled, identity, "relay-01", publicKey, t.TempDir()); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-policy failure, got %v", err)
	}

	if _, err := Enroll(testConfig(), identity, "other-agent", publicKey, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected foreign-agent failure, got %v", err)
	}
}

func TestEnrollHonorsExplicitUserAllowList(t *testing.T) {
	cfg := testConfig()
	cfg.KeyEnrollment.ServerOSLogin.AllowedUsers = []string{"bob"}

	_, err := Enroll(cfg, OSIdentity{Username: "alice", UID: 1020}, "relay-01", ssh.MarshalAuthorizedKey(testED25519PublicKey(t)), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected allow-list failure, got %v", err)
	}
}

func TestEnrollRejectsMultipleOrWeakKeys(t *testing.T) {
	key := ssh.MarshalAuthorizedKey(testED25519PublicKey(t))
	_, err := Enroll(testConfig(), OSIdentity{Username: "alice", UID: 1020}, "relay-01", append(key, key...), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected multiple-key failure, got %v", err)
	}

	weakKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weakPublicKey, err := ssh.NewPublicKey(&weakKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Enroll(testConfig(), OSIdentity{Username: "alice", UID: 1020}, "relay-01", ssh.MarshalAuthorizedKey(weakPublicKey), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "3072") {
		t.Fatalf("expected weak-RSA failure, got %v", err)
	}
}

func TestValidatePublicKeyRejectsUnsupportedAlgorithms(t *testing.T) {
	if err := validatePublicKey(unsupportedPublicKey{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-key failure, got %v", err)
	}
}

func testConfig() *config.ServerConfig {
	return &config.ServerConfig{
		AllowedHosts: []config.AllowedHost{{CN: "relay-01"}},
		KeyEnrollment: config.KeyEnrollmentPolicy{
			Mode: "server_os_login",
			ServerOSLogin: config.ServerOSLoginKeyPolicy{
				AllowedAgents: []string{"relay-01"},
				MinUID:        1000,
			},
		},
	}
}

func testED25519PublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sshKey
}

type unsupportedPublicKey struct{}

func (unsupportedPublicKey) Type() string { return "ssh-dss" }

func (unsupportedPublicKey) Marshal() []byte { return []byte("unsupported") }

func (unsupportedPublicKey) Verify([]byte, *ssh.Signature) error { return nil }

func (unsupportedPublicKey) CryptoPublicKey() crypto.PublicKey { return "unsupported" }
