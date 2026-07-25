package middleware

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func writePrimaryKey(t *testing.T, keysDir, host, user string) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(keysDir, host)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, user+".pub"), ssh.MarshalAuthorizedKey(sshPub), 0600); err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func TestDelegationKeySaveLoadExpiry(t *testing.T) {
	keysDir := t.TempDir()
	primary := writePrimaryKey(t, keysDir, "agent-01", "alice")
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())

	line := string(ssh.MarshalAuthorizedKey(delPub))
	meta := DelegationMeta{GatewayCN: "backup-web-01", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := SaveDelegationKey(keysDir, "agent-01", "alice", line, meta); err != nil {
		t.Fatalf("save: %v", err)
	}

	now := time.Now()
	keys, err := LoadSigningKeys(keysDir, "agent-01", "alice", now)
	if err != nil || len(keys) != 2 {
		t.Fatalf("want primary+delegation: %v %v", len(keys), err)
	}
	if string(keys[0].Marshal()) != string(primary.Marshal()) {
		t.Fatal("primary must come first")
	}

	// After expiry only the primary remains.
	keys, err = LoadSigningKeys(keysDir, "agent-01", "alice", now.Add(2*time.Hour))
	if err != nil || len(keys) != 1 {
		t.Fatalf("expired delegation must be excluded: %v %v", len(keys), err)
	}

	fp := DelegationFingerprint(delPub)
	if err := RemoveDelegationKeyFile(keysDir, "agent-01", "alice", fp); err != nil {
		t.Fatalf("remove: %v", err)
	}
	keys, _ = LoadSigningKeys(keysDir, "agent-01", "alice", now)
	if len(keys) != 1 {
		t.Fatalf("removed delegation must be excluded: %v", len(keys))
	}
}

func TestVerifyAnyKey(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	k1, _ := ssh.NewPublicKey(pub1)
	k2, _ := ssh.NewPublicKey(pub2)
	signer, _ := ssh.NewSignerFromKey(priv1)
	payload := []byte("hello")
	sig, _ := signer.Sign(rand.Reader, payload)
	if !VerifyAnyKey([]ssh.PublicKey{k2, k1}, payload, sig) {
		t.Fatal("should verify with second key")
	}
	if VerifyAnyKey([]ssh.PublicKey{k2}, payload, sig) {
		t.Fatal("must not verify with wrong key")
	}
}
