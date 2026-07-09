package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func generateTestKey(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(b)
}

func TestVerifySSHSignature(t *testing.T) {
	priv, err := ssh.ParseRawPrivateKey(generateTestKey(t))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	payload := []byte("test payload for signing")
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pubBytes := signer.PublicKey().Marshal()
	if err := VerifySSHSignature(pubBytes, payload, sig); err != nil {
		t.Fatalf("verify valid sig: %v", err)
	}
}

func TestVerifySSHSignatureTamperedPayload(t *testing.T) {
	priv, _ := ssh.ParseRawPrivateKey(generateTestKey(t))
	signer, _ := ssh.NewSignerFromKey(priv)

	sig, _ := signer.Sign(rand.Reader, []byte("original"))
	pubBytes := signer.PublicKey().Marshal()

	err := VerifySSHSignature(pubBytes, []byte("tampered"), sig)
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, _ := GenerateNonce()
	n2, _ := GenerateNonce()
	if len(n1) != 32 {
		t.Fatalf("nonce length: expected 32, got %d", len(n1))
	}
	if string(n1) == string(n2) {
		t.Fatal("two nonces should differ")
	}
}
