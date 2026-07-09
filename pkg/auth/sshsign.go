package auth

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SignWithSSHAgent signs payload using the SSH agent from SSH_AUTH_SOCK.
// It returns the marshalled public key, the SSH signature, and any error.
func SignWithSSHAgent(payload []byte) ([]byte, *ssh.Signature, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to ssh-agent: %w", err)
	}
	defer conn.Close()

	ag := agent.NewClient(conn)
	keys, err := ag.List()
	if err != nil {
		return nil, nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no keys in ssh-agent")
	}

	sig, err := ag.Sign(keys[0], payload)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-agent sign: %w", err)
	}
	return keys[0].Marshal(), sig, nil
}

// VerifySSHSignature verifies an SSH signature against a public key.
func VerifySSHSignature(pubKeyBytes, payload []byte, sig *ssh.Signature) error {
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	if err := pubKey.Verify(payload, sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// GenerateNonce produces a cryptographically random nonce.
func GenerateNonce() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return b, nil
}
