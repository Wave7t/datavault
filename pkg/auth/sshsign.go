package auth

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

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
	return signWithSSHAgentSocket(socket, payload)
}

// SignWithSSHAgentForUser signs payload through an SSH agent socket supplied
// by a Unix-socket peer. The socket must be absolute, a Unix-domain socket,
// and owned by that authenticated peer; this keeps the root-run Agent from
// accepting an arbitrary IPC endpoint on behalf of another local user.
func SignWithSSHAgentForUser(socket string, uid uint32, payload []byte) ([]byte, *ssh.Signature, error) {
	if err := ValidateSSHAgentSocketForUser(socket, uid); err != nil {
		return nil, nil, err
	}
	return signWithSSHAgentSocket(socket, payload)
}

// ValidateSSHAgentSocketForUser verifies that socket is an absolute Unix
// socket owned by the authenticated local peer.
func ValidateSSHAgentSocketForUser(socket string, uid uint32) error {
	if !filepath.IsAbs(socket) {
		return fmt.Errorf("SSH agent socket must be an absolute path")
	}
	info, err := os.Stat(socket)
	if err != nil {
		return fmt.Errorf("stat SSH agent socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("SSH agent path is not a Unix socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return fmt.Errorf("SSH agent socket is not owned by authenticated user")
	}
	return nil
}

func signWithSSHAgentSocket(socket string, payload []byte) ([]byte, *ssh.Signature, error) {
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
