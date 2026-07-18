package enrollment

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLocalServerEnrollsResolvedPeerIdentity(t *testing.T) {
	keysDir := t.TempDir()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	server := &LocalServer{
		Config:  testConfig(),
		KeysDir: keysDir,
		ResolveIdentity: func(net.Conn) (OSIdentity, error) {
			return OSIdentity{Username: "alice", UID: 1020}, nil
		},
	}
	go server.Handle(serverConn)

	request := LocalRequest{
		AgentCN:   "relay-01",
		PublicKey: string(ssh.MarshalAuthorizedKey(testED25519PublicKey(t))),
	}
	if err := json.NewEncoder(clientConn).Encode(request); err != nil {
		t.Fatalf("send request: %v", err)
	}
	var response LocalResponse
	if err := json.NewDecoder(clientConn).Decode(&response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.Error != "" || response.Fingerprint == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if _, err := os.Stat(filepath.Join(keysDir, "relay-01", "alice.pub")); err != nil {
		t.Fatalf("enrolled key missing: %v", err)
	}
}

func TestLocalServerRejectsUntrustedPeerIdentity(t *testing.T) {
	keysDir := t.TempDir()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	server := &LocalServer{
		Config:  testConfig(),
		KeysDir: keysDir,
		ResolveIdentity: func(net.Conn) (OSIdentity, error) {
			return OSIdentity{Username: "service", UID: 999}, nil
		},
	}
	go server.Handle(serverConn)

	request := LocalRequest{
		AgentCN:   "relay-01",
		PublicKey: string(ssh.MarshalAuthorizedKey(testED25519PublicKey(t))),
	}
	if err := json.NewEncoder(clientConn).Encode(request); err != nil {
		t.Fatalf("send request: %v", err)
	}
	var response LocalResponse
	if err := json.NewDecoder(clientConn).Decode(&response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(response.Error, "UID below") {
		t.Fatalf("expected policy rejection, got %#v", response)
	}
	if _, err := os.Stat(filepath.Join(keysDir, "relay-01", "service.pub")); !os.IsNotExist(err) {
		t.Fatalf("unexpected key write: %v", err)
	}
}

func TestListenLocalRefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLocal(path); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("expected regular-path refusal, got %v", err)
	}
}

func TestParseGetentPasswd(t *testing.T) {
	username, err := parseGetentPasswd([]byte("alice:x:1020:1020:Alice User:/home/alice:/bin/sh\n"), 1020)
	if err != nil {
		t.Fatalf("parseGetentPasswd: %v", err)
	}
	if username != "alice" {
		t.Fatalf("username: got %q", username)
	}

	for _, record := range [][]byte{
		[]byte(""),
		[]byte("alice:x:1000:1000:Alice User:/home/alice:/bin/sh\n"),
		[]byte("not-a-passwd-record\n"),
		[]byte("alice:x:1020:1020:Alice:/home/alice:/bin/sh\nother:x:1020:1020:Other:/home/other:/bin/sh\n"),
	} {
		if _, err := parseGetentPasswd(record, 1020); err == nil {
			t.Fatalf("expected malformed or mismatched record to fail: %q", record)
		}
	}
}
