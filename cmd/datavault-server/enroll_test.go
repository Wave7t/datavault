package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/datavault/internal/server/enrollment"
	"golang.org/x/crypto/ssh"
)

func TestRunKeyEnrollUsesLocalSocketWithoutSudo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyData := ssh.MarshalAuthorizedKey(sshKey)

	requests := make(chan enrollment.LocalRequest, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request enrollment.LocalRequest
		if err := json.NewDecoder(conn).Decode(&request); err == nil {
			requests <- request
			json.NewEncoder(conn).Encode(enrollment.LocalResponse{Fingerprint: "SHA256:test"})
		}
	}()

	var output bytes.Buffer
	if err := runKeyEnroll([]string{"--socket", path, "--agent", "relay-01"}, bytes.NewReader(keyData), &output); err != nil {
		t.Fatalf("runKeyEnroll: %v", err)
	}
	request := <-requests
	if request.AgentCN != "relay-01" || request.PublicKey != string(keyData) {
		t.Fatalf("unexpected request: %#v", request)
	}
	if !strings.Contains(output.String(), "SHA256:test") {
		t.Fatalf("missing fingerprint in output: %q", output.String())
	}
}
