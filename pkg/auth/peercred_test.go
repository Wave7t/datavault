//go:build linux

package auth

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/peer"
)

func TestGetPeerUID(t *testing.T) {
	// Create a Unix socket pair
	fds, err := syscallSocketpair()
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer fds[0].Close()
	defer fds[1].Close()

	// Wrap as net.UnixConn
	conn0, err := fdToUnixConn(fds[0])
	if err != nil {
		t.Fatalf("fd to UnixConn: %v", err)
	}
	defer conn0.Close()

	// Get peer UID from conn0's perspective (peer is the other end, which is ourselves)
	uid, err := GetPeerUID(conn0)
	if err != nil {
		t.Fatalf("GetPeerUID: %v", err)
	}

	// The peer should be ourselves
	expectedUID := uint32(os.Getuid())
	if uid != expectedUID {
		t.Fatalf("expected UID %d, got %d", expectedUID, uid)
	}
}

func TestGetPeerUIDNonUnixConn(t *testing.T) {
	// Use a TCP listener to create a non-Unix connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan net.Conn, 1)
	go func() {
		c, _ := net.Dial("tcp", ln.Addr().String())
		done <- c
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	clientConn := <-done
	defer clientConn.Close()

	_, err = GetPeerUID(conn)
	if err == nil {
		t.Fatal("expected error for non-unix connection")
	}
}

func TestNewPeerCredListenerWrapsPeerUID(t *testing.T) {
	path := t.TempDir() + "/agent.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	wrapped := NewPeerCredListener(ln)
	accepted := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			errCh <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()

	var serverConn net.Conn
	select {
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case serverConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accept")
	}
	defer serverConn.Close()

	addr, ok := serverConn.RemoteAddr().(PeerCredAddr)
	if !ok {
		t.Fatalf("expected PeerCredAddr, got %T", serverConn.RemoteAddr())
	}
	expectedUID := uint32(os.Getuid())
	if addr.UID != expectedUID {
		t.Fatalf("expected UID %d, got %d", expectedUID, addr.UID)
	}
}

func TestLookupUsername(t *testing.T) {
	// Lookup current user
	currentUID := uint32(os.Getuid())
	username, err := LookupUsername(currentUID)
	if err != nil {
		t.Fatalf("LookupUsername(%d): %v", currentUID, err)
	}
	if username == "" {
		t.Fatal("expected non-empty username")
	}
}

func TestLookupUsernameInvalidUID(t *testing.T) {
	// Use a very large UID that shouldn't exist
	const invalidUID uint32 = 999999
	_, err := LookupUsername(invalidUID)
	if err == nil {
		t.Fatal("expected error for invalid UID")
	}
}

func TestGetPeerUIDFromContextExplicit(t *testing.T) {
	const uid uint32 = 12345
	ctx := ContextWithPeerUID(context.Background(), uid)

	got, err := GetPeerUIDFromContext(ctx)
	if err != nil {
		t.Fatalf("GetPeerUIDFromContext: %v", err)
	}
	if got != uid {
		t.Fatalf("expected UID %d, got %d", uid, got)
	}
}

func TestGetPeerUIDFromContextPeerAddr(t *testing.T) {
	const uid uint32 = 54321
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: PeerCredAddr{Addr: dummyAddr("agent.sock"), UID: uid},
	})

	got, err := GetPeerUIDFromContext(ctx)
	if err != nil {
		t.Fatalf("GetPeerUIDFromContext: %v", err)
	}
	if got != uid {
		t.Fatalf("expected UID %d, got %d", uid, got)
	}
}

func TestGetPeerUIDFromContextMissing(t *testing.T) {
	_, err := GetPeerUIDFromContext(context.Background())
	if err == nil {
		t.Fatal("expected missing peer UID error")
	}
}

type dummyAddr string

func (a dummyAddr) Network() string { return "unix" }
func (a dummyAddr) String() string  { return string(a) }
