package auth

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"syscall"

	"google.golang.org/grpc/peer"
)

type peercredCtxKey struct{}

type PeerCredAddr struct {
	Addr net.Addr
	UID  uint32
}

func (a PeerCredAddr) Network() string {
	if a.Addr == nil {
		return "unix"
	}
	return a.Addr.Network()
}

func (a PeerCredAddr) String() string {
	if a.Addr == nil {
		return fmt.Sprintf("uid:%d", a.UID)
	}
	return fmt.Sprintf("%s uid:%d", a.Addr.String(), a.UID)
}

type peerCredConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *peerCredConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

type peerCredListener struct {
	net.Listener
}

func NewPeerCredListener(listener net.Listener) net.Listener {
	return &peerCredListener{Listener: listener}
}

func (l *peerCredListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	uid, err := GetPeerUID(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &peerCredConn{
		Conn: conn,
		remoteAddr: PeerCredAddr{
			Addr: conn.RemoteAddr(),
			UID:  uid,
		},
	}, nil
}

func ContextWithPeerUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, peercredCtxKey{}, uid)
}

func GetPeerUIDFromContext(ctx context.Context) (uint32, error) {
	if uid, ok := ctx.Value(peercredCtxKey{}).(uint32); ok {
		return uid, nil
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return 0, fmt.Errorf("peer uid not found")
	}
	addr, ok := p.Addr.(PeerCredAddr)
	if !ok {
		return 0, fmt.Errorf("peer uid not found")
	}
	return addr.UID, nil
}

func GetPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket connection")
	}
	f, err := unixConn.File()
	if err != nil {
		return 0, fmt.Errorf("get socket file descriptor: %w", err)
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	return cred.Uid, nil
}

func LookupUsername(uid uint32) (string, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "", fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	return u.Username, nil
}
