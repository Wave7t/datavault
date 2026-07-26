package auth

import (
	"context"
	"fmt"
	"net"
	"os/user"

	"google.golang.org/grpc/peer"
)

type peercredCtxKey struct{}

type PeerCredAddr struct {
	Addr   net.Addr
	UID    uint32
	PID    int32
	GID    uint32
	Groups []uint32 // supplementary GIDs, captured at Accept time
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

	pid, uid, gid, err := GetPeerCred(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read supplementary groups once at accept time to avoid PID reuse.
	// On error, leave groups empty — min_uid-only trust policies still work.
	groups, _ := ReadPeerGroups(pid)
	return &peerCredConn{
		Conn: conn,
		remoteAddr: PeerCredAddr{
			Addr:   conn.RemoteAddr(),
			UID:    uid,
			PID:    pid,
			GID:    gid,
			Groups: groups,
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

func LookupUsername(uid uint32) (string, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "", fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	return u.Username, nil
}

type CallerIdentity struct {
	UID      uint32
	Username string
	Groups   []string
}

// LookupCallerIdentity resolves uid → username and groups → group names.
// The supplementary GIDs MUST be captured at peerCredListener.Accept time
// (see PeerCredAddr.Groups) to avoid PID-reuse races; this function does
// not read /proc. Unresolvable GIDs are silently dropped.
func LookupCallerIdentity(uid uint32, groups []uint32) (CallerIdentity, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return CallerIdentity{}, fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	ident := CallerIdentity{UID: uid, Username: u.Username}
	for _, gid := range groups {
		if g, err := user.LookupGroupId(fmt.Sprintf("%d", gid)); err == nil {
			ident.Groups = append(ident.Groups, g.Name)
		}
		// silently skip unresolvable GIDs
	}
	return ident, nil
}

// GroupsFromContext returns the supplementary GIDs captured at Accept time
// for the incoming peer, if any.
func GroupsFromContext(ctx context.Context) ([]uint32, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil, fmt.Errorf("peer groups not found")
	}
	addr, ok := p.Addr.(PeerCredAddr)
	if !ok {
		return nil, fmt.Errorf("peer groups not found")
	}
	return addr.Groups, nil
}
