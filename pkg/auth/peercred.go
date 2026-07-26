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
	Addr net.Addr
	UID  uint32
	PID  int32
	GID  uint32
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

	return &peerCredConn{
		Conn: conn,
		remoteAddr: PeerCredAddr{
			Addr: conn.RemoteAddr(),
			UID:  uid,
			PID:  pid,
			GID:  gid,
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

func PIDFromContext(ctx context.Context) (int32, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return 0, fmt.Errorf("peer pid not found")
	}
	addr, ok := p.Addr.(PeerCredAddr)
	if !ok {
		return 0, fmt.Errorf("peer pid not found")
	}
	return addr.PID, nil
}

type CallerIdentity struct {
	UID      uint32
	PID      int32
	Username string
	Groups   []string
}

// LookupCallerIdentity resolves (uid, pid) → (username, group names).
// Supplementary groups come from /proc/<pid>/status and are resolved to
// names via os/user.LookupGroupId. Failures to resolve individual group
// names are non-fatal (the GID is dropped); failures to read /proc are
// non-fatal too (the identity is returned with empty Groups — min_uid-only
// trust policies still work, group-based policies will deny).
func LookupCallerIdentity(uid uint32, pid int32) (CallerIdentity, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return CallerIdentity{}, fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	ident := CallerIdentity{UID: uid, PID: pid, Username: u.Username}
	gids, err := ReadPeerGroups(pid)
	if err != nil {
		return ident, nil
	}
	for _, gid := range gids {
		if g, err := user.LookupGroupId(fmt.Sprintf("%d", gid)); err == nil {
			ident.Groups = append(ident.Groups, g.Name)
		}
		// silently skip unresolvable GIDs
	}
	return ident, nil
}
