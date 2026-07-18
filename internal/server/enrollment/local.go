package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/config"
)

// DefaultSocketPath is the local control socket served by datavault-server.
// The socket grants no filesystem access: the daemon obtains the caller's
// Linux SO_PEERCRED identity and applies KeyEnrollment before writing a key.
const DefaultSocketPath = "/var/run/datavault-key-enroll.sock"

const localRequestLimit = MaxPublicKeyBytes*2 + 1024

// LocalRequest is sent by the unprivileged key-enroll client over the local
// control socket. It intentionally has no username or UID field.
type LocalRequest struct {
	AgentCN   string `json:"agent_cn"`
	PublicKey string `json:"public_key"`
}

// LocalResponse is returned by the local control socket. It never includes
// key material or a filesystem path.
type LocalResponse struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	Error       string `json:"error,omitempty"`
}

// IdentityResolver obtains the local identity from an already accepted
// connection. Production uses peerIdentity; tests inject a resolver without
// relying on a platform-specific Unix socket implementation.
type IdentityResolver func(net.Conn) (OSIdentity, error)

// LocalServer serves self-enrollment requests for the root-running Server
// daemon.
type LocalServer struct {
	Config          *config.ServerConfig
	KeysDir         string
	ResolveIdentity IdentityResolver
	Logger          *log.Logger
}

// ListenLocal creates the root-owned enrollment socket. It refuses to replace
// a non-socket path, which prevents a startup cleanup from removing unrelated
// files. Socket mode 0666 is safe because every request is authorized from
// Linux SO_PEERCRED, not from its caller-supplied JSON body.
func ListenLocal(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("local enrollment socket path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create local enrollment socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refuse to replace non-socket local enrollment path %q", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale local enrollment socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect local enrollment socket: %w", err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on local enrollment socket: %w", err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, fmt.Errorf("set local enrollment socket mode: %w", err)
	}
	return auth.NewPeerCredListener(listener), nil
}

// Serve accepts local enrollment requests until listener is closed.
func (s *LocalServer) Serve(listener net.Listener) error {
	if s == nil || s.Config == nil {
		return fmt.Errorf("local enrollment server configuration is required")
	}
	if s.KeysDir == "" {
		return fmt.Errorf("local enrollment key directory is required")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if s.Logger != nil {
				s.Logger.Printf("local key enrollment accept: %v", err)
			}
			continue
		}
		go s.Handle(conn)
	}
}

// Handle processes one local enrollment connection.
func (s *LocalServer) Handle(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}

	resolve := s.ResolveIdentity
	if resolve == nil {
		resolve = peerIdentity
	}
	identity, err := resolve(conn)
	if err != nil {
		s.writeResponse(conn, LocalResponse{Error: "cannot determine local OS identity"})
		s.logf("local key enrollment identity: %v", err)
		return
	}

	var request LocalRequest
	decoder := json.NewDecoder(io.LimitReader(conn, localRequestLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.writeResponse(conn, LocalResponse{Error: "invalid enrollment request"})
		s.logf("local key enrollment request for %q: %v", identity.Username, err)
		return
	}

	result, err := Enroll(s.Config, identity, request.AgentCN, []byte(request.PublicKey), s.KeysDir)
	if err != nil {
		s.writeResponse(conn, LocalResponse{Error: err.Error()})
		s.logf("local key enrollment denied for os_user=%q uid=%d agent=%q: %v", identity.Username, identity.UID, request.AgentCN, err)
		return
	}

	s.writeResponse(conn, LocalResponse{Fingerprint: result.Fingerprint})
	s.logf("local key enrollment: os_user=%q uid=%d agent=%q fingerprint=%s", identity.Username, identity.UID, request.AgentCN, result.Fingerprint)
}

func peerIdentity(conn net.Conn) (OSIdentity, error) {
	address, ok := conn.RemoteAddr().(auth.PeerCredAddr)
	if !ok {
		return OSIdentity{}, fmt.Errorf("connection does not have peer credentials")
	}
	username, err := lookupUsernameWithGetent(address.UID)
	if err != nil {
		return OSIdentity{}, err
	}
	return OSIdentity{Username: username, UID: int(address.UID)}, nil
}

// lookupUsernameWithGetent delegates NSS resolution to the target operating
// system. A statically linked Server must not call os/user.LookupId here:
// glibc's cgo NSS lookup can require dynamic NSS modules (and has crashed on
// older distributions). getent retains local, LDAP, and other NSS backends
// without loading those modules into the Server process.
func lookupUsernameWithGetent(uid uint32) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/getent", "passwd", strconv.FormatUint(uint64(uid), 10)).Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("getent passwd lookup timed out for uid %d", uid)
		}
		return "", fmt.Errorf("getent passwd lookup for uid %d: %w", uid, err)
	}
	return parseGetentPasswd(output, uid)
}

func parseGetentPasswd(output []byte, wantedUID uint32) (string, error) {
	record := strings.TrimSpace(string(output))
	if record == "" || strings.Contains(record, "\n") {
		return "", fmt.Errorf("getent passwd returned no unique record for uid %d", wantedUID)
	}
	fields := strings.Split(record, ":")
	if len(fields) < 7 || fields[0] == "" {
		return "", fmt.Errorf("getent passwd returned malformed record for uid %d", wantedUID)
	}
	uid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil || uint32(uid) != wantedUID {
		return "", fmt.Errorf("getent passwd returned mismatched UID for uid %d", wantedUID)
	}
	return fields[0], nil
}

func (s *LocalServer) writeResponse(conn net.Conn, response LocalResponse) {
	if err := json.NewEncoder(conn).Encode(response); err != nil {
		s.logf("write local key enrollment response: %v", err)
	}
}

func (s *LocalServer) logf(format string, args ...interface{}) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}
