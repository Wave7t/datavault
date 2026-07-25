package httpsapi

import (
	"context"
	"net/http"
	"os/user"
	"strconv"
	"time"

	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
)

type ctxKey string

const ctxIdentity ctxKey = "httpsapi-identity"

type identity struct {
	GatewayCN string
	Username  string
	UID       uint32
	HomeDir   string
}

func identityFrom(ctx context.Context) identity {
	id, _ := ctx.Value(ctxIdentity).(identity)
	return id
}

// gate returns middleware enforcing, in order: (2) gateway CN allowlist,
// (3) Unix user resolution, (4) active delegation. Gate 1 (TLS client-cert
// verification) is enforced by the tls.Config in server.go. Failures return
// generic codes and are logged with detail.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api := s.deps.Cfg.HTTPSAPI

		gatewayCN := peerCN(r)
		if !gatewayCNAllowed(api.GatewayCNs, gatewayCN) {
			s.log().Printf("httpsapi: rejected gateway CN %q for %s", gatewayCN, r.URL.Path)
			writeUnauthorized(w)
			return
		}

		username := r.PathValue("user")
		if err := zfs.ValidateUsername(username); err != nil {
			s.log().Printf("httpsapi: invalid username %q from gateway %q", username, gatewayCN)
			writeDelegationRequired(w)
			return
		}
		account, err := user.Lookup(username)
		if err != nil {
			s.log().Printf("httpsapi: unknown user %q from gateway %q", username, gatewayCN)
			writeDelegationRequired(w)
			return
		}
		uid64, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil || uid64 < uint64(api.MinUID) {
			s.log().Printf("httpsapi: system account %q (uid %s) rejected for gateway %q", username, account.Uid, gatewayCN)
			writeDelegationRequired(w)
			return
		}

		d, err := store.GetWebDelegation(s.deps.DB, username, gatewayCN)
		if err != nil {
			writeInternal(w, s.log(), "load delegation", err)
			return
		}
		if d == nil || d.RevokedAt != nil || time.Now().After(d.ExpiresAt) {
			s.log().Printf("httpsapi: no active delegation for %q via gateway %q", username, gatewayCN)
			writeDelegationRequired(w)
			return
		}

		if !s.gatewayLimiter.allow(gatewayCN) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}

		id := identity{GatewayCN: gatewayCN, Username: username, UID: uint32(uid64), HomeDir: account.HomeDir}
		s.log().Printf("httpsapi: gateway=%q user=%q %s %s", gatewayCN, username, r.Method, r.URL.Path)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxIdentity, id)))
	})
}

func peerCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

func gatewayCNAllowed(allowed []string, cn string) bool {
	for _, a := range allowed {
		if a == cn {
			return true
		}
	}
	return false
}
