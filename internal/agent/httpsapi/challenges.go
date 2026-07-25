package httpsapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
)

const taskGrantTTL = 6 * time.Hour

var errNoDelegation = errors.New("no delegation")

// ephemeralKeys holds task private keys between challenge issuance and the
// signed request that consumes them. Entries are single-use and expire with
// their server challenge nonce. grantExpiresAt is fixed at challenge time so
// the payload the gateway signs and the payload the Agent re-verifies (and
// forwards to the Server) carry byte-identical expiry.
type ephemeralKeys struct {
	mu      sync.Mutex
	entries map[string]ephemeralEntry
}

type ephemeralEntry struct {
	signer         ssh.Signer
	expiresAt      time.Time // server nonce expiry (challenge TTL)
	grantExpiresAt time.Time // signed into the TaskGrantPayload
}

func newEphemeralKeys() *ephemeralKeys {
	return &ephemeralKeys{entries: make(map[string]ephemeralEntry)}
}

func (ek *ephemeralKeys) put(nonce []byte, signer ssh.Signer, nonceExpiry, grantExpiry time.Time) {
	ek.mu.Lock()
	defer ek.mu.Unlock()
	ek.entries[hex.EncodeToString(nonce)] = ephemeralEntry{
		signer: signer, expiresAt: nonceExpiry, grantExpiresAt: grantExpiry,
	}
}

// take removes and returns the entry for nonce, or nil if absent/expired.
func (ek *ephemeralKeys) take(nonce []byte) *ephemeralEntry {
	ek.mu.Lock()
	defer ek.mu.Unlock()
	key := hex.EncodeToString(nonce)
	e, ok := ek.entries[key]
	if !ok {
		return nil
	}
	delete(ek.entries, key)
	if time.Now().After(e.expiresAt) {
		return nil
	}
	return &e
}

type challengeRequest struct {
	Method     string `json:"method"`
	Rule       string `json:"rule,omitempty"`
	TargetPath string `json:"target_path,omitempty"`
	Server     string `json:"server,omitempty"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	var body challengeRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if !s.userLimiter.allow(id.Username) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many challenges")
		return
	}
	if s.deps.GetAuthChallengeFn == nil {
		writeError(w, http.StatusNotImplemented, "unimplemented", "challenge provider not configured")
		return
	}
	ch, err := s.deps.GetAuthChallengeFn()
	if err != nil {
		writeInternal(w, s.log(), "get auth challenge", err)
		return
	}
	server := body.Server
	if server == "" {
		server = ch.Server
	}

	var payload []byte
	switch body.Method {
	case "quota":
		payload, err = auth.ServerRequestPayload("GetQuotaUsage", ch.Nonce,
			&backuppbv1.GetQuotaUsageRequest{Username: id.Username})
	case "restore":
		payload, err = auth.ServerRequestPayload("PullRestore", ch.Nonce,
			&backuppbv1.PullRestoreRequest{Username: id.Username})
	case "sync":
		payload, err = s.syncChallengePayload(id, ch.Nonce, time.Unix(ch.ExpiresAt, 0))
	case "revoke_delegation":
		payload, err = s.revokeChallengePayload(id, ch.Nonce)
	default:
		writeError(w, http.StatusBadRequest, "invalid_method", "method must be one of sync, quota, restore, revoke_delegation")
		return
	}
	if err != nil {
		writeInternal(w, s.log(), "build challenge payload", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce":      base64.StdEncoding.EncodeToString(ch.Nonce),
		"payload":    base64.StdEncoding.EncodeToString(payload),
		"expires_at": ch.ExpiresAt,
		"server":     server,
	})
}

func (s *Server) syncChallengePayload(id identity, nonce []byte, nonceExpiresAt time.Time) ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	grantExpiry := time.Now().Add(taskGrantTTL)
	s.ephemeral.put(nonce, signer, nonceExpiresAt, grantExpiry)
	pubLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	return auth.TaskGrantPayload(nonce, id.Username, "PushBackup", pubLine, grantExpiry.Unix()), nil
}

func (s *Server) revokeChallengePayload(id identity, nonce []byte) ([]byte, error) {
	d, err := store.GetWebDelegation(s.deps.DB, id.Username, id.GatewayCN)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, errNoDelegation
	}
	return auth.DelegationRemovalPayload(nonce, id.Username, id.GatewayCN, d.DelegationPubKey), nil
}
