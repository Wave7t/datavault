package httpsapi

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
)

// signedRequest carries the gateway's delegation-key signature over a
// previously issued challenge payload.
type signedRequest struct {
	nonce     []byte
	signature []byte
	payload   []byte
}

// extractSigned rebuilds the payload for the method and verifies the
// gateway's delegation signature against the locally recorded key. The
// Server re-verifies independently; this local check exists to reject
// forgeries without an upstream round trip.
func (s *Server) extractSigned(w http.ResponseWriter, r *http.Request, id identity, method string, buildPayload func(nonce []byte) ([]byte, error)) (*signedRequest, bool) {
	nonceB64 := r.Header.Get("X-Datavault-Nonce")
	sigB64 := r.Header.Get("X-Datavault-Signature")
	nonce, err1 := base64.StdEncoding.DecodeString(nonceB64)
	sigBytes, err2 := base64.StdEncoding.DecodeString(sigB64)
	if err1 != nil || err2 != nil || len(nonce) == 0 || len(sigBytes) == 0 {
		s.log().Printf("httpsapi: malformed signature headers from gateway %q", id.GatewayCN)
		writeDelegationRequired(w)
		return nil, false
	}
	payload, err := buildPayload(nonce)
	if err != nil {
		if err == errNoDelegation {
			writeDelegationRequired(w)
		} else {
			writeInternal(w, s.log(), "rebuild payload", err)
		}
		return nil, false
	}
	d, err := store.GetWebDelegation(s.deps.DB, id.Username, id.GatewayCN)
	if err != nil {
		writeInternal(w, s.log(), "load delegation", err)
		return nil, false
	}
	if d == nil || d.RevokedAt != nil || time.Now().After(d.ExpiresAt) {
		writeDelegationRequired(w)
		return nil, false
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.DelegationPubKey))
	if err != nil {
		writeInternal(w, s.log(), "parse delegation key", err)
		return nil, false
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		writeDelegationRequired(w)
		return nil, false
	}
	if err := pubKey.Verify(payload, &sig); err != nil {
		s.log().Printf("httpsapi: delegation signature failed for user=%q gateway=%q", id.Username, id.GatewayCN)
		writeDelegationRequired(w)
		return nil, false
	}
	s.log().Printf("httpsapi: audit gateway=%q user=%q op=%s signed-ok", id.GatewayCN, id.Username, method)
	return &signedRequest{nonce: nonce, signature: sigBytes, payload: payload}, true
}

func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	signed, ok := s.extractSigned(w, r, id, "quota", func(nonce []byte) ([]byte, error) {
		return auth.ServerRequestPayload("GetQuotaUsage", nonce,
			&backuppbv1.GetQuotaUsageRequest{Username: id.Username})
	})
	if !ok {
		return
	}
	server := r.URL.Query().Get("server")
	usage, err := s.deps.GetQuotaUsageFn(id.Username, server, signed.nonce, signed.signature)
	if err != nil {
		s.log().Printf("httpsapi: quota upstream error for %q: %v", id.Username, err)
		writeError(w, http.StatusBadGateway, "upstream_unavailable", "backup server is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"used_bytes": usage.UsedBytes, "quota_bytes": usage.QuotaBytes,
		"dataset": usage.Dataset, "server": usage.Server,
	})
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	var body struct {
		TargetPath string `json:"target_path"`
		Server     string `json:"server"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	signed, ok := s.extractSigned(w, r, id, "restore", func(nonce []byte) ([]byte, error) {
		return auth.ServerRequestPayload("PullRestore", nonce,
			&backuppbv1.PullRestoreRequest{Username: id.Username})
	})
	if !ok {
		return
	}
	if !s.userLimiter.allow(id.Username) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	taskID, err := s.deps.RequestRestoreFn(id.Username, id.UID, body.TargetPath, body.Server, signed.nonce, signed.signature)
	if err != nil {
		s.log().Printf("httpsapi: restore upstream error for %q: %v", id.Username, err)
		writeError(w, http.StatusBadGateway, "upstream_unavailable", "backup server is unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"task_id": taskID})
}

func (s *Server) handleTriggerSync(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	var body struct {
		Rule   string `json:"rule"`
		Server string `json:"server"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	var entry *ephemeralEntry
	signed, ok := s.extractSigned(w, r, id, "sync", func(nonce []byte) ([]byte, error) {
		entry = s.ephemeral.take(nonce) // single-use; consumed even on failure
		if entry == nil {
			return nil, errNoDelegation // unknown or expired challenge
		}
		pubLine := string(ssh.MarshalAuthorizedKey(entry.signer.PublicKey()))
		return auth.TaskGrantPayload(nonce, id.Username, "PushBackup", pubLine, entry.grantExpiresAt.Unix()), nil
	})
	if !ok {
		return
	}
	if !s.userLimiter.allow(id.Username) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	pubLine := string(ssh.MarshalAuthorizedKey(entry.signer.PublicKey()))
	if err := s.deps.RegisterTaskGrantFn(body.Server, id.Username, "PushBackup", pubLine, entry.grantExpiresAt.Unix(), signed.nonce, signed.signature); err != nil {
		s.log().Printf("httpsapi: register task grant for %q: %v", id.Username, err)
		writeError(w, http.StatusBadGateway, "upstream_unavailable", "backup server is unavailable")
		return
	}
	taskID, err := s.deps.RunSyncWithTaskKeyFn(id.Username, body.Rule, entry.signer)
	if err != nil {
		writeInternal(w, s.log(), "run sync", err)
		return
	}
	s.log().Printf("httpsapi: audit gateway=%q user=%q op=trigger-sync rule=%q task=%q", id.GatewayCN, id.Username, body.Rule, taskID)
	writeJSON(w, http.StatusAccepted, map[string]any{"task_id": taskID})
}

func (s *Server) handleDeleteDelegation(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	signed, ok := s.extractSigned(w, r, id, "revoke_delegation", func(nonce []byte) ([]byte, error) {
		d, err := store.GetWebDelegation(s.deps.DB, id.Username, id.GatewayCN)
		if err != nil {
			return nil, err
		}
		if d == nil {
			return nil, errNoDelegation
		}
		return auth.DelegationRemovalPayload(nonce, id.Username, id.GatewayCN, d.DelegationPubKey), nil
	})
	if !ok {
		return
	}
	d, _ := store.GetWebDelegation(s.deps.DB, id.Username, id.GatewayCN)
	if s.deps.RemoveDelegationKeyFn != nil && d != nil {
		if err := s.deps.RemoveDelegationKeyFn("", id.Username, id.GatewayCN, d.DelegationPubKey, signed.nonce, signed.signature); err != nil {
			// Spec: local revocation takes effect regardless; Server-side
			// removal failure is logged for operators.
			s.log().Printf("httpsapi: server-side delegation removal failed for %q: %v", id.Username, err)
		}
	}
	if err := store.RevokeWebDelegation(s.deps.DB, id.Username, id.GatewayCN); err != nil {
		writeInternal(w, s.log(), "revoke delegation", err)
		return
	}
	s.log().Printf("httpsapi: audit gateway=%q user=%q op=revoke-delegation", id.GatewayCN, id.Username)
	w.WriteHeader(http.StatusNoContent)
}
