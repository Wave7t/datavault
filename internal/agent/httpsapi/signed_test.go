package httpsapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"testing"
	"time"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
)

// generateDelegationKeyPair creates a test ed25519 key pair and returns the
// SSH signer and authorized_keys line.
func generateDelegationKeyPair(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	return signer, pubLine
}

// signPayload signs payload with the given signer and returns ssh.Marshal(sig).
func signPayload(t *testing.T, signer ssh.Signer, payload []byte) []byte {
	t.Helper()
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(sig)
}

func TestChallengeAndSignedQuota(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	// Generate delegation key pair
	delSigner, delPubLine := generateDelegationKeyPair(t)

	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "gateway1",
		DelegationPubKey: delPubLine,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}

	fixedNonce := []byte("fixed-challenge-nonce-12345678")
	fixedChallenge := &agentpbv1.AuthChallenge{
		Nonce:     fixedNonce,
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Server:    "backup.example.com",
	}

	var capturedNonce, capturedSig []byte
	fakeQuota := &agentpbv1.QuotaUsage{
		UsedBytes:  1000,
		QuotaBytes: 5000,
		Dataset:    "default",
		Server:     "backup.example.com",
	}

	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gateway1"},
			MinUID:     0,
		},
	}

	s := mustServerWithDeps(t, Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
			return fixedChallenge, nil
		},
		GetQuotaUsageFn: func(username, server string, nonce, signature []byte) (*agentpbv1.QuotaUsage, error) {
			capturedNonce = nonce
			capturedSig = signature
			return fakeQuota, nil
		},
	})

	// 1. POST challenge for quota
	challengePath := "/v1/users/" + cur.Username + "/challenges"
	reqBody := []byte(`{"method":"quota"}`)
	req := makeRequest(t, http.MethodPost, challengePath, reqBody)
	req.SetPathValue("user", cur.Username)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for challenge, got %d: %s", rr.Code, rr.Body.String())
	}
	var chResp struct {
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
		ExpiresAt int64  `json:"expires_at"`
		Server    string `json:"server"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &chResp); err != nil {
		t.Fatal(err)
	}

	// Decode payload and sign it
	payload, err := base64.StdEncoding.DecodeString(chResp.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := signPayload(t, delSigner, payload)

	// 2. GET quota with signed headers
	quotaPath := "/v1/users/" + cur.Username + "/quota"
	req = makeRequest(t, http.MethodGet, quotaPath, nil)
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for quota, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify fake received the same nonce+signature
	if string(capturedNonce) != string(fixedNonce) {
		t.Fatalf("expected nonce forwarded verbatim")
	}
	if string(capturedSig) != string(sigBytes) {
		t.Fatalf("expected signature forwarded verbatim")
	}

	var quotaResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &quotaResp); err != nil {
		t.Fatal(err)
	}
	if quotaResp["used_bytes"].(float64) != 1000 {
		t.Fatalf("expected used_bytes 1000, got %v", quotaResp["used_bytes"])
	}

	// Negative: sign with different key -> 403
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongSigner, _ := ssh.NewSignerFromKey(wrongPriv)
	wrongSig := signPayload(t, wrongSigner, payload)
	req = makeRequest(t, http.MethodGet, quotaPath, nil)
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(wrongSig))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong key, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"code":"delegation_required"`) {
		t.Fatalf("expected delegation_required code, got %s", body)
	}

	// Negative: headers missing -> 403 delegation_required
	req = makeRequest(t, http.MethodGet, quotaPath, nil)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing headers, got %d: %s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if !strings.Contains(body, `"code":"delegation_required"`) {
		t.Fatalf("expected delegation_required code, got %s", body)
	}
}

func TestExtractSignedCorruptStoredKey(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "gateway1",
		DelegationPubKey: "not-a-real-key",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gateway1"},
			MinUID:     0,
		},
	}

	s := mustServerWithDeps(t, Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
	})

	// Make a signed request with any base64 nonce/signature headers
	quotaPath := "/v1/users/" + cur.Username + "/quota"
	req := makeRequest(t, http.MethodGet, quotaPath, nil)
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString([]byte("any-nonce")))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString([]byte("any-sig")))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for corrupt stored key, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"code":"delegation_required"`) {
		t.Fatalf("expected delegation_required code, got %s", body)
	}
}

func TestSignedSyncRegistersGrantAndRuns(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	delSigner, delPubLine := generateDelegationKeyPair(t)

	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "gateway1",
		DelegationPubKey: delPubLine,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}

	fixedNonce := []byte("fixed-sync-challenge-nonce!!")
	fixedChallenge := &agentpbv1.AuthChallenge{
		Nonce:     fixedNonce,
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Server:    "backup.example.com",
	}

	var (
		registerMethod      string
		registerPubKey      string
		registerExpiresAt   int64
		registerNonce       []byte
		registerSignature   []byte
		registerCalledFirst bool
		runSyncSigner       ssh.Signer
	)

	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gateway1"},
			MinUID:     0,
		},
	}

	s := mustServerWithDeps(t, Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
			return fixedChallenge, nil
		},
		RegisterTaskGrantFn: func(server, username, method, ephemeralPubKey string, expiresAt int64, nonce, signature []byte) error {
			registerMethod = method
			registerPubKey = ephemeralPubKey
			registerExpiresAt = expiresAt
			registerNonce = nonce
			registerSignature = signature
			registerCalledFirst = runSyncSigner == nil // RunSync not called yet
			return nil
		},
		RunSyncWithTaskKeyFn: func(username, ruleName string, taskKey ssh.Signer) (string, error) {
			runSyncSigner = taskKey
			return "sync-task-42", nil
		},
	})

	// 1. POST challenge for sync
	challengePath := "/v1/users/" + cur.Username + "/challenges"
	reqBody := []byte(`{"method":"sync","rule":"proj"}`)
	req := makeRequest(t, http.MethodPost, challengePath, reqBody)
	req.SetPathValue("user", cur.Username)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for sync challenge, got %d: %s", rr.Code, rr.Body.String())
	}
	var chResp struct {
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
		ExpiresAt int64  `json:"expires_at"`
		Server    string `json:"server"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &chResp); err != nil {
		t.Fatal(err)
	}

	// Decode payload and sign it with delegation key
	payload, err := base64.StdEncoding.DecodeString(chResp.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := signPayload(t, delSigner, payload)

	// 2. POST sync with signed headers
	syncPath := "/v1/users/" + cur.Username + "/syncs"
	syncBody := []byte(`{"rule":"proj"}`)
	req = makeRequest(t, http.MethodPost, syncPath, syncBody)
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for sync, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify RegisterTaskGrantFn assertions
	if registerMethod != "PushBackup" {
		t.Fatalf("expected method PushBackup, got %q", registerMethod)
	}
	if registerPubKey == "" {
		t.Fatal("expected non-empty ephemeral pubkey")
	}
	grantExpiry := time.Unix(registerExpiresAt, 0)
	expectedExpiry := now.Add(6 * time.Hour)
	if grantExpiry.Sub(expectedExpiry) > time.Minute || expectedExpiry.Sub(grantExpiry) > time.Minute {
		t.Fatalf("expected expires_at ~ now+6h, got %v", grantExpiry)
	}
	if string(registerNonce) != string(fixedNonce) {
		t.Fatalf("expected nonce forwarded verbatim")
	}
	if string(registerSignature) != string(sigBytes) {
		t.Fatalf("expected signature forwarded verbatim")
	}
	if !registerCalledFirst {
		t.Fatal("expected RegisterTaskGrantFn to run before RunSyncWithTaskKeyFn")
	}

	// Verify RunSyncWithTaskKeyFn got a signer whose pubkey matches the granted one
	if runSyncSigner == nil {
		t.Fatal("expected non-nil task signer")
	}
	grantedPubLine := strings.TrimSpace(registerPubKey)
	runPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(runSyncSigner.PublicKey())))
	if grantedPubLine != runPubLine {
		t.Fatalf("expected task key pubkey to match granted pubkey")
	}

	var syncResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &syncResp); err != nil {
		t.Fatal(err)
	}
	if syncResp["task_id"] != "sync-task-42" {
		t.Fatalf("expected task_id sync-task-42, got %v", syncResp["task_id"])
	}

	// Negative: reuse same nonce for second sync -> 403 (single-use challenge)
	req = makeRequest(t, http.MethodPost, syncPath, syncBody)
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for nonce reuse, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSignedRevokeDelegation(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	delSigner, delPubLine := generateDelegationKeyPair(t)

	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "gateway1",
		DelegationPubKey: delPubLine,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}

	fixedNonce := []byte("revoke-challenge-nonce!!")
	fixedChallenge := &agentpbv1.AuthChallenge{
		Nonce:     fixedNonce,
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Server:    "backup.example.com",
	}

	var capturedNonce, capturedSig []byte

	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gateway1"},
			MinUID:     0,
		},
	}

	s := mustServerWithDeps(t, Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
			return fixedChallenge, nil
		},
		RemoveDelegationKeyFn: func(server, username, gatewayCN, delegationPubKey string, nonce, signature []byte) error {
			capturedNonce = nonce
			capturedSig = signature
			return nil
		},
	})

	// 1. POST challenge for revoke_delegation
	challengePath := "/v1/users/" + cur.Username + "/challenges"
	reqBody := []byte(`{"method":"revoke_delegation"}`)
	req := makeRequest(t, http.MethodPost, challengePath, reqBody)
	req.SetPathValue("user", cur.Username)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for revoke challenge, got %d: %s", rr.Code, rr.Body.String())
	}
	var chResp struct {
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
		ExpiresAt int64  `json:"expires_at"`
		Server    string `json:"server"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &chResp); err != nil {
		t.Fatal(err)
	}

	// Decode payload and sign it
	payload, err := base64.StdEncoding.DecodeString(chResp.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := signPayload(t, delSigner, payload)

	// 2. DELETE delegation with signed headers
	delPath := "/v1/users/" + cur.Username + "/delegation"
	req = makeRequest(t, http.MethodDelete, delPath, nil)
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for revoke delegation, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify RemoveDelegationKeyFn received forwarded nonce+signature
	if string(capturedNonce) != string(fixedNonce) {
		t.Fatalf("expected nonce forwarded verbatim")
	}
	if string(capturedSig) != string(sigBytes) {
		t.Fatalf("expected signature forwarded verbatim")
	}

	// Verify local row is revoked
	d, err := store.GetWebDelegation(db, cur.Username, "gateway1")
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || d.RevokedAt == nil {
		t.Fatal("expected delegation to be revoked locally")
	}
}
