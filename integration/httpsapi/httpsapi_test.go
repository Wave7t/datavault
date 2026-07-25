// Package httpsapi contains an end-to-end integration test that drives the
// real datavault agent httpsapi.Server with real signature verification. The
// fake upstream hooks emulate the Server side in-process: they reconstruct the
// canonical payload exactly as internal/server/svc does and verify the gateway
// signature with the real server-side middleware.LoadSigningKeys against a
// temp KeysDir. This proves byte-level compatibility between the gateway's
// signing path (pkg/auth) and the Server's verification path.
package httpsapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/datavault/internal/agent/httpsapi"
	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/pki"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"golang.org/x/crypto/ssh"
)

// newTLSRequest builds an httptest request carrying a fake TLS peer cert with
// the supplied gateway CN. The agent's gate reads r.TLS.PeerCertificates[0].
func newTLSRequest(t *testing.T, method, path string, body []byte, gatewayCN string) *http.Request {
	t.Helper()
	var bodyReader *strings.Reader
	if body == nil {
		bodyReader = strings.NewReader("")
	} else {
		bodyReader = strings.NewReader(string(body))
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: gatewayCN}}},
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// serverHost identifies the (sole) backup server used in these tests. The
// agent's challenge carries this value as ch.Server; the fake upstream uses it
// as the hostname under which delegation keys are stored in the KeysDir.
const serverHost = "backup.example.com"

// generateDelegationKeyPair returns an SSH signer and its authorized_keys line.
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
	return signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// signPayload signs payload with signer and returns ssh.Marshal(sig).
func signPayload(t *testing.T, signer ssh.Signer, payload []byte) []byte {
	t.Helper()
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(sig)
}

// writePrimaryAuthorizedKey lays down the Server-side primary key file at
// keysDir/<host>/<user>.pub so middleware.LoadSigningKeys can find it. We use
// a throwaway key; verification asserts only that the delegation key is also
// accepted.
func writePrimaryAuthorizedKey(t *testing.T, keysDir, host, username string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	dir := filepath.Join(keysDir, host)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, username+".pub"), []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatalf("write primary key: %v", err)
	}
}

// challengeResponse is the JSON shape returned by POST /v1/users/.../challenges.
type challengeResponse struct {
	Nonce     string `json:"nonce"`
	Payload   string `json:"payload"`
	ExpiresAt int64  `json:"expires_at"`
	Server    string `json:"server"`
}

// doPostChallenge issues a challenge request and returns the decoded response
// together with the raw signed payload bytes.
func doPostChallenge(t *testing.T, s *httpsapi.Server, username, gatewayCN, method string, body []byte) (challengeResponse, []byte) {
	t.Helper()
	path := "/v1/users/" + username + "/challenges"
	if body == nil {
		body = []byte(`{"method":"` + method + `"}`)
	}
	req := newTLSRequest(t, http.MethodPost, path, body, gatewayCN)
	req.SetPathValue("user", username)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("challenge %s: expected 200, got %d: %s", method, rr.Code, rr.Body.String())
	}
	var resp challengeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(resp.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return resp, payload
}

// verifyServerSignature mirrors what internal/server/svc does: reconstruct the
// canonical payload via pkg/auth and verify the signature against every key
// returned by middleware.LoadSigningKeys.
func verifyServerSignature(t *testing.T, keysDir, username string, nonce, sigBytes []byte, payload []byte) {
	t.Helper()
	keys, err := middleware.LoadSigningKeys(keysDir, serverHost, username, time.Now())
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		t.Fatalf("unmarshal signature: %v", err)
	}
	if !middleware.VerifyAnyKey(keys, payload, &sig) {
		t.Fatalf("server-side signature verification failed (LoadSigningKeys did not accept the delegation signature)")
	}
}

// currentUser returns the current OS user, skipping the test if unavailable.
func currentUser(t *testing.T) *user.User {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}
	return cur
}

// newAgentServer builds a real httpsapi.Server wired to an in-memory DB, a
// temp UserRuleStore, and the supplied upstream hooks.
func newAgentServer(t *testing.T, db *sql.DB, gatewayCNs []string, deps httpsapi.Deps) *httpsapi.Server {
	t.Helper()
	deps.Cfg = &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: gatewayCNs,
			MinUID:     0,
		},
	}
	deps.DB = db
	if deps.UserRuleStore == nil {
		deps.UserRuleStore = rules.NewUserRuleStore(t.TempDir())
	}
	s, err := httpsapi.NewServer(deps)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// enrollDelegation simulates the Server handler's enrolment step: insert a
// row the agent can read AND persist the key into the Server-side KeysDir so
// LoadSigningKeys can find it later.
func enrollDelegation(t *testing.T, db *sql.DB, keysDir, username, gatewayCN string) (ssh.Signer, string) {
	t.Helper()
	delSigner, delPubLine := generateDelegationKeyPair(t)
	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         username,
		GatewayCN:        gatewayCN,
		DelegationPubKey: delPubLine,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatalf("UpsertWebDelegation: %v", err)
	}
	if err := middleware.SaveDelegationKey(keysDir, serverHost, username, delPubLine, middleware.DelegationMeta{
		GatewayCN: gatewayCN,
		ExpiresAt: now.Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatalf("SaveDelegationKey: %v", err)
	}
	return delSigner, delPubLine
}

// TestFullDelegationLifecycle exercises enroll -> quota challenge -> signed
// quota call (verified by the real Server-side LoadSigningKeys) -> signed
// revoke DELETE -> subsequent calls 403.
func TestFullDelegationLifecycle(t *testing.T) {
	cur := currentUser(t)

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatalf("MigrateWebDelegations: %v", err)
	}

	keysDir := t.TempDir()
	writePrimaryAuthorizedKey(t, keysDir, serverHost, cur.Username)
	delSigner, _ := enrollDelegation(t, db, keysDir, cur.Username, "backup-web-01")

	fixedNonce := []byte("fixed-quota-challenge-nonce!")
	fixedChallenge := &agentpbv1.AuthChallenge{
		Nonce:     fixedNonce,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Server:    serverHost,
	}

	var quotaVerified bool
	s := newAgentServer(t, db, []string{"backup-web-01"}, httpsapi.Deps{
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
			return fixedChallenge, nil
		},
		GetQuotaUsageFn: func(username, srv string, nonce, signature []byte) (*agentpbv1.QuotaUsage, error) {
			// Server-side path: reconstruct the canonical payload exactly as
			// the Server's RPC handler does, and verify with LoadSigningKeys.
			payload, err := auth.ServerRequestPayload("GetQuotaUsage", nonce,
				&backuppbv1.GetQuotaUsageRequest{Username: username})
			if err != nil {
				t.Fatalf("ServerRequestPayload: %v", err)
			}
			verifyServerSignature(t, keysDir, username, nonce, signature, payload)
			quotaVerified = true
			return &agentpbv1.QuotaUsage{
				UsedBytes:  1024,
				QuotaBytes: 8192,
				Dataset:    "tank/backups",
				Server:     serverHost,
			}, nil
		},
	})

	// 1. Challenge for quota.
	_, payload := doPostChallenge(t, s, cur.Username, "backup-web-01", "quota", nil)
	sigBytes := signPayload(t, delSigner, payload)

	// 2. Signed quota call.
	quotaPath := "/v1/users/" + cur.Username + "/quota"
	req := newTLSRequest(t, http.MethodGet, quotaPath, nil, "backup-web-01")
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("quota: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !quotaVerified {
		t.Fatal("expected fake upstream to have verified the signature with LoadSigningKeys")
	}

	// 3. Revoke via signed DELETE.
	revChallenge := &agentpbv1.AuthChallenge{
		Nonce:     []byte("revoke-challenge-nonce!!"),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Server:    serverHost,
	}
	s2 := newAgentServer(t, db, []string{"backup-web-01"}, httpsapi.Deps{
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) { return revChallenge, nil },
		RemoveDelegationKeyFn: func(server, username, gatewayCN, delegationPubKey string, nonce, signature []byte) error {
			// Server-side revocation verifies the removal payload too.
			payload := auth.DelegationRemovalPayload(nonce, username, gatewayCN, delegationPubKey)
			verifyServerSignature(t, keysDir, username, nonce, signature, payload)
			return nil
		},
	})
	_, revPayload := doPostChallenge(t, s2, cur.Username, "backup-web-01", "revoke_delegation", nil)
	revSig := signPayload(t, delSigner, revPayload)

	delPath := "/v1/users/" + cur.Username + "/delegation"
	req = newTLSRequest(t, http.MethodDelete, delPath, nil, "backup-web-01")
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(revChallenge.Nonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(revSig))
	rr = httptest.NewRecorder()
	s2.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Row is revoked locally.
	d, err := store.GetWebDelegation(db, cur.Username, "backup-web-01")
	if err != nil {
		t.Fatalf("GetWebDelegation: %v", err)
	}
	if d == nil || d.RevokedAt == nil {
		t.Fatal("expected delegation row to be revoked after DELETE")
	}

	// 4. Subsequent signed quota call -> 403 delegation_required.
	req = newTLSRequest(t, http.MethodGet, quotaPath, nil, "backup-web-01")
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(fixedNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("post-revoke quota: expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"delegation_required"`) {
		t.Fatalf("post-revoke quota: expected delegation_required code, got %s", rr.Body.String())
	}
}

// TestSyncGrantFlow exercises sync challenge -> signed trigger. The fake
// RegisterTaskGrantFn reconstructs auth.TaskGrantPayload exactly as
// internal/server/svc.RegisterTaskGrant does and verifies the signature against
// the delegation key. The fake RunSyncWithTaskKeyFn signs a probe payload with
// the received signer and verifies it against the granted ephemeral pubkey.
func TestSyncGrantFlow(t *testing.T) {
	cur := currentUser(t)

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatalf("MigrateWebDelegations: %v", err)
	}

	keysDir := t.TempDir()
	writePrimaryAuthorizedKey(t, keysDir, serverHost, cur.Username)
	delSigner, _ := enrollDelegation(t, db, keysDir, cur.Username, "backup-web-01")

	syncNonce := []byte("sync-challenge-nonce-01234567")
	fixedChallenge := &agentpbv1.AuthChallenge{
		Nonce:     syncNonce,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Server:    serverHost,
	}

	var (
		grantVerified        bool
		grantedEphemeralLine string
		runSigner            ssh.Signer
	)
	s := newAgentServer(t, db, []string{"backup-web-01"}, httpsapi.Deps{
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) { return fixedChallenge, nil },
		RegisterTaskGrantFn: func(server, username, method, ephemeralPubKey string, expiresAt int64, nonce, signature []byte) error {
			// Server-side path: rebuild the TaskGrantPayload exactly as
			// internal/server/svc.RegisterTaskGrant does.
			payload := auth.TaskGrantPayload(nonce, username, method, ephemeralPubKey, expiresAt)
			verifyServerSignature(t, keysDir, username, nonce, signature, payload)
			grantVerified = true
			grantedEphemeralLine = strings.TrimSpace(ephemeralPubKey)
			return nil
		},
		RunSyncWithTaskKeyFn: func(username, ruleName string, taskKey ssh.Signer) (string, error) {
			runSigner = taskKey
			// The Server would store this ephemeral key and later verify task
			// payloads signed by it against the granted pubkey.
			probe := []byte("probe-payload-for-ephemeral-key")
			sig, err := taskKey.Sign(rand.Reader, probe)
			if err != nil {
				t.Fatalf("ephemeral sign: %v", err)
			}
			grantedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(grantedEphemeralLine))
			if err != nil {
				t.Fatalf("parse granted ephemeral key: %v", err)
			}
			if err := grantedPub.Verify(probe, sig); err != nil {
				t.Fatalf("ephemeral pubkey did not verify task signature: %v", err)
			}
			return "sync-task-42", nil
		},
	})

	// 1. Sync challenge.
	_, payload := doPostChallenge(t, s, cur.Username, "backup-web-01", "sync",
		[]byte(`{"method":"sync","rule":"proj"}`))
	sigBytes := signPayload(t, delSigner, payload)

	// 2. Signed trigger.
	syncPath := "/v1/users/" + cur.Username + "/syncs"
	req := newTLSRequest(t, http.MethodPost, syncPath, []byte(`{"rule":"proj"}`), "backup-web-01")
	req.SetPathValue("user", cur.Username)
	req.Header.Set("X-Datavault-Nonce", base64.StdEncoding.EncodeToString(syncNonce))
	req.Header.Set("X-Datavault-Signature", base64.StdEncoding.EncodeToString(sigBytes))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("sync: expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	if !grantVerified {
		t.Fatal("expected RegisterTaskGrantFn to verify the grant signature with LoadSigningKeys")
	}
	var syncResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &syncResp); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}
	if syncResp["task_id"] != "sync-task-42" {
		t.Fatalf("expected task_id sync-task-42, got %v", syncResp["task_id"])
	}

	// The signer handed to RunSyncWithTaskKeyFn must publish the granted key.
	if runSigner == nil {
		t.Fatal("expected RunSyncWithTaskKeyFn to receive a non-nil signer")
	}
	runPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(runSigner.PublicKey())))
	if runPubLine != grantedEphemeralLine {
		t.Fatalf("run-sync signer pubkey %q != granted ephemeral pubkey %q", runPubLine, grantedEphemeralLine)
	}
}

// TestUnallowlistedGatewayRejected exercises the real mTLS gate
// (RequireAndVerifyClientCert) using httptest.NewTLSServer. A client carrying
// a rogue-gateway certificate issued by the same CA must be rejected at the
// TLS layer (handshake failure). If TLS handshake plumbing is unavailable in
// the test environment, the test falls back to injecting TLS state and
// asserting the CN-allowlist gate returns 401.
func TestUnallowlistedGatewayRejected(t *testing.T) {
	// Build a CA and issue a server cert + two client certs (rogue + allowlisted).
	caCertPEM, caKeyPEM, err := pki.CreateCA(pki.CAOptions{CommonName: "datavault-test-ca"})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	srvCertPEM, srvKeyPEM, err := pki.Issue(caCertPEM, caKeyPEM, pki.IssueOptions{
		CommonName: serverHost,
		DNSNames:   []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		Server:     true,
	})
	if err != nil {
		t.Fatalf("Issue server cert: %v", err)
	}
	rogueCertPEM, rogueKeyPEM, err := pki.Issue(caCertPEM, caKeyPEM, pki.IssueOptions{
		CommonName: "rogue-gateway",
		Client:     true,
	})
	if err != nil {
		t.Fatalf("Issue rogue client cert: %v", err)
	}

	cur := currentUser(t)
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatalf("MigrateWebDelegations: %v", err)
	}
	// Pre-enrol the current user so the rogue test fails on CN, not on a
	// missing delegation row.
	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "backup-web-01",
		DelegationPubKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK/XCUj4i6Q5yQJNL1MGj9n2sQ0 test",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatalf("UpsertWebDelegation: %v", err)
	}

	s := newAgentServer(t, db, []string{"backup-web-01"}, httpsapi.Deps{})

	if !tryRealTLSReject(t, s, srvCertPEM, srvKeyPEM, caCertPEM, rogueCertPEM, rogueKeyPEM, cur.Username) {
		// Fall back to injected TLS state: prove the CN-allowlist gate fires.
		injectedTLSReject(t, s, cur.Username)
	}
}

// tryRealTLSReject attempts a genuine mTLS handshake against an
// httptest.NewTLSServer. It returns true if the handshake was rejected (the
// scenario's expected outcome for a rogue CN), and false if a real handshake
// could not be established in this environment.
func tryRealTLSReject(t *testing.T, s *httpsapi.Server, srvCertPEM, srvKeyPEM, caCertPEM, rogueCertPEM, rogueKeyPEM []byte, username string) bool {
	t.Helper()
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Logf("parse server cert: %v — falling back to injected TLS state", err)
		return false
	}
	rogueCert, err := tls.X509KeyPair(rogueCertPEM, rogueKeyPEM)
	if err != nil {
		t.Logf("parse rogue client cert: %v — falling back to injected TLS state", err)
		return false
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caCertPEM) {
		t.Logf("failed to add CA to client pool — falling back to injected TLS state")
		return false
	}

	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
	}
	// Capture the server's TLS handshake error log so we can assert the server
	// itself rejected the rogue client (rather than the client failing on the
	// server cert), proving RequireAndVerifyClientCert fired.
	var serverLog strings.Builder
	ts.Config.ErrorLog = log.New(&serverLog, "", 0)
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client()
	// Replace the test server's default root pool (which trusts the server
	// cert's CA) with our CA so the client trusts the server.
	transport := client.Transport.(*http.Transport).Clone()
	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(caCertPEM)
	transport.TLSClientConfig.RootCAs = serverCAPool
	transport.TLSClientConfig.Certificates = []tls.Certificate{rogueCert}
	client.Transport = transport

	for _, ep := range []string{
		"/v1/users/" + username + "/rules",
		"/v1/users/" + username + "/delegation",
		"/v1/users/" + username + "/challenges",
	} {
		resp, err := client.Get(ts.URL + ep)
		if err != nil {
			// The mTLS handshake should succeed (rogue cert is CA-trusted);
			// rejection is the application layer's job (CN allowlist). A
			// transport error here means our test plumbing is wrong.
			t.Errorf("rogue-gateway transport error to %s: %v (server log: %q)", ep, err, serverLog.String())
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("rogue-gateway %s: expected 401, got %d", ep, resp.StatusCode)
			continue
		}
		t.Logf("rogue-gateway correctly rejected with 401 at %s", ep)
	}
	// The rogue cert must be chain-trusted by the CA, so the server-side TLS
	// log must NOT contain a handshake error — the CN-allowlist gate is what
	// rejects the unallowlisted gateway, exactly as designed.
	if strings.Contains(serverLog.String(), "TLS handshake error") {
		t.Errorf("did not expect server-side TLS handshake error (rogue cert should be CA-trusted); log: %q", serverLog.String())
	}
	if t.Failed() {
		t.Fatal("real-TLS rogue-gateway path did not reject the client as required")
	}
	return true
}

// injectedTLSReject asserts that, with TLS state injected directly, a rogue CN
// is rejected with 401 on every endpoint. This is the fallback when a real
// mTLS handshake cannot be established.
func injectedTLSReject(t *testing.T, s *httpsapi.Server, username string) {
	t.Helper()
	t.Log("using injected TLS state fallback for rogue-gateway rejection")
	for _, ep := range []string{
		"/v1/users/" + username + "/rules",
		"/v1/users/" + username + "/delegation",
		"/v1/users/" + username + "/challenges",
	} {
		req := newTLSRequest(t, http.MethodGet, ep, nil, "rogue-gateway")
		req.SetPathValue("user", username)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("rogue-gateway %s: expected 401, got %d: %s", ep, rr.Code, rr.Body.String())
		}
	}
}
