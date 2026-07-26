package svc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"testing"
	"time"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	return auth.ContextWithPeerUID(context.Background(), uint32(os.Getuid()))
}

func generateEd25519PubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new ssh public key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestEnrollWebDelegationValidatesAndForwards(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	pubKey := generateEd25519PubKey(t)

	var hookCalled bool
	var hookServer, hookUsername, hookGatewayCN, hookPubKey string
	var hookExpiresAt int64
	var hookNonce, hookSignature []byte

	service := &AgentService{
		Cfg: &config.AgentConfig{
			HTTPSAPI: &config.HTTPSAPIConfig{
				GatewayCNs:    []string{"backup-web-01"},
				DelegationTTL: 24 * time.Hour,
			},
		},
		DB: db,
		RegisterDelegationKeyFn: func(server, username string, uid uint32, groups []string, gatewayCN, delegationPubKey string, expiresAt int64, nonce, signature []byte) error {
			hookCalled = true
			hookServer = server
			hookUsername = username
			hookGatewayCN = gatewayCN
			hookPubKey = delegationPubKey
			hookExpiresAt = expiresAt
			hookNonce = nonce
			hookSignature = signature
			return nil
		},
	}

	// Positive: valid enrollment
	req := &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "backup-web-01",
		DelegationPubkey: pubKey,
		TtlSeconds:       int64(time.Hour.Seconds()),
		Server:           "server:8443",
		Nonce:            []byte("nonce"),
		Signature:        []byte("signature"),
	}
	resp, err := service.EnrollWebDelegation(ctx, req)
	if err != nil {
		t.Fatalf("EnrollWebDelegation: %v", err)
	}
	if !hookCalled {
		t.Fatal("expected hook to be called")
	}
	if hookServer != "server:8443" {
		t.Fatalf("unexpected server %q", hookServer)
	}
	if hookGatewayCN != "backup-web-01" {
		t.Fatalf("unexpected gateway CN %q", hookGatewayCN)
	}
	if hookPubKey != pubKey {
		t.Fatal("unexpected delegation pubkey")
	}
	if string(hookNonce) != "nonce" || string(hookSignature) != "signature" {
		t.Fatal("unexpected nonce/signature")
	}
	if hookUsername == "" {
		t.Fatal("expected username")
	}
	if resp.ExpiresAt == 0 {
		t.Fatal("expected expires_at")
	}
	// expires_at should be roughly now + 1h
	wantExpires := time.Now().Add(time.Hour).Unix()
	if resp.ExpiresAt < wantExpires-5 || resp.ExpiresAt > wantExpires+5 {
		t.Fatalf("expires_at %d not near expected %d", resp.ExpiresAt, wantExpires)
	}
	if hookExpiresAt != resp.ExpiresAt {
		t.Fatalf("hook expiresAt %d != response %d", hookExpiresAt, resp.ExpiresAt)
	}

	// Verify local row was written
	d, err := store.GetWebDelegation(db, hookUsername, "backup-web-01")
	if err != nil || d == nil {
		t.Fatalf("expected row in db: %v %v", d, err)
	}
	if d.DelegationPubKey != pubKey {
		t.Fatal("db pubkey mismatch")
	}

	// Negative: gateway not allowlisted
	hookCalled = false
	_, err = service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "evil-gw",
		DelegationPubkey: pubKey,
		TtlSeconds:       int64(time.Hour.Seconds()),
	})
	if err == nil {
		t.Fatal("expected error for disallowed gateway")
	}
	if hookCalled {
		t.Fatal("expected no hook call for disallowed gateway")
	}

	// Negative: TTL exceeds max
	_, err = service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "backup-web-01",
		DelegationPubkey: pubKey,
		TtlSeconds:       int64((48 * time.Hour).Seconds()),
	})
	if err == nil {
		t.Fatal("expected error for excessive TTL")
	}

	// Negative: zero TTL
	_, err = service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "backup-web-01",
		DelegationPubkey: pubKey,
		TtlSeconds:       0,
	})
	if err == nil {
		t.Fatal("expected error for zero TTL")
	}

	// Negative: malformed pubkey
	_, err = service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "backup-web-01",
		DelegationPubkey: "not-a-valid-key",
		TtlSeconds:       int64(time.Hour.Seconds()),
	})
	if err == nil {
		t.Fatal("expected error for malformed pubkey")
	}

	// Negative: hook returns error -> no local row (rollback)
	service.RegisterDelegationKeyFn = func(_ string, _ string, _ uint32, _ []string, _, _ string, _ int64, _, _ []byte) error {
		return assertAnError
	}
	_, err = service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "backup-web-01",
		DelegationPubkey: pubKey,
		TtlSeconds:       int64(time.Hour.Seconds()),
	})
	if err == nil {
		t.Fatal("expected error when hook fails")
	}
	// The row for this new enrollment should not exist (or old one from earlier success should remain)
	// Since we used same gateway, the old row from the first successful call should still be there
	// because the hook failed so UpsertWebDelegation was never called.
	d2, _ := store.GetWebDelegation(db, hookUsername, "backup-web-01")
	if d2 == nil {
		t.Fatal("expected original row to remain after failed hook")
	}
	if d2.DelegationPubKey != pubKey {
		t.Fatal("original row should be unchanged")
	}
}

func TestEnrollWebDelegationRequiresHTTPSAPIConfig(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	service := &AgentService{DB: db}
	_, err := service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{})
	if err == nil {
		t.Fatal("expected error when HTTPSAPI not configured")
	}
}

func TestEnrollWebDelegationRequiresHook(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	service := &AgentService{
		Cfg: &config.AgentConfig{
			HTTPSAPI: &config.HTTPSAPIConfig{
				GatewayCNs:    []string{"backup-web-01"},
				DelegationTTL: 24 * time.Hour,
			},
		},
		DB: db,
	}
	_, err := service.EnrollWebDelegation(ctx, &agentpbv1.EnrollWebDelegationRequest{
		GatewayCn:        "backup-web-01",
		DelegationPubkey: generateEd25519PubKey(t),
		TtlSeconds:       int64(time.Hour.Seconds()),
	})
	if err == nil {
		t.Fatal("expected error when hook not configured")
	}
}

func TestRevokeWebDelegationLocalEvenWhenServerFails(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	pubKey := generateEd25519PubKey(t)

	// Determine the username from context for DB setup
	username, _ := (&AgentService{}).extractUsername(ctx)

	// Pre-enroll a delegation directly in DB
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         username,
		GatewayCN:        "backup-web-01",
		DelegationPubKey: pubKey,
		ExpiresAt:        time.Now().Add(time.Hour),
		CreatedAt:        time.Now(),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	service := &AgentService{
		Cfg: &config.AgentConfig{
			HTTPSAPI: &config.HTTPSAPIConfig{
				GatewayCNs:    []string{"backup-web-01"},
				DelegationTTL: 24 * time.Hour,
			},
		},
		DB: db,
		RemoveDelegationKeyFn: func(_, _ string, _ uint32, _ []string, _, _ string, _, _ []byte) error {
			return assertAnError
		},
	}

	_, err := service.RevokeWebDelegation(ctx, &agentpbv1.RevokeWebDelegationRequest{
		GatewayCn: "backup-web-01",
		Server:    "server:8443",
		Nonce:     []byte("nonce"),
		Signature: []byte("signature"),
	})
	if err != nil {
		t.Fatalf("RevokeWebDelegation should succeed even when server call fails: %v", err)
	}

	// Verify local row is revoked
	d, err := store.GetWebDelegation(db, username, "backup-web-01")
	if err != nil || d == nil {
		t.Fatalf("expected row: %v %v", d, err)
	}
	if d.RevokedAt == nil {
		t.Fatal("expected row to be revoked")
	}
}

func TestRevokeWebDelegationNotFound(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	service := &AgentService{
		Cfg: &config.AgentConfig{
			HTTPSAPI: &config.HTTPSAPIConfig{
				GatewayCNs:    []string{"backup-web-01"},
				DelegationTTL: 24 * time.Hour,
			},
		},
		DB: db,
	}

	_, err := service.RevokeWebDelegation(ctx, &agentpbv1.RevokeWebDelegationRequest{
		GatewayCn: "backup-web-01",
	})
	if err == nil {
		t.Fatal("expected NotFound error")
	}
}

func TestRevokeWebDelegationAlreadyRevoked(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	username, _ := (&AgentService{}).extractUsername(ctx)
	pubKey := generateEd25519PubKey(t)

	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         username,
		GatewayCN:        "backup-web-01",
		DelegationPubKey: pubKey,
		ExpiresAt:        time.Now().Add(time.Hour),
		CreatedAt:        time.Now(),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := store.RevokeWebDelegation(db, username, "backup-web-01"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	service := &AgentService{
		Cfg: &config.AgentConfig{
			HTTPSAPI: &config.HTTPSAPIConfig{
				GatewayCNs:    []string{"backup-web-01"},
				DelegationTTL: 24 * time.Hour,
			},
		},
		DB: db,
	}

	_, err := service.RevokeWebDelegation(ctx, &agentpbv1.RevokeWebDelegationRequest{
		GatewayCn: "backup-web-01",
	})
	if err == nil {
		t.Fatal("expected NotFound error for already-revoked delegation")
	}
}

func TestListWebDelegations(t *testing.T) {
	ctx := testContext(t)
	db := openTestDB(t)
	username, _ := (&AgentService{}).extractUsername(ctx)
	pubKey := generateEd25519PubKey(t)

	for _, cn := range []string{"gw-a", "gw-b"} {
		if err := store.UpsertWebDelegation(db, store.WebDelegation{
			Username:         username,
			GatewayCN:        cn,
			DelegationPubKey: pubKey,
			ExpiresAt:        time.Now().Add(time.Hour),
			CreatedAt:        time.Now(),
		}); err != nil {
			t.Fatalf("upsert %s: %v", cn, err)
		}
	}
	if err := store.RevokeWebDelegation(db, username, "gw-a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	service := &AgentService{DB: db}
	resp, err := service.ListWebDelegations(ctx, &agentpbv1.ListWebDelegationsRequest{})
	if err != nil {
		t.Fatalf("ListWebDelegations: %v", err)
	}
	if len(resp.Delegations) != 2 {
		t.Fatalf("expected 2 delegations, got %d", len(resp.Delegations))
	}

	// Find gw-a and check revoked=true
	var foundA, foundB bool
	for _, d := range resp.Delegations {
		if d.GatewayCn == "gw-a" {
			foundA = true
			if !d.Revoked {
				t.Fatal("expected gw-a to be revoked")
			}
		}
		if d.GatewayCn == "gw-b" {
			foundB = true
			if d.Revoked {
				t.Fatal("expected gw-b to not be revoked")
			}
		}
	}
	if !foundA || !foundB {
		t.Fatal("expected both delegations in response")
	}
}

// assertAnError is a sentinel error for hook failures.
var assertAnError = assertError("hook failed")

type assertError string

func (e assertError) Error() string { return string(e) }
