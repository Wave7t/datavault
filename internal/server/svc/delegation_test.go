package svc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newTestServer(t *testing.T) (*BackupServer, context.Context, func()) {
	t.Helper()
	keysDir := t.TempDir()
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.MigrateNonces(db); err != nil {
		t.Fatalf("migrate nonces: %v", err)
	}
	if err := store.MigrateTaskGrants(db); err != nil {
		t.Fatalf("migrate task grants: %v", err)
	}
	ctx := middleware.ContextWithHostname(context.Background(), "agent-01")

	srv := &BackupServer{
		DB:      db,
		KeysDir: keysDir,
	}
	return srv, ctx, func() { db.Close() }
}

func writePrimaryKey(t *testing.T, keysDir, host, user string) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(keysDir, host)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, user+".pub"), ssh.MarshalAuthorizedKey(sshPub), 0600); err != nil {
		t.Fatal(err)
	}
	return sshPub, signer
}

func signPayload(signer ssh.Signer, payload []byte) []byte {
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		panic(err)
	}
	return ssh.Marshal(sig)
}

func insertNonce(t *testing.T, db *sql.DB, hexNonce string) {
	t.Helper()
	if err := store.InsertNonce(db, hexNonce, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("insert nonce: %v", err)
	}
}

func TestRegisterDelegationKeyRequiresPrimarySignature(t *testing.T) {
	srv, ctx, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key for alice
	_, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")

	// Generate a different (unauthorized) key pair
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongSigner, _ := ssh.NewSignerFromKey(wrongPriv)

	// Generate delegation key
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

	hexNonce := "abcd1234abcd1234"
	nonceBytes, _ := hex.DecodeString(hexNonce)
	insertNonce(t, srv.DB, hexNonce)

	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	payload := auth.DelegationConsentPayload(nonceBytes, "alice", "backup-web-01", delPubKeyLine, expiresAt)

	// Try with wrong signer → should fail
	reqWrong := &backuppbv1.RegisterDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine, ExpiresAt: expiresAt,
		Nonce: nonceBytes, Signature: signPayload(wrongSigner, payload),
	}
	_, err := srv.RegisterDelegationKey(ctx, reqWrong)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for wrong key, got: %v", err)
	}

	// Now try with primary signer → should succeed
	insertNonce(t, srv.DB, "abcd1234abcd1235")
	nonceBytes2, _ := hex.DecodeString("abcd1234abcd1235")
	payload2 := auth.DelegationConsentPayload(nonceBytes2, "alice", "backup-web-01", delPubKeyLine, expiresAt)

	reqPrimary := &backuppbv1.RegisterDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine, ExpiresAt: expiresAt,
		Nonce: nonceBytes2, Signature: signPayload(primarySigner, payload2),
	}
	_, err = srv.RegisterDelegationKey(ctx, reqPrimary)
	if err != nil {
		t.Fatalf("primary sign failed: %v", err)
	}

	// Verify files exist on disk
	fp := middleware.DelegationFingerprint(delPub)
	delDir := filepath.Join(srv.KeysDir, "agent-01", "alice.delegations")
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); err != nil {
		t.Fatalf("delegation pub file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(delDir, fp+".meta")); err != nil {
		t.Fatalf("delegation meta file missing: %v", err)
	}
}

func TestRegisterTaskGrantRequiresDelegationSignature(t *testing.T) {
	srv, ctx, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key and enroll a delegation key
	primaryPub, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	delSigner, _ := ssh.NewSignerFromKey(delPriv)
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

	// Enroll delegation key
	hexNonce := "abcd1234abcd1234"
	nonceBytes, _ := hex.DecodeString(hexNonce)
	insertNonce(t, srv.DB, hexNonce)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	consentPayload := auth.DelegationConsentPayload(nonceBytes, "alice", "backup-web-01", delPubKeyLine, expiresAt)
	reqConsent := &backuppbv1.RegisterDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine, ExpiresAt: expiresAt,
		Nonce: nonceBytes, Signature: signPayload(primarySigner, consentPayload),
	}
	if _, err := srv.RegisterDelegationKey(ctx, reqConsent); err != nil {
		t.Fatalf("enroll delegation: %v", err)
	}

	// Generate ephemeral key
	_, epPriv, _ := ed25519.GenerateKey(rand.Reader)
	epPub, _ := ssh.NewPublicKey(epPriv.Public())
	epPubKeyLine := string(ssh.MarshalAuthorizedKey(epPub))

	// Try signing task grant with primary key → should fail
	hexNonce2 := "abcd1234abcd1235"
	nonceBytes2, _ := hex.DecodeString(hexNonce2)
	insertNonce(t, srv.DB, hexNonce2)
	grantExpires := time.Now().Add(time.Hour).Unix()
	grantPayload := auth.TaskGrantPayload(nonceBytes2, "alice", "PushBackup", epPubKeyLine, grantExpires)

	reqPrimary := &backuppbv1.RegisterTaskGrantRequest{
		Username: "alice", Method: "PushBackup",
		EphemeralPubkey: epPubKeyLine, ExpiresAt: grantExpires,
		Nonce: nonceBytes2, Signature: signPayload(primarySigner, grantPayload),
	}
	_, err := srv.RegisterTaskGrant(ctx, reqPrimary)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for primary key, got: %v", err)
	}

	// Sign with delegation key → should succeed
	hexNonce3 := "abcd1234abcd1236"
	nonceBytes3, _ := hex.DecodeString(hexNonce3)
	insertNonce(t, srv.DB, hexNonce3)
	grantPayload2 := auth.TaskGrantPayload(nonceBytes3, "alice", "PushBackup", epPubKeyLine, grantExpires)

	reqDel := &backuppbv1.RegisterTaskGrantRequest{
		Username: "alice", Method: "PushBackup",
		EphemeralPubkey: epPubKeyLine, ExpiresAt: grantExpires,
		Nonce: nonceBytes3, Signature: signPayload(delSigner, grantPayload2),
	}
	_, err = srv.RegisterTaskGrant(ctx, reqDel)
	if err != nil {
		t.Fatalf("delegation sign failed: %v", err)
	}

	// Verify grant exists in DB
	fp := middleware.DelegationFingerprint(epPub)
	got, err := store.GetTaskGrant(srv.DB, "agent-01", "alice", fp, time.Now())
	if err != nil || got == nil || got.Method != "PushBackup" {
		t.Fatalf("task grant not found: %v %v", got, err)
	}

	_ = primaryPub // silence unused warning if any
}

func TestRemoveDelegationKeyByDelegationKeyItself(t *testing.T) {
	srv, ctx, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key and enroll a delegation key
	_, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	delSigner, _ := ssh.NewSignerFromKey(delPriv)
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

	// Enroll delegation key
	hexNonce := "abcd1234abcd1234"
	nonceBytes, _ := hex.DecodeString(hexNonce)
	insertNonce(t, srv.DB, hexNonce)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	consentPayload := auth.DelegationConsentPayload(nonceBytes, "alice", "backup-web-01", delPubKeyLine, expiresAt)
	reqConsent := &backuppbv1.RegisterDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine, ExpiresAt: expiresAt,
		Nonce: nonceBytes, Signature: signPayload(primarySigner, consentPayload),
	}
	if _, err := srv.RegisterDelegationKey(ctx, reqConsent); err != nil {
		t.Fatalf("enroll delegation: %v", err)
	}

	// Verify files exist
	fp := middleware.DelegationFingerprint(delPub)
	delDir := filepath.Join(srv.KeysDir, "agent-01", "alice.delegations")
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); err != nil {
		t.Fatalf("delegation pub file missing before remove: %v", err)
	}

	// Remove using delegation key signature
	hexNonce2 := "abcd1234abcd1235"
	nonceBytes2, _ := hex.DecodeString(hexNonce2)
	insertNonce(t, srv.DB, hexNonce2)
	removalPayload := auth.DelegationRemovalPayload(nonceBytes2, "alice", "backup-web-01", delPubKeyLine)

	reqRemove := &backuppbv1.RemoveDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine,
		Nonce: nonceBytes2, Signature: signPayload(delSigner, removalPayload),
	}
	_, err := srv.RemoveDelegationKey(ctx, reqRemove)
	if err != nil {
		t.Fatalf("remove by delegation key failed: %v", err)
	}

	// Verify files are gone
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); !os.IsNotExist(err) {
		t.Fatal("delegation pub file should be removed")
	}
	if _, err := os.Stat(filepath.Join(delDir, fp+".meta")); !os.IsNotExist(err) {
		t.Fatal("delegation meta file should be removed")
	}
}

func TestRemoveDelegationKeyByPrimaryKey(t *testing.T) {
	srv, ctx, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key and enroll a delegation key
	_, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

	// Enroll delegation key
	hexNonce := "abcd1234abcd1234"
	nonceBytes, _ := hex.DecodeString(hexNonce)
	insertNonce(t, srv.DB, hexNonce)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	consentPayload := auth.DelegationConsentPayload(nonceBytes, "alice", "backup-web-01", delPubKeyLine, expiresAt)
	reqConsent := &backuppbv1.RegisterDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine, ExpiresAt: expiresAt,
		Nonce: nonceBytes, Signature: signPayload(primarySigner, consentPayload),
	}
	if _, err := srv.RegisterDelegationKey(ctx, reqConsent); err != nil {
		t.Fatalf("enroll delegation: %v", err)
	}

	// Verify files exist
	fp := middleware.DelegationFingerprint(delPub)
	delDir := filepath.Join(srv.KeysDir, "agent-01", "alice.delegations")
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); err != nil {
		t.Fatalf("delegation pub file missing before remove: %v", err)
	}

	// Remove using primary key signature
	hexNonce2 := "abcd1234abcd1235"
	nonceBytes2, _ := hex.DecodeString(hexNonce2)
	insertNonce(t, srv.DB, hexNonce2)
	removalPayload := auth.DelegationRemovalPayload(nonceBytes2, "alice", "backup-web-01", delPubKeyLine)

	reqRemove := &backuppbv1.RemoveDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine,
		Nonce: nonceBytes2, Signature: signPayload(primarySigner, removalPayload),
	}
	_, err := srv.RemoveDelegationKey(ctx, reqRemove)
	if err != nil {
		t.Fatalf("remove by primary key failed: %v", err)
	}

	// Verify files are gone
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); !os.IsNotExist(err) {
		t.Fatal("delegation pub file should be removed")
	}
	if _, err := os.Stat(filepath.Join(delDir, fp+".meta")); !os.IsNotExist(err) {
		t.Fatal("delegation meta file should be removed")
	}
}

func TestRemoveDelegationKeyRejectsUnrelatedKey(t *testing.T) {
	srv, ctx, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key and enroll a delegation key
	_, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

	// Enroll delegation key
	hexNonce := "abcd1234abcd1234"
	nonceBytes, _ := hex.DecodeString(hexNonce)
	insertNonce(t, srv.DB, hexNonce)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	consentPayload := auth.DelegationConsentPayload(nonceBytes, "alice", "backup-web-01", delPubKeyLine, expiresAt)
	reqConsent := &backuppbv1.RegisterDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine, ExpiresAt: expiresAt,
		Nonce: nonceBytes, Signature: signPayload(primarySigner, consentPayload),
	}
	if _, err := srv.RegisterDelegationKey(ctx, reqConsent); err != nil {
		t.Fatalf("enroll delegation: %v", err)
	}

	// Verify files exist
	fp := middleware.DelegationFingerprint(delPub)
	delDir := filepath.Join(srv.KeysDir, "agent-01", "alice.delegations")
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); err != nil {
		t.Fatalf("delegation pub file missing before remove: %v", err)
	}

	// Generate unrelated key
	_, unrelatedPriv, _ := ed25519.GenerateKey(rand.Reader)
	unrelatedSigner, _ := ssh.NewSignerFromKey(unrelatedPriv)

	// Attempt removal using unrelated key signature
	hexNonce2 := "abcd1234abcd1235"
	nonceBytes2, _ := hex.DecodeString(hexNonce2)
	insertNonce(t, srv.DB, hexNonce2)
	removalPayload := auth.DelegationRemovalPayload(nonceBytes2, "alice", "backup-web-01", delPubKeyLine)

	reqRemove := &backuppbv1.RemoveDelegationKeyRequest{
		Username: "alice", GatewayCn: "backup-web-01",
		DelegationPubkey: delPubKeyLine,
		Nonce: nonceBytes2, Signature: signPayload(unrelatedSigner, removalPayload),
	}
	_, err := srv.RemoveDelegationKey(ctx, reqRemove)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for unrelated key, got: %v", err)
	}

	// Verify files still exist
	if _, err := os.Stat(filepath.Join(delDir, fp+".pub")); err != nil {
		t.Fatal("delegation pub file should still exist")
	}
	if _, err := os.Stat(filepath.Join(delDir, fp+".meta")); err != nil {
		t.Fatal("delegation meta file should still exist")
	}
}
