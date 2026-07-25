package svc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/auth"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestQuotaSignatureAcceptsDelegationKey(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key for alice
	_, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")

	// Generate and enroll a delegation key
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	delSigner, _ := ssh.NewSignerFromKey(delPriv)
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

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
	ctx := middleware.ContextWithHostname(context.Background(), "agent-01")
	if _, err := srv.RegisterDelegationKey(ctx, reqConsent); err != nil {
		t.Fatalf("enroll delegation: %v", err)
	}

	// Build a quota request signed by the delegation key
	hexNonce2 := "abcd1234abcd1235"
	nonceBytes2, _ := hex.DecodeString(hexNonce2)
	insertNonce(t, srv.DB, hexNonce2)

	req := &backuppbv1.GetQuotaUsageRequest{
		Username:  "alice",
		Nonce:     nonceBytes2,
		Signature: nil,
	}
	payload, _ := auth.ServerRequestPayload("GetQuotaUsage", nonceBytes2, req)
	req.Signature = signPayload(delSigner, payload)

	// Should succeed with delegation key
	if err := srv.verifyQuotaSignature("agent-01", req); err != nil {
		t.Fatalf("delegation key signature rejected: %v", err)
	}

	// Sign with unrelated key → should fail
	_, unrelatedPriv, _ := ed25519.GenerateKey(rand.Reader)
	unrelatedSigner, _ := ssh.NewSignerFromKey(unrelatedPriv)
	req.Signature = signPayload(unrelatedSigner, payload)

	if err := srv.verifyQuotaSignature("agent-01", req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for unrelated key, got: %v", err)
	}
}
