package svc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestValidateBackupIdentity(t *testing.T) {
	tests := []struct {
		name  string
		batch *backuppbv1.BackupBatch
		code  codes.Code
	}{
		{name: "user", batch: &backuppbv1.BackupBatch{Username: "alice", RuleType: "user"}, code: codes.OK},
		{name: "machine", batch: &backuppbv1.BackupBatch{Username: "_machine", RuleType: "machine"}, code: codes.OK},
		{name: "unknown rule", batch: &backuppbv1.BackupBatch{Username: "alice", RuleType: "admin"}, code: codes.InvalidArgument},
		{name: "user machine dataset", batch: &backuppbv1.BackupBatch{Username: "_machine", RuleType: "user"}, code: codes.PermissionDenied},
		{name: "machine user dataset", batch: &backuppbv1.BackupBatch{Username: "alice", RuleType: "machine"}, code: codes.PermissionDenied},
		{name: "machine credentials", batch: &backuppbv1.BackupBatch{Username: "_machine", RuleType: "machine", Nonce: []byte("nonce")}, code: codes.InvalidArgument},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateBackupIdentity(test.batch)
			if got := status.Code(err); got != test.code {
				t.Fatalf("status code = %v, want %v (err=%v)", got, test.code, err)
			}
		})
	}
}

func buildBatchPayload(batch *backuppbv1.BackupBatch) []byte {
	batchForHash := proto.Clone(batch).(*backuppbv1.BackupBatch)
	batchForHash.Signature = nil
	batchForHash.Nonce = nil
	batchForHash.SignerPubkey = nil

	payload := append(batch.Nonce, []byte("PushBackup")...)
	batchHash := sha256.Sum256(mustMarshal(batchForHash))
	payload = append(payload, batchHash[:]...)
	return payload
}

func TestBatchSignatureAcceptsGrantedEphemeralKey(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	// Write primary key for alice (needed for the delegation enrollment)
	_, primarySigner := writePrimaryKey(t, srv.KeysDir, "agent-01", "alice")

	// Generate and enroll a delegation key
	_, delPriv, _ := ed25519.GenerateKey(rand.Reader)
	delPub, _ := ssh.NewPublicKey(delPriv.Public())
	_ = delPub
	delSigner, _ := ssh.NewSignerFromKey(delPriv)
	_ = delSigner
	delPubKeyLine := string(ssh.MarshalAuthorizedKey(delPub))

	// Enroll delegation key via RegisterDelegationKey
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

	// Generate ephemeral key
	_, epPriv, _ := ed25519.GenerateKey(rand.Reader)
	epPub, _ := ssh.NewPublicKey(epPriv.Public())
	epSigner, _ := ssh.NewSignerFromKey(epPriv)

	// Insert task grant for the ephemeral key with method "PushBackup"
	fp := middleware.DelegationFingerprint(epPub)
	grant := store.TaskGrant{
		Hostname:             "agent-01",
		Username:             "alice",
		Method:               "PushBackup",
		EphemeralFingerprint: fp,
		EphemeralPubKey:      string(ssh.MarshalAuthorizedKey(epPub)),
		ExpiresAt:            time.Now().Add(time.Hour),
	}
	if err := store.InsertTaskGrant(srv.DB, grant); err != nil {
		t.Fatalf("insert task grant: %v", err)
	}

	// Build batch signed by ephemeral key with SignerPubkey set
	hexNonce2 := "abcd1234abcd1235"
	nonceBytes2, _ := hex.DecodeString(hexNonce2)
	insertNonce(t, srv.DB, hexNonce2)

	batch := &backuppbv1.BackupBatch{
		Username:     "alice",
		RuleType:     "user",
		Nonce:        nonceBytes2,
		SignerPubkey: epPub.Marshal(),
	}
	payload := buildBatchPayload(batch)
	batch.Signature = signPayload(epSigner, payload)

	// Should succeed with valid grant and matching ephemeral key
	if err := srv.verifyBatchSignature("agent-01", batch); err != nil {
		t.Fatalf("ephemeral key signature rejected: %v", err)
	}

	// Negative: same signature but no grant row → Unauthenticated
	batch2 := &backuppbv1.BackupBatch{
		Username:     "alice",
		RuleType:     "user",
		Nonce:        nonceBytes2,
		SignerPubkey: epPub.Marshal(),
		Signature:    batch.Signature,
	}
	// Delete the grant
	if _, err := srv.DB.Exec("DELETE FROM task_grants"); err != nil {
		t.Fatalf("delete grants: %v", err)
	}
	if err := srv.verifyBatchSignature("agent-01", batch2); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without grant, got: %v", err)
	}

	// Negative: grant exists but SignerPubkey is a different key → Unauthenticated
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(otherPriv.Public())
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)

	// Re-insert grant for the original ephemeral key
	if err := store.InsertTaskGrant(srv.DB, grant); err != nil {
		t.Fatalf("re-insert task grant: %v", err)
	}

	batch3 := &backuppbv1.BackupBatch{
		Username:     "alice",
		RuleType:     "user",
		Nonce:        nonceBytes2,
		SignerPubkey: otherPub.Marshal(), // different key
	}
	payload3 := buildBatchPayload(batch3)
	batch3.Signature = signPayload(otherSigner, payload3)

	if err := srv.verifyBatchSignature("agent-01", batch3); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for different key, got: %v", err)
	}
}
