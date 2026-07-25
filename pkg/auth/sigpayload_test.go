package auth

import (
	"bytes"
	"crypto/sha256"
	"testing"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/protobuf/proto"
)

func TestServerRequestPayloadMatchesLegacyFormat(t *testing.T) {
	nonce := []byte("0123456789abcdef")
	req := &backuppbv1.GetQuotaUsageRequest{Username: "alice"}
	got, err := ServerRequestPayload("GetQuotaUsage", nonce, req)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	// Legacy construction, copied from pre-refactor cmd/dvault signServerRequest.
	clone := proto.Clone(req).(*backuppbv1.GetQuotaUsageRequest)
	clone.Signature = nil
	clone.Nonce = nil
	data, _ := proto.Marshal(clone)
	hash := sha256.Sum256(data)
	want := append(append(append([]byte{}, nonce...), []byte("GetQuotaUsage")...), hash[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestStatementPayloadsAreMethodBound(t *testing.T) {
	nonce := []byte("n")
	a := DelegationConsentPayload(nonce, "alice", "gw", "ssh-ed25519 AAAA", 100)
	b := DelegationConsentPayload(nonce, "alice", "gw", "ssh-ed25519 AAAA", 101)
	c := DelegationRemovalPayload(nonce, "alice", "gw", "ssh-ed25519 AAAA")
	d := TaskGrantPayload(nonce, "alice", "PushBackup", "ssh-ed25519 BBBB", 100)
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, d) || bytes.Equal(c, d) {
		t.Fatal("payloads must differ across fields and methods")
	}
}
