package auth

import (
	"crypto/sha256"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ServerRequestPayload builds the canonical bytes a user (or delegated
// gateway) signs for a Server RPC: nonce || method || sha256(request),
// where the request is marshalled with nonce and signature cleared. This
// matches the Server-side verification exactly; all constructors and
// verifiers must use this single implementation.
func ServerRequestPayload(method string, nonce []byte, req proto.Message) ([]byte, error) {
	clone := proto.Clone(req)
	clearField(clone, "nonce")
	clearField(clone, "signature")
	data, err := proto.Marshal(clone)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	payload := make([]byte, 0, len(nonce)+len(method)+sha256.Size)
	payload = append(payload, nonce...)
	payload = append(payload, []byte(method)...)
	return append(payload, hash[:]...), nil
}

// clearField zeroes a scalar field by name using protobuf reflection.
func clearField(m proto.Message, name string) {
	fd := m.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd != nil {
		m.ProtoReflect().Clear(fd)
	}
}

// statementPayload builds nonce || method || sha256(fields joined by NUL).
func statementPayload(nonce []byte, method string, fields ...string) []byte {
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	payload := make([]byte, 0, len(nonce)+len(method)+sha256.Size)
	payload = append(payload, nonce...)
	payload = append(payload, []byte(method)...)
	return append(payload, sum[:]...)
}

// DelegationConsentPayload is what a user's primary SSH key signs to enroll
// a gateway delegation key at the Server.
func DelegationConsentPayload(nonce []byte, username, gatewayCN, delegationPubKey string, expiresAt int64) []byte {
	return statementPayload(nonce, "RegisterDelegationKey", username, gatewayCN, delegationPubKey, strconv.FormatInt(expiresAt, 10))
}

// DelegationRemovalPayload is signed by the user's primary key, or by the
// delegation key itself, to remove a delegation.
func DelegationRemovalPayload(nonce []byte, username, gatewayCN, delegationPubKey string) []byte {
	return statementPayload(nonce, "RemoveDelegationKey", username, gatewayCN, delegationPubKey)
}

// TaskGrantPayload is signed by a gateway delegation key to authorize one
// ephemeral task key for one sync method.
func TaskGrantPayload(nonce []byte, username, method, ephemeralPubKey string, expiresAt int64) []byte {
	return statementPayload(nonce, "RegisterTaskGrant", username, method, ephemeralPubKey, strconv.FormatInt(expiresAt, 10))
}
