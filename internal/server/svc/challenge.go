package svc

import (
	"context"
	"fmt"
	"time"

	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetChallenge generates a cryptographic nonce and returns it with a 5-minute expiry.
// The caller must sign this nonce with their SSH key to authenticate subsequent RPCs.
func (s *BackupServer) GetChallenge(ctx context.Context, req *backuppbv1.GetChallengeRequest) (*backuppbv1.Challenge, error) {
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate nonce")
	}

	expiresAt := time.Now().Add(5 * time.Minute)
	if err := store.InsertNonce(s.DB, fmt.Sprintf("%x", nonce), expiresAt); err != nil {
		return nil, status.Error(codes.Internal, "failed to store nonce")
	}

	return &backuppbv1.Challenge{
		Nonce:     nonce,
		ExpiresAt: expiresAt.Unix(),
	}, nil
}
