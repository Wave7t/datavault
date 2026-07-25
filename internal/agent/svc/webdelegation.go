package svc

import (
	"context"
	"time"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnrollWebDelegation records a user's consent for a gateway to act on their
// behalf. The Server is updated first (it holds the consent signature as
// proof); the local record is written only after Server success.
func (s *AgentService) EnrollWebDelegation(ctx context.Context, req *agentpbv1.EnrollWebDelegationRequest) (*agentpbv1.EnrollWebDelegationResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if s.Cfg == nil || s.Cfg.HTTPSAPI == nil {
		return nil, status.Error(codes.FailedPrecondition, "https_api is not configured")
	}
	api := s.Cfg.HTTPSAPI
	if !gatewayCNAllowed(api.GatewayCNs, req.GatewayCn) {
		return nil, status.Error(codes.InvalidArgument, "gateway is not allowlisted")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.DelegationPubkey)); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid delegation public key")
	}
	if req.TtlSeconds <= 0 || time.Duration(req.TtlSeconds)*time.Second > api.DelegationTTL {
		return nil, status.Errorf(codes.InvalidArgument, "ttl must be between 1s and %v", api.DelegationTTL)
	}
	if s.RegisterDelegationKeyFn == nil {
		return nil, status.Error(codes.Unimplemented, "delegation registration not configured")
	}
	expiresAt := time.Now().Add(time.Duration(req.TtlSeconds) * time.Second).Unix()
	if err := s.RegisterDelegationKeyFn(req.Server, username, req.GatewayCn, req.DelegationPubkey, expiresAt, req.Nonce, req.Signature); err != nil {
		return nil, status.Errorf(codes.Internal, "register delegation key at server: %v", err)
	}
	if err := store.UpsertWebDelegation(s.DB, store.WebDelegation{
		Username:         username,
		GatewayCN:        req.GatewayCn,
		DelegationPubKey: req.DelegationPubkey,
		ExpiresAt:        time.Unix(expiresAt, 0),
		CreatedAt:        time.Now(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "record delegation: %v", err)
	}
	return &agentpbv1.EnrollWebDelegationResponse{ExpiresAt: expiresAt}, nil
}

// RevokeWebDelegation removes a delegation. Local revocation always takes
// effect; Server removal is attempted first and a failure only logs (the
// delegation expires at the Server on its own, and operators can remove the
// key file manually during incident response).
func (s *AgentService) RevokeWebDelegation(ctx context.Context, req *agentpbv1.RevokeWebDelegationRequest) (*agentpbv1.RevokeWebDelegationResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	d, err := store.GetWebDelegation(s.DB, username, req.GatewayCn)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load delegation: %v", err)
	}
	if d == nil || d.RevokedAt != nil {
		return nil, status.Error(codes.NotFound, "no active delegation for gateway")
	}
	if s.RemoveDelegationKeyFn != nil {
		// Best effort: failure is logged by the caller (CLI prints a warning).
		_ = s.RemoveDelegationKeyFn(req.Server, username, req.GatewayCn, d.DelegationPubKey, req.Nonce, req.Signature)
	}
	if err := store.RevokeWebDelegation(s.DB, username, req.GatewayCn); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke delegation: %v", err)
	}
	return &agentpbv1.RevokeWebDelegationResponse{}, nil
}

func (s *AgentService) ListWebDelegations(ctx context.Context, req *agentpbv1.ListWebDelegationsRequest) (*agentpbv1.ListWebDelegationsResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	list, err := store.ListWebDelegations(s.DB, username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list delegations: %v", err)
	}
	resp := &agentpbv1.ListWebDelegationsResponse{}
	for _, d := range list {
		resp.Delegations = append(resp.Delegations, &agentpbv1.WebDelegation{
			GatewayCn:        d.GatewayCN,
			DelegationPubkey: d.DelegationPubKey,
			ExpiresAt:        d.ExpiresAt.Unix(),
			Revoked:          d.RevokedAt != nil,
		})
	}
	return resp, nil
}

func gatewayCNAllowed(allowed []string, cn string) bool {
	for _, a := range allowed {
		if a == cn {
			return true
		}
	}
	return false
}
