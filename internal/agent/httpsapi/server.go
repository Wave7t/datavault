// Package httpsapi exposes the datavault agent to allowlisted web gateways
// over mutually authenticated HTTPS. Every request must present a
// CA-issued client certificate whose CN is configured in
// https_api.gateway_cns, and the addressed Unix user must hold an active
// delegation for that gateway (see dvault web enroll).
package httpsapi

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/tlsconfig"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"golang.org/x/crypto/ssh"
)

// Deps holds the dependencies required by the HTTPS API server.
type Deps struct {
	Cfg           *config.AgentConfig // HTTPSAPI must be non-nil
	DB            *sql.DB
	UserRuleStore *rules.UserRuleStore

	GetAuthChallengeFn    func() (*agentpbv1.AuthChallenge, error)
	GetStatusFn           func(username, taskID string) (*agentpbv1.SyncStatusUpdate, error)
	GetQuotaUsageFn       func(username, server string, nonce, signature []byte) (*agentpbv1.QuotaUsage, error)
	RequestRestoreFn      func(username string, uid uint32, targetPath, server string, nonce, signature []byte) (string, error)
	RunSyncWithTaskKeyFn  func(username, ruleName string, taskKey ssh.Signer) (string, error)
	RegisterTaskGrantFn   func(server, username, method, ephemeralPubKey string, expiresAt int64, nonce, signature []byte) error
	RemoveDelegationKeyFn func(server, username, gatewayCN, delegationPubKey string, nonce, signature []byte) error

	Logger *log.Logger // nil = log.Default()
}

// Server is the HTTPS gateway API. It shares the agent's orchestrator and
// stores through Deps and never trusts caller-supplied identity.
type Server struct {
	deps           Deps
	mux            *http.ServeMux
	httpSrv        *http.Server
	gatewayLimiter *rateLimiter
	userLimiter    *rateLimiter
}

func NewServer(deps Deps) (*Server, error) {
	if deps.Cfg == nil || deps.Cfg.HTTPSAPI == nil {
		return nil, fmt.Errorf("https_api config is required")
	}
	if deps.DB == nil || deps.UserRuleStore == nil {
		return nil, fmt.Errorf("db and user rule store are required")
	}
	s := &Server{
		deps:           deps,
		mux:            http.NewServeMux(),
		gatewayLimiter: newRateLimiter(100, 200),
		userLimiter:    newRateLimiter(10.0/60.0, 10), // 10 write ops per minute per user
	}
	s.routes()
	return s, nil
}

func (s *Server) log() *log.Logger {
	if s.deps.Logger != nil {
		return s.deps.Logger
	}
	return log.Default()
}

// Handler returns the root handler (middleware chain + mux). Used by
// ListenAndServe and by tests via httptest.
func (s *Server) Handler() http.Handler {
	return s.gate(s.mux)
}

// ListenAndServe starts the mTLS listener. It blocks until the server stops.
func (s *Server) ListenAndServe() error {
	api := s.deps.Cfg.HTTPSAPI
	clientCA, err := tlsconfig.LoadCertPool(api.CAFile)
	if err != nil {
		return fmt.Errorf("load gateway CA: %w", err)
	}
	s.httpSrv = &http.Server{
		Addr:              api.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // SSE streams are long-lived; per-request deadlines handled in handlers
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCA,
			Certificates: nil, // loaded from files below
		},
	}
	return s.httpSrv.ListenAndServeTLS(api.CertFile, api.KeyFile)
}

// Shutdown gracefully stops the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// routes wires the HTTP handlers. Task 12 replaces this stub.
func (s *Server) routes() {}
