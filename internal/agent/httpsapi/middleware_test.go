package httpsapi

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os/user"
	"testing"
	"time"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
)

func TestGateGatewayCNAllowlist(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	s := mustServer(t, db)

	// CN not in gateway_cns -> 401 unauthorized
	req := httptest.NewRequest(http.MethodGet, "/v1/users/testuser/rules", nil)
	req.SetPathValue("user", "testuser")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "bad-cn"}}},
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad CN, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !contains(body, `"code":"unauthorized"`) {
		t.Fatalf("expected unauthorized code in body, got %s", body)
	}
}

func TestGateUsernameValidation(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	s := mustServer(t, db)
	goodCN := "gateway1"

	cases := []struct {
		name string
		user string
	}{
		{"root user", "root"},
		{"invalid username", "no such user!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/users/invalid/rules", nil)
			req.SetPathValue("user", tc.user)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: goodCN}}},
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for invalid user %q, got %d", tc.user, rr.Code)
			}
			body := rr.Body.String()
			if !contains(body, `"code":"delegation_required"`) {
				t.Fatalf("expected delegation_required code in body, got %s", body)
			}
		})
	}
}

func TestGateDelegationRequired(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	// Use current user and min_uid=0 so user lookup passes
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gateway1"},
			MinUID:     0,
		},
	}
	s, err := NewServer(Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
	})
	if err != nil {
		t.Fatal(err)
	}

	goodCN := "gateway1"
	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+cur.Username+"/rules", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: goodCN}}},
		}
		req.SetPathValue("user", cur.Username)
		return req
	}

	// No delegation row -> 403
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, makeReq())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing delegation, got %d", rr.Code)
	}

	// Expired row -> still 403
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        goodCN,
		DelegationPubKey: "pk1",
		ExpiresAt:        time.Now().Add(-time.Hour),
		CreatedAt:        time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, makeReq())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired delegation, got %d", rr.Code)
	}

	// Revoked row -> still 403
	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        goodCN,
		DelegationPubKey: "pk2",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeWebDelegation(db, cur.Username, goodCN); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, makeReq())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked delegation, got %d", rr.Code)
	}

	// Active row -> passes gate (empty mux returns 404)
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        goodCN,
		DelegationPubKey: "pk3",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, makeReq())
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("expected to pass gates (not 401/403), got %d", rr.Code)
	}
}

func mustServer(t *testing.T, db *sql.DB) *Server {
	t.Helper()
	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gateway1"},
			MinUID:     1000,
		},
	}
	s, err := NewServer(Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
