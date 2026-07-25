package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/datavault/internal/agent/httpsapi"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/pki"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
)

func TestQuotaWarningReached(t *testing.T) {
	for _, test := range []struct {
		used, quota, percent int64
		want                 bool
	}{
		{89, 100, 90, false},
		{90, 100, 90, true},
		{1, 3, 34, false},
		{2, 3, 34, true},
		{100, 0, 90, false},
	} {
		if got := quotaWarningReached(test.used, test.quota, test.percent); got != test.want {
			t.Fatalf("quotaWarningReached(%d,%d,%d)=%v, want %v", test.used, test.quota, test.percent, got, test.want)
		}
	}
}

// writeTestPKI materializes a CA, a server cert (with 127.0.0.1 SAN) for the
// HTTPS listener, and two client certs (allowlisted CN and a stranger CN).
// All certs are signed by the same freshly generated CA, whose key is kept on
// disk so additional client certs can be issued via pki.Issue.
type testPKI struct {
	caPath string

	serverCertPath string
	serverKeyPath  string

	allowedCertPath string
	allowedKeyPath  string

	strangerCertPath string
	strangerKeyPath  string
}

func writeTestPKI(t *testing.T, dir string, allowedCN, strangerCN string) testPKI {
	t.Helper()
	caCert, caKey, err := pki.CreateCA(pki.CAOptions{CommonName: "datavault test CA", ValidFor: time.Hour})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	serverCert, serverKey, err := pki.Issue(caCert, caKey, pki.IssueOptions{
		CommonName:  "agent.localhost",
		Server:      true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ValidFor:    time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue server: %v", err)
	}
	allowedCert, allowedKey, err := pki.Issue(caCert, caKey, pki.IssueOptions{
		CommonName: allowedCN, Client: true, ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue allowed client: %v", err)
	}
	strangerCert, strangerKey, err := pki.Issue(caCert, caKey, pki.IssueOptions{
		CommonName: strangerCN, Client: true, ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue stranger client: %v", err)
	}
	p := testPKI{
		caPath:           filepath.Join(dir, "ca.pem"),
		serverCertPath:   filepath.Join(dir, "server.crt"),
		serverKeyPath:    filepath.Join(dir, "server.key"),
		allowedCertPath:  filepath.Join(dir, "allowed.crt"),
		allowedKeyPath:   filepath.Join(dir, "allowed.key"),
		strangerCertPath: filepath.Join(dir, "stranger.crt"),
		strangerKeyPath:  filepath.Join(dir, "stranger.key"),
	}
	writeFile(t, p.caPath, caCert)
	writeFile(t, p.serverCertPath, serverCert)
	writeFile(t, p.serverKeyPath, serverKey)
	writeFile(t, p.allowedCertPath, allowedCert)
	writeFile(t, p.allowedKeyPath, allowedKey)
	writeFile(t, p.strangerCertPath, strangerCert)
	writeFile(t, p.strangerKeyPath, strangerKey)
	return p
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestHTTPSAPIStartsOnlyWhenConfigured asserts:
//  1. With cfg.HTTPSAPI == nil, startHTTPSAPI returns (nil, nil) and never
//     opens a listener.
//  2. With cfg.HTTPSAPI configured with real PKI, the listener comes up and
//     enforces mTLS: a client without a cert fails the handshake, and a cert
//     whose CN is not allowlisted is rejected with 401.
func TestHTTPSAPIStartsOnlyWhenConfigured(t *testing.T) {
	// Case 1: no https_api -> (nil, nil), no listener.
	cfg := &config.AgentConfig{HTTPSAPI: nil}
	srv, err := startHTTPSAPI(cfg, httpsapi.Deps{})
	if err != nil {
		t.Fatalf("nil config: %v", err)
	}
	if srv != nil {
		t.Fatalf("nil config should return (nil, nil), got %v", srv)
	}

	// Case 2: configured https_api with real PKI.
	dir := t.TempDir()
	pki := writeTestPKI(t, dir, "gateway-allowed", "gateway-stranger")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	// Pre-bind a free TCP port so the test is deterministic; pass it to the
	// config so ListenAndServe does not race on :0 ephemeral port lookup.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind listener: %v", err)
	}
	addr := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("close pre-bind listener: %v", err)
	}

	cfg2 := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:        addr,
			CertFile:      pki.serverCertPath,
			KeyFile:       pki.serverKeyPath,
			CAFile:        pki.caPath,
			GatewayCNs:    []string{"gateway-allowed"},
			DelegationTTL: 24 * time.Hour,
			MinUID:        0,
		},
	}
	srv, err = startHTTPSAPI(cfg2, httpsapi.Deps{
		Cfg:           cfg2,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(dir),
	})
	if err != nil {
		t.Fatalf("startHTTPSAPI configured: %v", err)
	}
	if srv == nil {
		t.Fatal("configured https_api should return a non-nil server")
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(pki.caPath)
	if err != nil {
		t.Fatal(err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load CA into pool")
	}

	// Negative 1: no client cert -> TLS handshake fails.
	noCertClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13},
		},
	}
	if _, err := noCertClient.Get("https://" + addr + "/v1/health"); err == nil {
		t.Fatal("expected TLS handshake failure without client cert")
	}

	// Negative 2: client cert whose CN is not allowlisted -> 401.
	strangerPair, err := tls.LoadX509KeyPair(pki.strangerCertPath, pki.strangerKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{strangerPair},
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
	resp, err := wrongClient.Get("https://" + addr + "/v1/health")
	if err != nil {
		t.Fatalf("stranger CN request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stranger CN: expected 401, got %d", resp.StatusCode)
	}

	// Positive: allowlisted client cert reaches a handler (proves mTLS passed).
	allowedPair, err := tls.LoadX509KeyPair(pki.allowedCertPath, pki.allowedKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	allowedClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{allowedPair},
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
	resp, err = allowedClient.Get("https://" + addr + "/v1/health")
	if err != nil {
		t.Fatalf("allowed client request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("allowed CN got 401, expected to pass mTLS gate")
	}
}
