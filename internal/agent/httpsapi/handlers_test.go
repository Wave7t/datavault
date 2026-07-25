package httpsapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"testing"
	"time"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
)

// makeRequest builds an authenticated request for the current OS user with a
// fake TLS state (reused from middleware_test.go patterns).
func makeRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "gateway1"}}},
	}
	// Extract username from path if present
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "users" && i+1 < len(parts) {
			req.SetPathValue("user", parts[i+1])
			break
		}
	}
	// Also set path values for named route segments
	for i, p := range parts {
		if p == "rules" && i+1 < len(parts) && parts[i+1] != "" {
			req.SetPathValue("name", parts[i+1])
		}
		if p == "syncs" && i+1 < len(parts) && parts[i+1] != "" {
			req.SetPathValue("task", parts[i+1])
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	_ = cur // used for skip check
	return req
}

func mustServerWithDeps(t *testing.T, deps Deps) *Server {
	t.Helper()
	s, err := NewServer(deps)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRulesCRUDOverHTTPS(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	// Insert active delegation for current user
	now := time.Now()
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "gateway1",
		DelegationPubKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK/XCUj4i6Q5yQJNL1MGj9n2sQ0 test",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
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
	ruleStore := rules.NewUserRuleStore(t.TempDir())
	s := mustServerWithDeps(t, Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: ruleStore,
	})

	// POST add rule
	path := "/v1/users/" + cur.Username + "/rules"
	reqBody := []byte(`{"name":"proj","paths":["` + cur.HomeDir + `/x"]}`)
	req := makeRequest(t, http.MethodPost, path, reqBody)
	req.SetPathValue("user", cur.Username)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for add rule, got %d: %s", rr.Code, rr.Body.String())
	}

	// GET list rules -> contains proj
	req = makeRequest(t, http.MethodGet, path, nil)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for list rules, got %d: %s", rr.Code, rr.Body.String())
	}
	var listResp struct {
		Rules []struct {
			Name    string   `json:"name"`
			Paths   []string `json:"paths"`
			Exclude []string `json:"exclude"`
			Enabled bool     `json:"enabled"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range listResp.Rules {
		if r.Name == "proj" {
			found = true
			if !r.Enabled {
				t.Fatal("expected rule to be enabled")
			}
		}
	}
	if !found {
		t.Fatal("expected proj in rules list")
	}

	// POST same name -> 409
	req = makeRequest(t, http.MethodPost, path, reqBody)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate rule, got %d: %s", rr.Code, rr.Body.String())
	}

	// POST disable
	disablePath := path + "/proj/disable"
	req = makeRequest(t, http.MethodPost, disablePath, nil)
	req.SetPathValue("user", cur.Username)
	req.SetPathValue("name", "proj")
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for disable, got %d: %s", rr.Code, rr.Body.String())
	}

	// GET -> enabled=false
	req = makeRequest(t, http.MethodGet, path, nil)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	for _, r := range listResp.Rules {
		if r.Name == "proj" && r.Enabled {
			t.Fatal("expected proj to be disabled")
		}
	}

	// DELETE rule
	delPath := path + "/proj"
	req = makeRequest(t, http.MethodDelete, delPath, nil)
	req.SetPathValue("user", cur.Username)
	req.SetPathValue("name", "proj")
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for delete, got %d: %s", rr.Code, rr.Body.String())
	}

	// GET -> absent
	req = makeRequest(t, http.MethodGet, path, nil)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	for _, r := range listResp.Rules {
		if r.Name == "proj" {
			t.Fatal("expected proj to be absent after delete")
		}
	}

	// POST with path outside $HOME -> 400
	badBody := []byte(`{"name":"bad","paths":["/etc"]}`)
	req = makeRequest(t, http.MethodPost, path, badBody)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for path outside home, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestStatusJSONAndDelegationRead(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user:", err)
	}

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateWebDelegations(db); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	delPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK/XCUj4i6Q5yQJNL1MGj9n2sQ0 test"
	if err := store.UpsertWebDelegation(db, store.WebDelegation{
		Username:         cur.Username,
		GatewayCN:        "gateway1",
		DelegationPubKey: delPubKey,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
	}); err != nil {
		t.Fatal(err)
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

	fakeStatus := &agentpbv1.SyncStatusUpdate{
		TaskId: "task-1",
		Phase:  "SCANNING",
		Stats: &agentpbv1.SyncStats{
			TotalFiles:       10,
			ScannedFiles:     5,
			ChangedFiles:     2,
			TransferredFiles: 1,
			TransferredBytes: 1024,
			CurrentRateBps:   100,
		},
	}

	s := mustServerWithDeps(t, Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
		GetStatusFn: func(username, taskID string) (*agentpbv1.SyncStatusUpdate, error) {
			if taskID == "task-1" {
				return fakeStatus, nil
			}
			return nil, nil // task not found
		},
	})

	// GET sync status
	statusPath := "/v1/users/" + cur.Username + "/syncs/task-1"
	req := makeRequest(t, http.MethodGet, statusPath, nil)
	req.SetPathValue("user", cur.Username)
	req.SetPathValue("task", "task-1")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for sync status, got %d: %s", rr.Code, rr.Body.String())
	}
	var statusResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	if statusResp["task_id"] != "task-1" {
		t.Fatalf("expected task_id task-1, got %v", statusResp["task_id"])
	}
	if statusResp["phase"] != "SCANNING" {
		t.Fatalf("expected phase SCANNING, got %v", statusResp["phase"])
	}
	stats, ok := statusResp["stats"].(map[string]any)
	if !ok {
		t.Fatal("expected stats map")
	}
	if stats["total_files"].(float64) != 10 {
		t.Fatalf("expected total_files 10, got %v", stats["total_files"])
	}

	// GET delegation
	delegationPath := "/v1/users/" + cur.Username + "/delegation"
	req = makeRequest(t, http.MethodGet, delegationPath, nil)
	req.SetPathValue("user", cur.Username)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for delegation, got %d: %s", rr.Code, rr.Body.String())
	}
	var delResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &delResp); err != nil {
		t.Fatal(err)
	}
	if delResp["gateway_cn"] != "gateway1" {
		t.Fatalf("expected gateway_cn gateway1, got %v", delResp["gateway_cn"])
	}
	if delResp["delegation_pubkey"] != delPubKey {
		t.Fatalf("expected delegation_pubkey to match, got %v", delResp["delegation_pubkey"])
	}
}
