package httpsapi

import (
	"testing"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
)

func TestNewServerNilConfig(t *testing.T) {
	_, err := NewServer(Deps{})
	if err == nil {
		t.Fatal("expected error for nil Cfg.HTTPSAPI")
	}
}

func TestNewServerNilDB(t *testing.T) {
	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gw"},
		},
	}
	_, err := NewServer(Deps{Cfg: cfg})
	if err == nil {
		t.Fatal("expected error for nil DB")
	}
}

func TestNewServerNilUserRuleStore(t *testing.T) {
	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gw"},
		},
	}
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = NewServer(Deps{Cfg: cfg, DB: db})
	if err == nil {
		t.Fatal("expected error for nil UserRuleStore")
	}
}

func TestHandlerReturnsHandler(t *testing.T) {
	cfg := &config.AgentConfig{
		HTTPSAPI: &config.HTTPSAPIConfig{
			Listen:     ":0",
			CertFile:   "/dev/null",
			KeyFile:    "/dev/null",
			CAFile:     "/dev/null",
			GatewayCNs: []string{"gw"},
		},
	}
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewServer(Deps{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: rules.NewUserRuleStore(t.TempDir()),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}
}
