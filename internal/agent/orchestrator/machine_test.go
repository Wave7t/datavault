package orchestrator

import (
	"path/filepath"
	"testing"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
)

func TestRunSyncRejectsMissingServers(t *testing.T) {
	o := New(&config.AgentConfig{}, nil, nil, nil)
	if _, err := o.RunSync("_machine", ""); err == nil {
		t.Fatal("expected sync without servers to fail")
	}
}

func TestRunSyncRejectsUserWithoutCallerSigner(t *testing.T) {
	o := New(&config.AgentConfig{Servers: []config.ServerEntry{{Address: "server:8443"}}}, nil, nil, nil)
	if _, err := o.RunSync("alice", ""); err == nil {
		t.Fatal("expected user sync without caller signer to fail")
	}
}

func TestMachineRulesFromConfigFiltersEnabled(t *testing.T) {
	input := []config.MachineRule{
		{Name: "enabled", Paths: []string{"/etc"}, Exclude: []string{"*.tmp"}, Schedule: "0 3 * * *", Enabled: true},
		{Name: "disabled", Paths: []string{"/var"}, Enabled: false},
	}

	got := machineRulesFromConfig(input, "")
	if len(got) != 1 {
		t.Fatalf("expected 1 enabled rule, got %d", len(got))
	}
	if got[0].Name != "enabled" || got[0].Paths[0] != "/etc" || got[0].Exclude[0] != "*.tmp" || !got[0].Enabled {
		t.Fatalf("unexpected rule: %#v", got[0])
	}
}

func TestMachineRulesFromConfigFiltersByName(t *testing.T) {
	input := []config.MachineRule{
		{Name: "one", Paths: []string{"/one"}, Enabled: true},
		{Name: "two", Paths: []string{"/two"}, Enabled: true},
	}

	got := machineRulesFromConfig(input, "two")
	if len(got) != 1 || got[0].Name != "two" {
		t.Fatalf("expected only rule two, got %#v", got)
	}
}

func TestFilterRulesByName(t *testing.T) {
	input := []rules.Rule{{Name: "one"}, {Name: "two"}}

	got := filterRulesByName(input, "one")
	if len(got) != 1 || got[0].Name != "one" {
		t.Fatalf("expected only rule one, got %#v", got)
	}
	all := filterRulesByName(input, "")
	if len(all) != len(input) {
		t.Fatalf("expected all rules, got %#v", all)
	}
}

func TestGetTrackerForUserRestrictsTaskOwnership(t *testing.T) {
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateTasks(db); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertTask(db, store.TaskRecord{TaskID: "alice-task", ServerID: "server", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	tracker := progress.NewTracker()
	orch := New(&config.AgentConfig{}, nil, db, nil)
	orch.tasks["alice-task"] = tracker

	if _, err := orch.GetTrackerForUser("alice", "alice-task"); err != nil {
		t.Fatalf("owner should access task: %v", err)
	}
	if _, err := orch.GetTrackerForUser("bob", "alice-task"); err == nil {
		t.Fatal("different user must not access task")
	}
	if _, err := orch.GetTrackerForUser("root", "alice-task"); err != nil {
		t.Fatalf("root should access task: %v", err)
	}
	orch.tasks = make(map[string]*progress.Tracker)
	restored, err := orch.GetTrackerForUser("alice", "alice-task")
	if err != nil {
		t.Fatalf("stored task should remain queryable after restart: %v", err)
	}
	if phase, _, _ := restored.Snapshot(); phase != progress.PhaseFailed {
		t.Fatalf("reconstructed task phase = %s, want FAILED", phase)
	}
}

func TestResolveServerRequiresConfiguredAddress(t *testing.T) {
	o := New(&config.AgentConfig{Servers: []config.ServerEntry{{Address: "primary:8443"}, {Address: "secondary:8443"}}}, nil, nil, nil)
	if server, err := o.resolveServer("secondary:8443"); err != nil || server.Address != "secondary:8443" {
		t.Fatalf("resolve configured server = %#v, %v", server, err)
	}
	for _, address := range []string{"", "attacker:8443"} {
		if _, err := o.resolveServer(address); err == nil {
			t.Fatalf("resolveServer(%q) unexpectedly succeeded", address)
		}
	}
}
