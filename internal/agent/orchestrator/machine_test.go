package orchestrator

import (
	"testing"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
)

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
