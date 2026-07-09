package rules

import "fmt"

type Rule struct {
	Name     string   `yaml:"name"     json:"name"`
	Paths    []string `yaml:"paths"    json:"paths"`
	Exclude  []string `yaml:"exclude"  json:"exclude,omitempty"`
	Schedule string   `yaml:"schedule" json:"schedule,omitempty"`
	Enabled  bool     `yaml:"enabled"  json:"enabled"`
}

func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("rule %q: at least one path is required", r.Name)
	}
	return nil
}
