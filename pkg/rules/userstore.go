package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type UserRuleStore struct {
	baseDir string
}

type userRuleFile struct {
	Rules []Rule `yaml:"rules"`
}

func NewUserRuleStore(baseDir string) *UserRuleStore {
	return &UserRuleStore{baseDir: baseDir}
}

func (s *UserRuleStore) filePath(username string) string {
	return filepath.Join(s.baseDir, username+".yaml")
}

func (s *UserRuleStore) Load(username string) ([]Rule, error) {
	f, err := os.Open(s.filePath(username))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open user rules for %q: %w", username, err)
	}
	defer f.Close()

	var uf userRuleFile
	if err := yaml.NewDecoder(f).Decode(&uf); err != nil {
		return nil, fmt.Errorf("decode user rules for %q: %w", username, err)
	}
	return uf.Rules, nil
}

func (s *UserRuleStore) Save(username string, rules []Rule) error {
	if err := os.MkdirAll(s.baseDir, 0700); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	f, err := os.Create(s.filePath(username))
	if err != nil {
		return fmt.Errorf("create user rules for %q: %w", username, err)
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	uf := userRuleFile{Rules: rules}
	if err := yaml.NewEncoder(f).Encode(&uf); err != nil {
		return fmt.Errorf("encode user rules: %w", err)
	}
	return nil
}

func (s *UserRuleStore) Add(username string, rule Rule) error {
	rules, err := s.Load(username)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Name == rule.Name {
			return fmt.Errorf("rule %q already exists", rule.Name)
		}
	}
	rule.Enabled = true
	rules = append(rules, rule)
	return s.Save(username, rules)
}

func (s *UserRuleStore) Remove(username, name string) error {
	rules, err := s.Load(username)
	if err != nil {
		return err
	}
	filtered := make([]Rule, 0, len(rules))
	found := false
	for _, r := range rules {
		if r.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !found {
		return fmt.Errorf("rule %q not found", name)
	}
	return s.Save(username, filtered)
}

func (s *UserRuleStore) SetEnabled(username, name string, enabled bool) error {
	rules, err := s.Load(username)
	if err != nil {
		return err
	}
	for i, r := range rules {
		if r.Name == name {
			rules[i].Enabled = enabled
			return s.Save(username, rules)
		}
	}
	return fmt.Errorf("rule %q not found", name)
}
