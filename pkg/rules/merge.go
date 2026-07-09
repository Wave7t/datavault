package rules

import "github.com/example/datavault/pkg/config"

// MergeResult holds the merged backup plan for a single user.
type MergeResult struct {
	Rules    []Rule
	Schedule string
	QuotaGB  int64
}

// MergeUserRules combines global rules from the server with the user's personal rules.
func MergeUserRules(globalRules []config.GlobalRule, userRules []Rule, policy config.UserPolicyBlock, username string) MergeResult {
	result := MergeResult{
		Schedule: policy.DefaultSchedule,
		QuotaGB:  policy.DefaultQuotaGB,
	}

	// Check for per-user overrides
	if override, ok := policy.PerUserOverrides[username]; ok {
		if override.QuotaGB > 0 {
			result.QuotaGB = override.QuotaGB
		}
		if override.Schedule != "" {
			result.Schedule = override.Schedule
		}
	}

	// Global rules first (they become user responsibilities)
	for _, gr := range globalRules {
		result.Rules = append(result.Rules, Rule{
			Name:    gr.Name,
			Paths:   gr.Paths,
			Exclude: gr.Exclude,
			Enabled: true, // global rules are always enabled
		})
	}

	// User personal rules
	for _, ur := range userRules {
		if ur.Enabled {
			result.Rules = append(result.Rules, ur)
		}
	}

	return result
}
