package svc

import (
	"context"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
)

// GetGlobalConfig returns the server's global backup rules and user policy.
// The agent calls this at startup to merge server-side rules with machine and user rules.
func (s *BackupServer) GetGlobalConfig(ctx context.Context, req *backuppbv1.GetGlobalConfigRequest) (*backuppbv1.GlobalConfig, error) {
	gc := &backuppbv1.GlobalConfig{
		UserPolicy: &backuppbv1.UserPolicy{
			DefaultSchedule:  s.Cfg.UserPolicy.DefaultSchedule,
			DefaultQuotaGb:   s.Cfg.UserPolicy.DefaultQuotaGB,
			PerUserOverrides: make(map[string]*backuppbv1.UserOverride),
		},
	}

	for _, gr := range s.Cfg.GlobalRules {
		gc.GlobalRules = append(gc.GlobalRules, &backuppbv1.GlobalRule{
			Name:    gr.Name,
			Paths:   gr.Paths,
			Exclude: gr.Exclude,
		})
	}

	for name, override := range s.Cfg.UserPolicy.PerUserOverrides {
		gc.UserPolicy.PerUserOverrides[name] = &backuppbv1.UserOverride{
			QuotaGb:  override.QuotaGB,
			Schedule: override.Schedule,
		}
	}

	return gc, nil
}
