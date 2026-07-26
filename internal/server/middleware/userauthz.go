package middleware

import (
	"fmt"
	"strings"

	"github.com/example/datavault/pkg/config"
)

type AuthDecision int

const (
	DecisionAllow AuthDecision = iota
	DecisionRequireSig
	DecisionDeny
)

const (
	CapBackup     = "backup"
	CapQuota      = "quota"
	CapRestore    = "restore"
	CapDelegation = "delegation"
)

func MethodToCapability(fullMethod string) string {
	switch strings.TrimPrefix(fullMethod, "/backup.v1.BackupService/") {
	case "PushBackup":
		return CapBackup
	case "GetQuotaUsage":
		return CapQuota
	case "PullRestore":
		return CapRestore
	case "RegisterDelegationKey", "RemoveDelegationKey", "RegisterTaskGrant":
		return CapDelegation
	}
	return ""
}

func DecideAuth(cfg *config.ServerConfig, agentCN string, uid int32,
	username string, groups []string, fullMethod string) (AuthDecision, error) {

	entry, ok := cfg.UserAuth.EntryForAgent(agentCN)
	if !ok {
		// No per-agent entry → use the default mode.
		if cfg.UserAuth.DefaultMode != "host_vouched" {
			return DecisionRequireSig, nil
		}
		// Default is host_vouched but no entry for this agent — that means the
		// admin never configured trust for this host. Fall back to safe path.
		return DecisionRequireSig, nil
	}
	if entry.Mode != "host_vouched" {
		return DecisionRequireSig, nil
	}

	cap := MethodToCapability(fullMethod)
	if cap == "" {
		// Methods without a capability mapping (e.g., GetChallenge) are mTLS-only;
		// they never reach DecideAuth because they're in MethodWhitelist.
		return DecisionRequireSig, nil
	}
	if !containsString(entry.Capabilities, cap) {
		// Capability not granted for this agent → fall back to per_user_key
		return DecisionRequireSig, nil
	}

	if !trustEvaluate(entry.Trust, uid, username, groups) {
		return DecisionDeny, fmt.Errorf("host_vouched: %q on %q fails trust policy", username, agentCN)
	}
	return DecisionAllow, nil
}

func trustEvaluate(p config.TrustPolicy, uid int32, username string, groups []string) bool {
	if containsString(p.Exclude, username) {
		return false
	}
	if containsString(p.Include, username) {
		return true
	}
	if uid < p.MinUID {
		return false
	}
	if len(p.Groups) == 0 {
		return true
	}
	for _, want := range p.Groups {
		if containsString(groups, want) {
			return true
		}
	}
	return false
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
