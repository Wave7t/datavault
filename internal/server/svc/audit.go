package svc

import (
	"log"
	"strings"

	"github.com/example/datavault/internal/server/middleware"
)

// LogAuthDecision writes a single structured log line recording the auth
// method used for a user operation. Called from each handler after DecideAuth.
func LogAuthDecision(logger *log.Logger, fullMethod, agentCN, username string, uid int32, decision middleware.AuthDecision) {
	if logger == nil {
		return
	}
	method := strings.TrimPrefix(fullMethod, "/backup.v1.BackupService/")
	var d, am string
	switch decision {
	case middleware.DecisionAllow:
		d, am = "allow", "host_vouched"
	case middleware.DecisionRequireSig:
		d, am = "require_sig", "ssh_signature"
	case middleware.DecisionDeny:
		d, am = "deny", "denied"
	}
	logger.Printf("audit method=%s agent=%s user=%s uid=%d auth_method=%s decision=%s",
		method, agentCN, username, uid, am, d)
}
