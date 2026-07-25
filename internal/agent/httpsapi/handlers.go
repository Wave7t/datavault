package httpsapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
)

const maxBodyBytes = 64 << 10

func (s *Server) routes() {
	m := s.mux
	m.Handle("GET /v1/users/{user}/rules", http.HandlerFunc(s.handleListRules))
	m.Handle("POST /v1/users/{user}/rules", http.HandlerFunc(s.handleAddRule))
	m.Handle("DELETE /v1/users/{user}/rules/{name}", http.HandlerFunc(s.handleRemoveRule))
	m.Handle("POST /v1/users/{user}/rules/{name}/enable", http.HandlerFunc(s.handleSetRuleEnabled(true)))
	m.Handle("POST /v1/users/{user}/rules/{name}/disable", http.HandlerFunc(s.handleSetRuleEnabled(false)))
	m.Handle("POST /v1/users/{user}/challenges", http.HandlerFunc(s.handleChallenge))
	m.Handle("POST /v1/users/{user}/syncs", http.HandlerFunc(s.handleTriggerSync))
	m.Handle("GET /v1/users/{user}/syncs/{task}", http.HandlerFunc(s.handleSyncStatus))
	m.Handle("GET /v1/users/{user}/quota", http.HandlerFunc(s.handleQuota))
	m.Handle("POST /v1/users/{user}/restores", http.HandlerFunc(s.handleRestore))
	m.Handle("GET /v1/users/{user}/delegation", http.HandlerFunc(s.handleGetDelegation))
	m.Handle("DELETE /v1/users/{user}/delegation", http.HandlerFunc(s.handleDeleteDelegation))
}

type ruleJSON struct {
	Name    string   `json:"name"`
	Paths   []string `json:"paths"`
	Exclude []string `json:"exclude"`
	Enabled bool     `json:"enabled"`
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body is not valid JSON")
		return false
	}
	return true
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	ruleList, err := s.deps.UserRuleStore.Load(id.Username)
	if err != nil {
		writeInternal(w, s.log(), "load rules", err)
		return
	}
	out := []ruleJSON{}
	for _, rl := range ruleList {
		out = append(out, ruleJSON{Name: rl.Name, Paths: rl.Paths, Exclude: rl.Exclude, Enabled: rl.Enabled})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	var body ruleJSON
	if !decodeBody(w, r, &body) {
		return
	}
	rule := rules.Rule{Name: body.Name, Paths: body.Paths, Exclude: body.Exclude, Enabled: true}
	if err := rule.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_rule", err.Error())
		return
	}
	if err := rules.ValidateUserPaths(rule.Paths, id.HomeDir); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_rule", err.Error())
		return
	}
	if err := s.deps.UserRuleStore.Add(id.Username, rule); err != nil {
		if strings.Contains(err.Error(), "exists") {
			writeError(w, http.StatusConflict, "rule_exists", "a rule with this name already exists")
			return
		}
		writeInternal(w, s.log(), "add rule", err)
		return
	}
	s.log().Printf("httpsapi: audit gateway=%q user=%q op=add-rule name=%q", id.GatewayCN, id.Username, rule.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"name": rule.Name})
}

func (s *Server) handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	name := r.PathValue("name")
	if err := s.deps.UserRuleStore.Remove(id.Username, name); err != nil {
		writeError(w, http.StatusNotFound, "rule_not_found", "rule not found")
		return
	}
	s.log().Printf("httpsapi: audit gateway=%q user=%q op=remove-rule name=%q", id.GatewayCN, id.Username, name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetRuleEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := identityFrom(r.Context())
		name := r.PathValue("name")
		if err := s.deps.UserRuleStore.SetEnabled(id.Username, name, enabled); err != nil {
			writeError(w, http.StatusNotFound, "rule_not_found", "rule not found")
			return
		}
		s.log().Printf("httpsapi: audit gateway=%q user=%q op=set-rule-enabled name=%q enabled=%v", id.GatewayCN, id.Username, name, enabled)
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "enabled": enabled})
	}
}

func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	taskID := r.PathValue("task")
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		s.streamStatus(w, r, id, taskID) // sse.go
		return
	}
	if s.deps.GetStatusFn == nil {
		writeError(w, http.StatusNotImplemented, "unimplemented", "status provider not configured")
		return
	}
	st, err := s.deps.GetStatusFn(id.Username, taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "task_not_found", "task not found")
		return
	}
	writeJSON(w, http.StatusOK, statusJSON(st))
}

func (s *Server) handleGetDelegation(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	d, err := store.GetWebDelegation(s.deps.DB, id.Username, id.GatewayCN)
	if err != nil {
		writeInternal(w, s.log(), "load delegation", err)
		return
	}
	if d == nil { // unreachable through the gate, but stay defensive
		writeDelegationRequired(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"gateway_cn":        d.GatewayCN,
		"delegation_pubkey": d.DelegationPubKey,
		"expires_at":        d.ExpiresAt.Unix(),
	})
}

func statusJSON(st *agentpbv1.SyncStatusUpdate) map[string]any {
	out := map[string]any{
		"task_id": st.TaskId,
		"phase":   st.Phase,
		"error":   st.Error,
	}
	if st.Stats != nil {
		out["stats"] = map[string]any{
			"total_files":       st.Stats.TotalFiles,
			"scanned_files":     st.Stats.ScannedFiles,
			"changed_files":     st.Stats.ChangedFiles,
			"transferred_files": st.Stats.TransferredFiles,
			"transferred_bytes": st.Stats.TransferredBytes,
			"current_rate_bps":  st.Stats.CurrentRateBps,
		}
	}
	return out
}
