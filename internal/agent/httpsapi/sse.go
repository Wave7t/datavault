package httpsapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// streamStatus pushes SyncStatusUpdate JSON documents as SSE events until
// the task reaches a terminal phase or the client disconnects.
func (s *Server) streamStatus(w http.ResponseWriter, r *http.Request, id identity, taskID string) {
	if s.deps.GetStatusFn == nil {
		writeError(w, http.StatusNotImplemented, "unimplemented", "status provider not configured")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	send := func() bool {
		st, err := s.deps.GetStatusFn(id.Username, taskID)
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", `{"error":"task_not_found"}`)
			flusher.Flush()
			return false
		}
		data, _ := json.Marshal(statusJSON(st))
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return st.Phase != "COMPLETED" && st.Phase != "FAILED"
	}
	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}
