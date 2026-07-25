package httpsapi

import (
	"encoding/json"
	"log"
	"net/http"
)

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeError emits an RFC 9457-style error body. Security failures must use
// the generic codes below and never echo internal detail.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	var body apiError
	body.Error.Code = code
	body.Error.Message = message
	_ = json.NewEncoder(w).Encode(body)
}

func writeUnauthorized(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "unauthorized", "client certificate is not authorized")
}

func writeDelegationRequired(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "delegation_required", "no active delegation for this gateway and user")
}

func writeInternal(w http.ResponseWriter, logger *log.Logger, op string, err error) {
	logger.Printf("httpsapi: %s: %v", op, err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
