package handler

import (
	"net/http"
)

func setCustomHeader(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: setting header from user input without CRLF sanitization
	customVal := r.URL.Query().Get("val")
	w.Header().Set("X-Custom", customVal)

	// VULNERABLE: directly using request parameter in header
	w.Header().Set("X-Forwarded-User", r.FormValue("user"))
}
