package handler

import (
	"net/http"
	"net/url"
	"strings"
)

func setCustomHeaderSafe(w http.ResponseWriter, r *http.Request) {
	// SAFE: URL-encode the value before setting header
	customVal := r.URL.Query().Get("val")
	sanitized := url.QueryEscape(customVal)
	w.Header().Set("X-Custom", sanitized)

	// SAFE: strip CRLF before setting header
	user := r.FormValue("user")
	user = strings.ReplaceAll(user, "\r", "")
	user = strings.ReplaceAll(user, "\n", "")
	w.Header().Set("X-Forwarded-User", user)
}
