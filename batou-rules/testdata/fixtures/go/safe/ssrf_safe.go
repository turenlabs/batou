package safe

import (
	"net/http"
	"net/url"
)

// SAFE: HTTP requests restricted to an allowlist of hostnames.
// Should NOT trigger BATOU-SSRF-001 or any SSRF rules.

var allowedHosts = map[string]bool{
	"api.example.com":     true,
	"cdn.example.com":     true,
	"service.internal":    true,
}

func HandleProxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	parsed, err := url.Parse(target)
	if err != nil {
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}

	// Validate host against allowlist
	if !allowedHosts[parsed.Hostname()] {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	// Safe: only allowlisted hosts are fetched
	resp, err := http.Get(parsed.String())
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
}
