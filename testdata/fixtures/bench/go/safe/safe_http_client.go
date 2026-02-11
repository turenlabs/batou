package safe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{
	"api.example.com":     true,
	"cdn.example.com":     true,
	"service.example.com": true,
}

// SAFE: URL validated against allowlist before HTTP request
func ProxyRequest(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	parsed, err := url.Parse(target)
	if err != nil || !allowedHosts[parsed.Hostname()] {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	if parsed.Scheme != "https" {
		http.Error(w, "https only", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(parsed.String())
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	json.NewEncoder(w).Encode(data)
}

// SAFE: Hardcoded URL (no user input)
func FetchConfig() (map[string]string, error) {
	resp, err := http.Get("https://config.internal.example.com/v1/settings")
	if err != nil {
		return nil, fmt.Errorf("config fetch failed: %w", err)
	}
	defer resp.Body.Close()

	var cfg map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
