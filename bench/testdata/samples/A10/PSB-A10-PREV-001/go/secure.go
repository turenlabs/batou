// PSB-A10-PREV-001: URL preview/unfurl feature
// CWE: CWE-918
// Expected: (none - secure)
package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

func isSafeHost(hostname string) bool {
	addrs, err := net.LookupHost(hostname)
	if err \!= nil {
		return false
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func preview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.URL == "" {
		http.Error(w, `{"error":"url is required"}`, http.StatusBadRequest)
		return
	}

	parsed, err := url.Parse(req.URL)
	if err \!= nil || (parsed.Scheme \!= "http" && parsed.Scheme \!= "https") {
		http.Error(w, `{"error":"invalid URL"}`, http.StatusBadRequest)
		return
	}
	if \!isSafeHost(parsed.Hostname()) {
		http.Error(w, `{"error":"blocked URL"}`, http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(req.URL)
	if err \!= nil {
		http.Error(w, `{"error":"failed to fetch"}`, http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	html := string(body)

	titleRe := regexp.MustCompile(`<title>(.*?)</title>`)
	title := ""
	if m := titleRe.FindStringSubmatch(html); len(m) > 1 {
		title = m[1]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"title": title})
}
GOEOF < /dev/null