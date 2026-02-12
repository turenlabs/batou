// PSB-A10-PREV-001: URL preview/unfurl feature
// CWE: CWE-918
// Expected: GTSS-SSRF-001
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
)

func preview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.URL == "" {
		http.Error(w, `{"error":"url is required"}`, http.StatusBadRequest)
		return
	}

	resp, err := http.Get(req.URL)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch URL"}`, http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	titleRe := regexp.MustCompile(`<title>(.*?)</title>`)
	title := ""
	if m := titleRe.FindStringSubmatch(html); len(m) > 1 {
		title = m[1]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"title": title,
	})
}
