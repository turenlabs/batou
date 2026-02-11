// Source: CWE-918 - Server-Side Request Forgery in Go
// Expected: GTSS-SSRF-001 (URL from User Input)
// OWASP: A10:2021 - Server-Side Request Forgery

package handler

import (
	"io"
	"net/http"
)

func ProxyFetch(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "Fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	io.Copy(w, resp.Body)
}

func WebhookForward(w http.ResponseWriter, r *http.Request) {
	webhookURL := r.FormValue("callback_url")
	payload := r.FormValue("data")
	client := &http.Client{}
	req, _ := http.NewRequest("POST", webhookURL, nil)
	req.Header.Set("Content-Type", "application/json")
	_ = payload
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Forward failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
