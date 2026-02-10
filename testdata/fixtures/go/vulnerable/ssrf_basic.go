package vulnerable

import (
	"io"
	"net/http"
)

// VULN: Server-side request forgery (SSRF) - user controls the target URL for http.Get.
// Should trigger taint analysis for go.http.get sink with user input source.

func HandleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")

	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	io.Copy(w, resp.Body)
}
