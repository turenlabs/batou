// PSB-A01-TRAV-001: File download endpoint
// CWE: CWE-22, CWE-23
// Expected: (none - secure)
package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

const uploadDir = "/var/app/uploads"

func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "filename is required", http.StatusBadRequest)
		return
	}

	cleaned := filepath.Clean(filename)
	if strings.Contains(cleaned, "..") {
		http.Error(w, "invalid filename", http.StatusForbidden)
		return
	}

	absPath, err := filepath.Abs(filepath.Join(uploadDir, cleaned))
	if err != nil || !strings.HasPrefix(absPath, uploadDir) {
		http.Error(w, "invalid filename", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, absPath)
}
