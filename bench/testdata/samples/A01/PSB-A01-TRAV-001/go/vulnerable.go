// PSB-A01-TRAV-001: File download endpoint
// CWE: CWE-22, CWE-23
// Expected: BATOU-TRAV-001, BATOU-TRAV-003
package main

import (
	"net/http"
	"path/filepath"
)

const uploadDir = "/var/app/uploads"

func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "filename is required", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, filename)
	http.ServeFile(w, r, filePath)
}
