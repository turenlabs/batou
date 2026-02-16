// Source: CWE-22 - Path Traversal in Go file server
// Expected: BATOU-TRV-001 (Path Traversal via user input in file path)
// OWASP: A01:2021 - Broken Access Control (Path Traversal)

package handler

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "./uploads"

func ServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	fullPath := filepath.Join(uploadDir, filename)
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	io.Copy(w, file)
}

func DownloadAttachment(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	path := "/var/attachments/" + name
	http.ServeFile(w, r, path)
}
