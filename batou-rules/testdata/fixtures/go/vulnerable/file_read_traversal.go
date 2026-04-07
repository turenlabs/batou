package vulnerable

import (
	"html/template"
	"net/http"
	"os"
	"path/filepath"
)

// VULN: Path traversal via unsanitized user-controlled path passed to http.ServeFile.
// Should trigger SnkFileRead taint flow.

func HandleStaticFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	fullPath := filepath.Join("/var/www/static", filename)
	http.ServeFile(w, r, fullPath)
}

// VULN: File existence check with user-controlled path (information disclosure).

func HandleFileCheck(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	_, err := os.Stat(path)
	if err == nil {
		w.Write([]byte("exists"))
	} else {
		w.Write([]byte("not found"))
	}
}

// VULN: Directory listing with user-controlled path.

func HandleDirectoryList(w http.ResponseWriter, r *http.Request) {
	dir := r.FormValue("dir")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		w.Write([]byte(e.Name() + "\n"))
	}
}

// VULN: Template inclusion with user-controlled path (LFI).

func HandleTemplateLFI(w http.ResponseWriter, r *http.Request) {
	tmplName := r.FormValue("template")
	tmpl, _ := template.ParseFiles(tmplName)
	tmpl.Execute(w, nil)
}
