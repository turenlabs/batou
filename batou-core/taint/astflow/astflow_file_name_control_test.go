package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go — external control of file name or path (CWE-73).
//
// A request-derived value used as the destination of os.Rename / os.Link
// lets the attacker control which file gets clobbered or linked. These flow
// through the existing SnkFileWrite category but report CWE-73; filepath.Base
// neutralizes them like any other path-traversal sanitizer.
// =========================================================================

func hasCWE73FileWriteFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Sink.CWEID == "CWE-73" {
			return true
		}
	}
	return false
}

func TestAnalyzeGo_FileNameControl_OsRename(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func moveUpload(w http.ResponseWriter, r *http.Request) {
	dest := r.FormValue("name")
	os.Rename("/tmp/upload.bin", dest)
}
`
	flows := AnalyzeGo(code, "/app/files.go")
	if !hasCWE73FileWriteFlow(flows) {
		t.Error("expected CWE-73 SnkFileWrite flow for r.FormValue -> os.Rename second arg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_FileNameControl_OsLink(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func linkUpload(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("name")
	os.Link("/tmp/source.bin", target)
}
`
	flows := AnalyzeGo(code, "/app/files.go")
	if !hasCWE73FileWriteFlow(flows) {
		t.Error("expected CWE-73 SnkFileWrite flow for r.URL.Query().Get -> os.Link second arg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_FileNameControl_OsRename_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func moveUpload(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("name")
	dest := filepath.Base(raw)
	os.Rename("/tmp/upload.bin", dest)
}
`
	flows := AnalyzeGo(code, "/app/files.go")
	if hasCWE73FileWriteFlow(flows) {
		t.Error("expected NO CWE-73 flow when destination is sanitized via filepath.Base")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_FileNameControl_OsRename_Hardcoded(t *testing.T) {
	code := `package main

import "os"

func moveUpload() {
	os.Rename("/tmp/upload.bin", "/var/data/final.bin")
}
`
	flows := AnalyzeGo(code, "/app/files.go")
	if hasCWE73FileWriteFlow(flows) {
		t.Error("expected NO CWE-73 flow when both paths are hardcoded literals")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}
