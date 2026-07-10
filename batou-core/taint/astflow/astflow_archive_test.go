package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog registration tests ---

func TestCatalogMatcher_ArchiveSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	checks := []struct {
		method string
		id     string
	}{
		{"OpenReader", "go.archive.zip.openreader"},
		{"NewReader", "go.archive.zip.newreader"},
		{"Open", "go.archive.zip.file.open"},
		{"NewReader", "go.archive.tar.newreader"},
		{"Next", "go.archive.tar.reader.next"},
	}

	for _, c := range checks {
		found := false
		for _, src := range matcher.sourcesByMethod[c.method] {
			if src.ID == c.id && src.Category == taint.SrcExternal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected source %q (method=%q) to be registered as SrcExternal", c.id, c.method)
		}
	}
}

// --- End-to-end flow tests ---

func TestAnalyzeGo_ZipSlip_OpenReader(t *testing.T) {
	code := `package main

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func extract(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		path := filepath.Join(dst, f.Name)
		out, err := os.Create(path)
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}
`
	flows := AnalyzeGo(code, "/app/extract.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for zip-slip: zip.OpenReader → r.File → f.Name → os.Create(filepath.Join(..))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_ZipSlip_NewReader(t *testing.T) {
	code := `package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func upload(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	reader := bytes.NewReader(body)
	zr, err := zip.NewReader(reader, int64(len(body)))
	if err != nil {
		return
	}
	for _, f := range zr.File {
		path := filepath.Join("/tmp", f.Name)
		out, _ := os.Create(path)
		rc, _ := f.Open()
		io.Copy(out, rc)
	}
}
`
	flows := AnalyzeGo(code, "/app/upload.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for zip-slip via zip.NewReader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TarSlip_Next(t *testing.T) {
	code := `package main

import (
	"archive/tar"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func extractTar(w http.ResponseWriter, r *http.Request, dst string) {
	tr := tar.NewReader(r.Body)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		path := filepath.Join(dst, hdr.Name)
		out, err := os.Create(path)
		if err != nil {
			return
		}
		io.Copy(out, tr)
		out.Close()
	}
}
`
	flows := AnalyzeGo(code, "/app/extract_tar.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for tar-slip: tr.Next() → hdr.Name → os.Create(filepath.Join(..))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestAnalyzeGo_ZipSlip_FilepathClean_NoGuard verifies that filepath.Clean
// ALONE does NOT neutralise zip-slip. Clean("../../etc/passwd") still returns
// "../../etc/passwd" — Clean only collapses .. segments lexically; it does
// not reject escapes. PR-HH removed filepath.Clean as a standalone sanitiser
// to make this explicit.
func TestAnalyzeGo_ZipSlip_FilepathClean_NoGuard(t *testing.T) {
	code := `package main

import (
	"archive/zip"
	"os"
	"path/filepath"
)

func extract(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		clean := filepath.Clean(f.Name)
		path := filepath.Join(dst, clean)
		_, _ = os.Create(path)
	}
	return nil
}
`
	flows := AnalyzeGo(code, "/app/extract_unsafe.go")
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Source.ID == "go.archive.zip.openreader" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SnkFileWrite zip-slip flow when only filepath.Clean is applied (no prefix-check / IsLocal / SecureJoin guard)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestAnalyzeGo_ZipSlip_IsLocal_Sanitized verifies that guarding the archive
// entry with filepath.IsLocal (Go 1.20+) neutralises zip-slip. IsLocal
// returns false on any path that escapes the current directory, so a
// `if !filepath.IsLocal(name) { continue }` check is a complete sound guard.
func TestAnalyzeGo_ZipSlip_IsLocal_Sanitized(t *testing.T) {
	code := `package main

import (
	"archive/zip"
	"os"
	"path/filepath"
)

func extract(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if !filepath.IsLocal(f.Name) {
			continue
		}
		path := filepath.Join(dst, f.Name)
		_, _ = os.Create(path)
	}
	return nil
}
`
	flows := AnalyzeGo(code, "/app/extract_safe.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Source.ID == "go.archive.zip.openreader" {
			t.Errorf("expected no SnkFileWrite zip-slip flow when filepath.IsLocal guards the archive entry; got: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// --- Helper-extractor (param-typed source) flow tests ---
//
// The dominant real-world zip-slip / tar-slip shape factors the per-entry sink
// into a helper that receives the archive entry as a parameter. The catalog
// sources key on the OpenReader/Next CALL and so miss this form; seeding the
// `*zip.File` / `*tar.Header` parameter itself as a source closes it.

func TestAnalyzeGo_ZipSlip_HelperParam(t *testing.T) {
	code := `package main

import (
	"os"
	"path/filepath"
	"archive/zip"
)

func extract(dest string, f *zip.File) {
	p := filepath.Join(dest, f.Name)
	out, _ := os.Create(p)
	_ = out
}
`
	flows := AnalyzeGo(code, "/app/extract_helper.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for helper-extractor zip-slip: *zip.File param → f.Name → os.Create(filepath.Join(..))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TarSlip_HelperParam(t *testing.T) {
	code := `package main

import (
	"os"
	"path/filepath"
	"archive/tar"
)

func extract(dest string, h *tar.Header) {
	p := filepath.Join(dest, h.Name)
	out, _ := os.Create(p)
	_ = out
}
`
	flows := AnalyzeGo(code, "/app/extract_tar_helper.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for helper-extractor tar-slip: *tar.Header param → h.Name → os.Create(filepath.Join(..))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestAnalyzeGo_ZipSlip_HelperParam_Guarded confirms the param-seeded source is
// still subject to the existing sanitiser layer: a `filepath.IsLocal` guard
// that fail-closes (continue/return) neutralises the flow, so a correctly
// guarded helper extractor produces NO finding (FP-safety).
func TestAnalyzeGo_ZipSlip_HelperParam_Guarded(t *testing.T) {
	code := `package main

import (
	"os"
	"path/filepath"
	"archive/zip"
)

func extract(dest string, f *zip.File) {
	if !filepath.IsLocal(f.Name) {
		return
	}
	p := filepath.Join(dest, f.Name)
	out, _ := os.Create(p)
	_ = out
}
`
	flows := AnalyzeGo(code, "/app/extract_helper_safe.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Source.ID == "go.archive.entryparam.f" {
			t.Errorf("expected no SnkFileWrite flow when filepath.IsLocal guards the archive entry param; got: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

func TestAnalyzeGo_TarSlip_Linkname(t *testing.T) {
	code := `package main

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

func extractTar(tr *tar.Reader, dst string) {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		link := filepath.Join(dst, hdr.Linkname)
		os.Symlink(link, filepath.Join(dst, hdr.Name))
	}
}
`
	flows := AnalyzeGo(code, "/app/extract_tar.go")
	sawSymlink := false
	for _, f := range flows {
		if f.Source.ID == "go.archive.tar.reader.next" {
			sawSymlink = true
			break
		}
	}
	if !sawSymlink {
		t.Error("expected taint flow originating from go.archive.tar.reader.next")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
