package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PR-HH — path-traversal sanitiser recognition.
//
// These fixtures exercise the three classes of CWE-22 guard that the Go
// catalog now recognises explicitly:
//
//   1. filepath.IsLocal(x)             Go 1.20+ — complete sound guard
//   2. securejoin.SecureJoin(base, x)  cyphar/filepath-securejoin
//   3. filepath.Clean + strings.HasPrefix containment check
//
// And the explicit negative case: filepath.Clean ALONE is NOT a path
// sanitiser (Clean("../../etc/passwd") returns "../../etc/passwd"). The
// `filepath.Clean` standalone sanitiser entry was removed from the Go
// catalog in this PR to make this guarantee explicit.
// =========================================================================

// hasFileSinkFlow returns true if any taint flow ends at a file-read or
// file-write sink originating from the given source ID.
func hasFileSinkFlow(flows []taint.TaintFlow, srcID string) bool {
	for _, f := range flows {
		if f.Source.ID != srcID {
			continue
		}
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			return true
		}
	}
	return false
}

// TestPathSanitizer_CleanAlone_StillFlags asserts the negative invariant:
// applying filepath.Clean without an additional containment guard does NOT
// neutralise path traversal. Clean only collapses .. lexically, so
// Clean("../../etc/passwd") still escapes.
func TestPathSanitizer_CleanAlone_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	p := filepath.Clean(name)
	_, _ = os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected SnkFileRead flow when only filepath.Clean is applied — Clean alone is NOT a path-traversal sanitiser")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestPathSanitizer_CleanWithHasPrefixGuard_Sanitized asserts that the
// canonical Clean + strings.HasPrefix guard combo is recognised. Without
// the Clean+HasPrefix combo nothing reliably bounds the path inside the
// trusted base.
func TestPathSanitizer_CleanWithHasPrefixGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	p := filepath.Clean(name)
	if !strings.HasPrefix(p, "/var/data/") {
		return
	}
	_, _ = os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when filepath.Clean is paired with a strings.HasPrefix prefix-check guard")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestPathSanitizer_IsLocalGuard_Sanitized exercises filepath.IsLocal as
// a complete sound guard (Go 1.20+). IsLocal returns false on any path
// that escapes the current directory, so `if !filepath.IsLocal(x) { return }`
// is a complete CWE-22 guard.
func TestPathSanitizer_IsLocalGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if !filepath.IsLocal(name) {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when filepath.IsLocal guards the path")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestPathSanitizer_IsAbsNegativeGuard_Sanitized exercises filepath.IsAbs
// used as a negative guard — `if filepath.IsAbs(x) { return }` rejects
// absolute paths, leaving only relative paths to continue. Combined with
// the bounded extraction directory this is a reasonable defence.
func TestPathSanitizer_IsAbsNegativeGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if filepath.IsAbs(name) {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when filepath.IsAbs is used as a negative guard")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestPathSanitizer_StringsContainsDotDotGuard_Sanitized exercises a
// `if strings.Contains(name, "..") { return }` rejection guard. This is the
// pre-Go-1.20 idiom for callers that don't want to take a dependency on
// filepath-securejoin.
func TestPathSanitizer_StringsContainsDotDotGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if strings.Contains(name, "..") {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when a strings.Contains(name, \"..\") rejection guard is applied")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestPathSanitizer_SecureJoin_Sanitized exercises cyphar/filepath-securejoin.
// SecureJoin returns a path guaranteed to stay under the supplied base and
// resolves symlinks safely — it is a complete CWE-22/CWE-59 sanitiser.
func TestPathSanitizer_SecureJoin_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"

	securejoin "github.com/cyphar/filepath-securejoin"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	p, err := securejoin.SecureJoin("/var/data", name)
	if err != nil {
		return
	}
	_, _ = os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when securejoin.SecureJoin is used to bound the path")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestPathSanitizer_SecureJoinVFS_Sanitized exercises the VFS variant of
// SecureJoin — same safety guarantee, different signature.
func TestPathSanitizer_SecureJoinVFS_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"

	securejoin "github.com/cyphar/filepath-securejoin"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	p, err := securejoin.SecureJoinVFS("/var/data", name, nil)
	if err != nil {
		return
	}
	_, _ = os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when securejoin.SecureJoinVFS is used to bound the path")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestPathSanitizer_OsRename_IsLocalGuard_Sanitized confirms the same guard
// recognition holds for write-side path sinks (os.Rename), not just reads.
func TestPathSanitizer_OsRename_IsLocalGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	dest := r.FormValue("name")
	if !filepath.IsLocal(dest) {
		return
	}
	os.Rename("/tmp/upload.bin", dest)
}
`
	flows := AnalyzeGo(code, "/app/files.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when filepath.IsLocal guards the os.Rename destination")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}
