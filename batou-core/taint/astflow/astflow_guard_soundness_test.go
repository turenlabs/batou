package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Guard-heuristic soundness.
//
// processGuardPattern runs on every *ast.IfStmt with an early-exit body.
// Before this fix, inferGuardCategories defaulted to ALL sink categories
// whenever the condition merely MENTIONED a tainted variable without any
// recognized guard function — so `if name == "" { return }` or
// `if len(name) > 100 { return }` silently "sanitized" the variable for
// every category (path traversal, command injection, SQLi, ...).
//
// The narrowed rule: a guard only sanitizes when the condition carries
// actual validation semantics —
//   - a recognized guard function (HasPrefix/MatchString/IsLocal/IsAbs/
//     Contains/Rel) → category-specific, unchanged;
//   - an allowlist map lookup keyed by the tainted value (allowed[name]);
//   - a call to a validation-named helper (isX/hasX/validateX/checkX/
//     allowX/matchX/sanitizeX/verifyX) taking the tainted value;
//   - a validation-result boolean linked to the tainted value
//     (matched, _ := regexp.MatchString(p, name); if !matched { ... });
//   - a `v != <literal>` comparison with early return (v is pinned to a
//     compile-time constant afterwards) — applies to v only.
//
// Pure nil/empty/len/err shapes sanitize NOTHING.
// =========================================================================

// --- Unsound shapes: must keep flowing ---

// TestGuardSoundness_EmptyStringGuard_StillFlags: `if name == "" { return }`
// rejects only the empty string; "../../etc/passwd" passes the guard.
func TestGuardSoundness_EmptyStringGuard_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if name == "" {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected file-sink flow: an empty-string check is NOT a path-traversal sanitizer")
	}
}

// TestGuardSoundness_LenGuard_StillFlags: `if len(name) > 100 { return }`
// bounds length, not content.
func TestGuardSoundness_LenGuard_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if len(name) > 100 {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected file-sink flow: a length check is NOT a path-traversal sanitizer")
	}
}

// TestGuardSoundness_DenylistEqualityGuard_StillFlags:
// `if name == "forbidden" { return }` is a one-entry denylist — every other
// malicious value passes.
func TestGuardSoundness_DenylistEqualityGuard_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if name == "passwd" {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected file-sink flow: an == denylist check is NOT a sanitizer")
	}
}

// TestGuardSoundness_NilErrShapeMentioningTaintedVar_StillFlags: a compound
// nil/err/empty condition that mentions the tainted variable but contains no
// validation call must not sanitize it.
func TestGuardSoundness_NilErrShapeMentioningTaintedVar_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmdArg := r.FormValue("arg")
	f, err := os.Open("/etc/app.conf")
	if err != nil || cmdArg == "" {
		return
	}
	_ = f
	exec.Command("tool", cmdArg).Run()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			found = true
		}
	}
	if !found {
		t.Error("expected command-sink flow: err-nil + empty-string compound guard is NOT a sanitizer")
	}
}

// --- Sound shapes: must stay sanitized ---

// TestGuardSoundness_NotEqualLiteralGuard_Sanitized:
// `if name != "config.json" { return }` pins name to a compile-time constant
// for all code after the guard — a sound single-value allowlist.
func TestGuardSoundness_NotEqualLiteralGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if name != "config.json" {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow: after `name != literal` early return, name is a constant")
	}
}

// TestGuardSoundness_ValidationNamedFuncGuard_Sanitized:
// `if !isValidPath(name) { return }` — a validation-named helper taking the
// tainted value keeps the all-category guard behavior.
func TestGuardSoundness_ValidationNamedFuncGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"strings"
)

func isValidPath(p string) bool {
	return !strings.Contains(p, "..") && !strings.HasPrefix(p, "/")
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if !isValidPath(name) {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when a validation-named helper guards the value")
	}
}

// TestGuardSoundness_ValidationMethodGuard_Sanitized:
// `if !policy.AllowsPath(name) { return }` — validation-named method with the
// tainted value as argument.
func TestGuardSoundness_ValidationMethodGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if !policy.AllowsPath(name) {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when a validation-named method guards the value")
	}
}

// TestGuardSoundness_AllowlistMapGuard_Sanitized:
// `if !allowed[name] { return }` — allowlist map lookup keyed by the tainted
// value remains a full sanitizer.
func TestGuardSoundness_AllowlistMapGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

var allowed = map[string]bool{"a.txt": true, "b.txt": true}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if !allowed[name] {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when an allowlist map guards the value")
	}
}

// TestGuardSoundness_ValidationLinkGuard_Sanitized: the indirect
// validation-result-boolean pattern still sanitizes.
func TestGuardSoundness_ValidationLinkGuard_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"regexp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	matched, err := regexp.MatchString("^[a-zA-Z0-9_.-]+$", name)
	if err != nil || !matched {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow when a regexp validation boolean guards the value")
	}
}

// --- Precision fixes for flows unmasked by the guard narrowing ---

// TestFormatSanitizer_HexVerb_Sanitized: fmt.Sprintf("%x", ...) yields hex
// digits only — the result cannot carry path separators or shell metachars.
func TestFormatSanitizer_HexVerb_Sanitized(t *testing.T) {
	code := `package main

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	key := fmt.Sprintf("%x", md5.Sum([]byte(name)))
	_, _ = os.ReadFile(filepath.Join("/var/cache", key))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected NO file-sink flow: a hex-x-formatted value is hex digits only")
	}
}

// TestFormatSanitizer_StringVerb_StillFlags: %s passes content through.
func TestFormatSanitizer_StringVerb_StillFlags(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	p := fmt.Sprintf("/var/data/%s", name)
	_, _ = os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected file-sink flow: a string verb passes attacker content through Sprintf")
	}
}

// TestFormatSanitizer_MixedVerbs_StillFlags: one content-passing verb in the
// format disqualifies the whole call.
func TestFormatSanitizer_MixedVerbs_StillFlags(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	p := fmt.Sprintf("%d-%v", 7, name)
	_, _ = os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected file-sink flow: a value verb passes attacker content through Sprintf")
	}
}

// TestZipReaderOpen_NotFilesystemSink: zip.Reader.Open(entryName) reads an
// entry from inside the (already attacker-supplied) archive — it is not a
// filesystem path sink and must not be mislabeled CWE-22 via a package-blind
// bare-"Open" match.
func TestZipReaderOpen_NotFilesystemSink(t *testing.T) {
	code := `package main

import (
	"archive/zip"
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	f, hdr, _ := r.FormFile("pkg")
	defer f.Close()
	zr, err := zip.NewReader(f, hdr.Size)
	if err != nil {
		return
	}
	for _, file := range zr.File {
		rc, err := zr.Open(file.Name)
		if err != nil {
			return
		}
		_, _ = io.ReadAll(rc)
		rc.Close()
	}
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.os.open" {
			t.Errorf("zip.Reader.Open mislabeled as go.os.open (CWE-22): %s -> %s line %d",
				f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestOsOpen_StillFilesystemSink: the package-qualified entry still matches
// the real os.Open.
func TestOsOpen_StillFilesystemSink(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	_, _ = os.Open(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.os.open" {
			found = true
		}
	}
	if !found {
		t.Error("expected go.os.open flow for os.Open(tainted)")
	}
}

// TestGuardSoundness_HashNamedFuncGuard_StillFlags: "has" prefix must not
// swallow "hash..." helpers — hashing in a condition is not validation of
// the value that continues to flow.
func TestGuardSoundness_HashNamedFuncGuard_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	if hashKey(name) == 0 {
		return
	}
	_, _ = os.ReadFile(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFileSinkFlow(flows, "go.http.request.formvalue") {
		t.Error("expected file-sink flow: hashKey(...) is not a validation helper")
	}
}
