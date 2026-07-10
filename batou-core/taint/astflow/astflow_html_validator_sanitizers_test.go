package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go HTML / validator-library sanitizer tests.
//
// Validates new sanitizer entries:
//   go.bluemonday.sanitizebytes        (microcosm-cc/bluemonday — []byte variant)
//   go.bluemonday.sanitizereader       (microcosm-cc/bluemonday — io.Reader variant)
//   go.govalidator.safefilename        (asaskevich/govalidator — path traversal)
//   go.govalidator.normalizeemail      (asaskevich/govalidator — email canonicalization)
//   go.govalidator.whitelist           (asaskevich/govalidator — char whitelist)
//   go.govalidator.blacklist           (asaskevich/govalidator — char blacklist)
//   go.govalidator.striplow            (asaskevich/govalidator — control-char strip)
// =========================================================================

func TestCatalogMatcher_HTMLValidatorSanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sanitizers := cat.Sanitizers()
	matcher := NewCatalogMatcher(nil, nil, sanitizers, nil)

	expected := map[string]string{
		"go.bluemonday.sanitizebytes":   "SanitizeBytes",
		"go.bluemonday.sanitizereader":  "SanitizeReader",
		"go.govalidator.safefilename":   "SafeFileName",
		"go.govalidator.normalizeemail": "NormalizeEmail",
		"go.govalidator.whitelist":      "WhiteList",
		"go.govalidator.blacklist":      "BlackList",
		"go.govalidator.striplow":       "StripLow",
	}

	for id, method := range expected {
		found := false
		for _, s := range matcher.sanitizersByMethod[method] {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sanitizer %q to be indexed by method %q", id, method)
		}
	}
}

// --- bluemonday.SanitizeBytes ---

func TestAnalyzeGo_BluemondaySanitizeBytes_NeutralizesXSS(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	policy := bluemonday.UGCPolicy()
	clean := policy.SanitizeBytes([]byte(body))
	w.Write(clean)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTMLOutput flow when policy.SanitizeBytes is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_BluemondaySanitizeBytes_NoSanitizer_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	w.Write([]byte(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HTMLOutput flow without sanitizer (negative control)")
	}
}

// --- bluemonday.SanitizeReader ---

func TestAnalyzeGo_BluemondaySanitizeReader_NeutralizesXSS(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	policy := bluemonday.UGCPolicy()
	buf := policy.SanitizeReader(strings.NewReader(body))
	w.Write(buf.Bytes())
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTMLOutput flow when policy.SanitizeReader is used; got id=%s", f.Sink.ID)
		}
	}
}

// --- govalidator.SafeFileName ---

func TestAnalyzeGo_GovalidatorSafeFileName_NeutralizesPathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"

	"github.com/asaskevich/govalidator"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	clean := govalidator.SafeFileName(name)
	os.ReadFile("/uploads/" + clean)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		// go.os.readfile is categorized as SnkFileWrite (path-traversal sink convention).
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead {
			t.Errorf("expected NO file-path flow when govalidator.SafeFileName is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_GovalidatorSafeFileName_NoSanitizer_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	os.ReadFile("/uploads/" + name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead {
			found = true
		}
	}
	if !found {
		t.Errorf("expected file-path flow without sanitizer (negative control)")
	}
}

// --- govalidator.NormalizeEmail ---

func TestAnalyzeGo_GovalidatorNormalizeEmail_NeutralizesLogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"

	"github.com/asaskevich/govalidator"
)

func handler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	clean, err := govalidator.NormalizeEmail(email)
	if err != nil {
		return
	}
	log.Printf("user signup: %s", clean)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO Log flow when govalidator.NormalizeEmail is used; got id=%s", f.Sink.ID)
		}
	}
}

// --- govalidator.WhiteList ---

func TestAnalyzeGo_GovalidatorWhiteList_NeutralizesSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"

	"github.com/asaskevich/govalidator"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	col := r.FormValue("col")
	clean := govalidator.WhiteList(col, "a-z0-9_")
	db.Query("SELECT " + clean + " FROM t")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQLQuery flow when govalidator.WhiteList is used; got id=%s", f.Sink.ID)
		}
	}
}

// --- govalidator.BlackList ---

func TestAnalyzeGo_GovalidatorBlackList_NeutralizesCommandInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"

	"github.com/asaskevich/govalidator"
)

func handler(w http.ResponseWriter, r *http.Request) {
	arg := r.FormValue("arg")
	clean := govalidator.BlackList(arg, ";|&$<>")
	exec.Command("sh", "-c", "echo "+clean).Run()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("expected NO Command flow when govalidator.BlackList is used; got id=%s", f.Sink.ID)
		}
	}
}

// --- govalidator.StripLow ---

func TestAnalyzeGo_GovalidatorStripLow_NeutralizesLogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"

	"github.com/asaskevich/govalidator"
)

func handler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	clean := govalidator.StripLow(user)
	log.Printf("login: %s", clean)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO Log flow when govalidator.StripLow is used; got id=%s", f.Sink.ID)
		}
	}
}
