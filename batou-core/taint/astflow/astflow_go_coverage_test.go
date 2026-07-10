package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register the Go taint catalog (sources/sinks/sanitizers).
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// hasSinkCWE reports whether any flow reaches a sink with the given CWE.
// (hasSinkID is defined in astflow_redirect_test.go.)
func hasSinkCWE(flows []taint.TaintFlow, cwe string) bool {
	for _, f := range flows {
		if f.Sink.CWEID == cwe {
			return true
		}
	}
	return false
}

// =========================================================================
// Catalog registration — the new Go coverage sinks must be present.
// =========================================================================

func TestGoCoverage_NewSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}
	want := map[string]string{
		"go.text.template.parse":             "*template.Template",
		"go.jwt.parser.parseunverified":      "*jwt.Parser",
		"go.gomail.message.setheader":        "*gomail.Message",
		"go.gomail.message.setaddressheader": "*gomail.Message",
	}
	got := map[string]string{}
	for _, s := range cat.Sinks() {
		if _, ok := want[s.ID]; ok {
			got[s.ID] = s.ObjectType
			// IRON RULE: every new sink must be receiver-typed, never bare.
			if s.ObjectType == "" {
				t.Errorf("sink %q has empty ObjectType (bare-name collision risk)", s.ID)
			}
		}
	}
	for id, ot := range want {
		if got[id] != ot {
			t.Errorf("sink %q: ObjectType = %q, want %q", id, got[id], ot)
		}
	}
}

// =========================================================================
// text/template Parse SSTI (CWE-94) — tainted template BODY.
// =========================================================================

func TestGoCoverage_TextTemplateParseSSTI(t *testing.T) {
	code := `package main

import (
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.URL.Query().Get("tpl")
	t := template.New("x")
	t.Parse(body)
	t.Execute(w, nil)
}
`
	flows := AnalyzeGo(code, "/app/ssti.go")
	if !hasSinkCWE(flows, "CWE-94") {
		t.Error("expected CWE-94 SSTI flow: request -> template.Parse(body)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestGoCoverage_TextTemplateParseFileRead_Safe(t *testing.T) {
	// Loading a template DEFINITION from a file / embedded FS is the dominant
	// benign template-loader pattern — a file_read source reaching Parse must
	// NOT fire (only a REQUEST-controlled template body is SSTI).
	code := `package main

import (
	"os"
	"text/template"
)

func load(path string) (*template.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t := template.New("x")
	return t.Parse(string(data))
}
`
	flows := AnalyzeGo(code, "/app/loader.go")
	if hasSinkID(flows, "go.text.template.parse") {
		t.Error("did not expect an SSTI flow when the template body comes from a file read")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestGoCoverage_TextTemplateParseConstant_Safe(t *testing.T) {
	// A constant template body carries no taint — must NOT fire.
	code := `package main

import (
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	_ = r
	t := template.New("x")
	t.Parse("Hello {{.Name}}")
	t.Execute(w, nil)
}
`
	flows := AnalyzeGo(code, "/app/safe_tmpl.go")
	if hasSinkID(flows, "go.text.template.parse") {
		t.Error("did not expect a Parse SSTI flow for a constant template literal")
	}
}

// =========================================================================
// JWT ParseUnverified signature bypass (CWE-347).
// =========================================================================

func TestGoCoverage_JWTParseUnverified(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func auth(r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	parser.ParseUnverified(tokenStr, claims)
}
`
	flows := AnalyzeGo(code, "/app/jwt.go")
	if !hasSinkCWE(flows, "CWE-347") {
		t.Error("expected CWE-347 flow: request header -> jwt Parser.ParseUnverified")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// =========================================================================
// gomail header injection (CWE-93) — tainted header value, sanitizer-aware.
// =========================================================================

func TestGoCoverage_GomailHeaderInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"gopkg.in/gomail.v2"
)

func send(r *http.Request) {
	subject := r.URL.Query().Get("subject")
	m := gomail.NewMessage()
	m.SetHeader("Subject", subject)
}
`
	flows := AnalyzeGo(code, "/app/mail.go")
	if !hasSinkCWE(flows, "CWE-93") {
		t.Error("expected CWE-93 flow: request -> gomail Message.SetHeader value")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestGoCoverage_GomailHeaderSanitized_Safe(t *testing.T) {
	// Stripping CR/LF from the value before SetHeader neutralizes the
	// header-injection flow.
	code := `package main

import (
	"net/http"
	"strings"

	"gopkg.in/gomail.v2"
)

func send(r *http.Request) {
	raw := r.URL.Query().Get("subject")
	subject := strings.ReplaceAll(strings.ReplaceAll(raw, "\r", ""), "\n", "")
	m := gomail.NewMessage()
	m.SetHeader("Subject", subject)
}
`
	flows := AnalyzeGo(code, "/app/mail_safe.go")
	if hasSinkID(flows, "go.gomail.message.setheader") {
		t.Error("did not expect a header-injection flow after CRLF stripping")
	}
}
