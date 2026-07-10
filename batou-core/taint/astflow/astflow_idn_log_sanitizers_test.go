package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Modern Go IDN / hostname / URL / log-injection sanitizer tests.
//
// Validates the new sanitizer entries:
//   go.idna.toascii            (golang.org/x/net/idna — homograph defense)
//   go.url.parserequesturi     (strict absolute-URI validation)
//   go.netip.parseaddrport     (validated host:port)
//   go.mail.parseaddresslist   (RFC 5322 address-list validation)
//   go.strconv.quote           (control-byte / CRLF escaping)
//   go.strconv.quotetoascii    (ASCII-only Go-quoted form)
// =========================================================================

func TestCatalogMatcher_IDNLogSanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sanitizers := cat.Sanitizers()
	matcher := NewCatalogMatcher(nil, nil, sanitizers, nil)

	expected := map[string]string{
		"go.idna.toascii":          "ToASCII",
		"go.url.parserequesturi":   "ParseRequestURI",
		"go.netip.parseaddrport":   "ParseAddrPort",
		"go.mail.parseaddresslist": "ParseAddressList",
		"go.strconv.quote":         "Quote",
		"go.strconv.quotetoascii":  "QuoteToASCII",
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

func TestAnalyzeGo_IdnaToASCII_SanitizesSSRF(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/net/idna"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return
	}
	http.Get("https://" + ascii + "/data")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO URL-fetch flow when idna.ToASCII is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_UrlParseRequestURI_SanitizesSSRF(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("u")
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return
	}
	http.Get(u.String())
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO URL-fetch flow when url.ParseRequestURI is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_NetipParseAddrPort_SanitizesSSRF(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/netip"
)

func handler(w http.ResponseWriter, r *http.Request) {
	hp := r.FormValue("hp")
	ap, err := netip.ParseAddrPort(hp)
	if err != nil {
		return
	}
	http.Get("http://" + ap.String() + "/x")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO URL-fetch flow when netip.ParseAddrPort is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_MailParseAddressList_SanitizesHeader(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
	"net/mail"
)

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("to")
	addrs, err := mail.ParseAddressList(raw)
	if err != nil {
		return
	}
	log.Println("recipients", addrs)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog || f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO log/header flow when mail.ParseAddressList is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_StrconvQuote_SanitizesLog(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := strconv.Quote(name)
	log.Println("user", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO log flow when strconv.Quote wraps the tainted value; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_StrconvQuoteToASCII_SanitizesLog(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := strconv.QuoteToASCII(name)
	log.Println("user", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO log flow when strconv.QuoteToASCII is used; got id=%s", f.Sink.ID)
		}
	}
}

// Negative regression: the new sanitizers must NOT clear taint on a code path
// where they are not actually applied. Without the new sanitizers, tainted host
// reaches http.Get directly — the URL-fetch flow must still be reported.
func TestAnalyzeGo_IDNLogSanitizers_NoFalseSanitization(t *testing.T) {
	code := `package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	http.Get("https://" + host + "/data")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	got := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			got = true
			for _, s := range f.Steps {
				if containsAnyIDN(s.Description, []string{
					"sanitized by idna.ToASCII",
					"sanitized by url.ParseRequestURI",
					"sanitized by netip.ParseAddrPort",
					"sanitized by mail.ParseAddressList",
					"sanitized by strconv.Quote",
					"sanitized by strconv.QuoteToASCII",
				}) {
					t.Errorf("new sanitizer fired on un-sanitized SSRF path; flow=%s step=%s", f.Sink.ID, s.Description)
				}
			}
		}
	}
	if !got {
		t.Errorf("expected an URL-fetch flow on the un-sanitized handler (regression: catalog over-broadly sanitized)")
	}
}

func containsAnyIDN(s string, needles []string) bool {
	for _, n := range needles {
		if len(s) >= len(n) {
			for i := 0; i+len(n) <= len(s); i++ {
				if s[i:i+len(n)] == n {
					return true
				}
			}
		}
	}
	return false
}
