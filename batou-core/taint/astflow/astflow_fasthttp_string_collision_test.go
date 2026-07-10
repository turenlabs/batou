package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// flowHasSourceID reports whether any flow's source matches the given catalog ID.
func flowHasSourceID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Source.ID == id {
			return true
		}
	}
	return false
}

// TestAnalyzeGo_GinRedirectStringNotFasthttp is the load-bearing regression test
// for the gin CWE-601 open-redirect false positive. `req.URL.String()` on a
// *net/http.Request (req.URL is a *net/url.URL) was wrongly seeded as a
// github.com/valyala/fasthttp.RequestCtx external source: the receiver-name
// heuristic matched "req" against the catalog ObjectType
// "github.com/valyala/fasthttp.RequestCtx" because that string contains
// "http.Request" as a substring of "fasthttp.Request...". The name heuristic
// must require a package boundary, so a plain net/url.URL.String() is NOT seeded
// as fasthttp external input.
func TestAnalyzeGo_GinRedirectStringNotFasthttp(t *testing.T) {
	// Mirrors gin's redirectRequest: rURL is derived from req.URL.String() and
	// passed to http.Redirect. The only String() source here is on *url.URL, not
	// a fasthttp type.
	code := `package gin

import "net/http"

func redirectRequest(req *http.Request, w http.ResponseWriter) {
	rURL := req.URL.String()
	http.Redirect(w, req, rURL, http.StatusMovedPermanently)
}
`
	flows := AnalyzeGo(code, "/app/gin.go")

	// The bug: req.URL.String() seeded as a fasthttp RequestCtx (or any fasthttp
	// .String) external source. None of the fasthttp .String source entries must
	// match here.
	for _, badID := range []string{
		"go.comvalyalafasthttp.requestctx.string",
		"go.comvalyalafasthttp.requestheader.string",
		"go.comvalyalafasthttp.uri.string",
		"go.comvalyalafasthttp.args.string",
	} {
		if flowHasSourceID(flows, badID) {
			t.Errorf("req.URL.String() on *http.Request wrongly seeded as fasthttp source %q (gin CWE-601 open-redirect FP)", badID)
		}
	}

	// And specifically: no flow whose source is the SrcExternal fasthttp .String
	// mislabel should reach the redirect sink.
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal && f.Source.MethodName == "String" &&
			f.Sink.Category == taint.SnkRedirect {
			t.Errorf("unexpected external-String -> redirect flow (fasthttp mislabel): source=%s", f.Source.ID)
		}
	}
}

// TestMatchesReceiverType_FasthttpSubstringCollision unit-tests the boundary fix
// directly: the net/http receiver-name heuristic must NOT fire for fasthttp
// ObjectTypes that merely contain "http.Request" as a substring, but MUST still
// fire for genuine net/http types.
func TestMatchesReceiverType_FasthttpSubstringCollision(t *testing.T) {
	cases := []struct {
		recv    string
		objType string
		want    bool
		note    string
	}{
		// The bug: "req" must NOT match fasthttp.RequestCtx / RequestHeader.
		{"req", "github.com/valyala/fasthttp.RequestCtx", false, "fasthttp.RequestCtx substring collision"},
		{"r", "github.com/valyala/fasthttp.RequestCtx", false, "fasthttp.RequestCtx substring collision"},
		{"request", "github.com/valyala/fasthttp.RequestHeader", false, "fasthttp.RequestHeader substring collision"},
		// Genuine net/http types must still resolve by receiver name.
		{"req", "*http.Request", true, "net/http.Request still matches req"},
		{"r", "*net/http.Request", true, "qualified net/http.Request still matches r"},
		{"w", "http.ResponseWriter", true, "net/http.ResponseWriter still matches w"},
		{"resp", "net/http.ResponseWriter", true, "qualified ResponseWriter still matches resp"},
	}
	for _, c := range cases {
		if got := matchesReceiverType(c.recv, c.objType); got != c.want {
			t.Errorf("matchesReceiverType(%q, %q) = %v, want %v (%s)", c.recv, c.objType, got, c.want, c.note)
		}
	}
}

// TestPkgQualifiedTypeContains exercises the boundary helper in isolation.
func TestPkgQualifiedTypeContains(t *testing.T) {
	cases := []struct {
		objType string
		want    string
		expect  bool
	}{
		{"github.com/valyala/fasthttp.RequestCtx", "http.Request", false},
		{"github.com/valyala/fasthttp.RequestHeader", "http.Request", false},
		{"*http.Request", "http.Request", true},
		{"net/http.Request", "http.Request", true},
		{"http.Request", "http.Request", true},
		{"http.ResponseWriter", "http.ResponseWriter", true},
		{"github.com/valyala/fasthttp.URI", "http.Request", false},
	}
	for _, c := range cases {
		if got := pkgQualifiedTypeContains(c.objType, c.want); got != c.expect {
			t.Errorf("pkgQualifiedTypeContains(%q, %q) = %v, want %v", c.objType, c.want, got, c.expect)
		}
	}
}
