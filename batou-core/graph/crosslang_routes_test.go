package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestNormalizeRoutePath locks the path-canonicalisation contract the
// matcher relies on: an outbound `"/api/x?q=" + v` and a registered
// `/api/x` must normalise to the same key.
func TestNormalizeRoutePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/api/items", "/api/items"},
		{"/api/items?q=", "/api/items"},
		{"/api/items?q=1&sort=2", "/api/items"},
		{"/api/items/", "/api/items"},
		{"api/items", "/api/items"},
		{`"/api/items"`, "/api/items"},
		{"/api/items#frag", "/api/items"},
		{"/api/items/${id}", "/api/items"},
		{"  /api/items  ", "/api/items"},
		{"", ""},
		{"/", ""},
		{"?q=1", ""},
	}
	for _, tc := range cases {
		if got := NormalizeRoutePath(tc.in); got != tc.want {
			t.Errorf("NormalizeRoutePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// makeHandlerNode builds a route-handler node with a SQL sink so the
// matcher has something to flag.
func makeHandlerNode(id, file, path string, lang rules.Language) *FuncNode {
	return &FuncNode{
		ID:          id,
		FilePath:    file,
		Name:        "handler",
		Language:    lang,
		StartLine:   1,
		EndLine:     10,
		RoutePath:   path,
		RouteMethod: "",
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{
				{SinkCategory: taint.SnkSQLQuery, MethodName: "execute", Line: 5, ArgFromParam: -1},
			},
		},
	}
}

// makeOutboundNode builds a caller node issuing a tainted outbound request
// to the given path.
func makeOutboundNode(id, file, path string) *FuncNode {
	return &FuncNode{
		ID:        id,
		FilePath:  file,
		Name:      "caller",
		Language:  rules.LangJavaScript,
		StartLine: 1,
		EndLine:   5,
		OutboundRequests: []OutboundRequest{
			{Path: path, Line: 2, TaintedArg: "req.query.q", SourceCategory: string(taint.SrcUserInput)},
		},
	}
}

// TestLinkServiceBoundaryEdges_Match is the positive matcher unit: a JS
// outbound request to /api/items must link to a Python handler for the
// same path and synthesise a cross-language CWE-89 finding with a
// two-file taint path and a cross-file Calls edge.
func TestLinkServiceBoundaryEdges_Match(t *testing.T) {
	cg := NewCallGraph("/proj", "sess")
	caller := makeOutboundNode("/proj/web/client.js:caller", "/proj/web/client.js", "/api/items")
	handler := makeHandlerNode("/proj/api/server.py:handler", "/proj/api/server.py", "/api/items", rules.LangPython)
	cg.AddNode(caller)
	cg.AddNode(handler)

	findings := linkServiceBoundaryEdges(cg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 cross-language finding, got %d", len(findings))
	}
	f := findings[0]
	if f.CWEID != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.CWEID)
	}
	if f.RuleID != "BATOU-CROSSLANG-SQL_QUERY" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	// Taint path must span both files.
	sawJS, sawPySink := false, false
	for _, s := range f.TaintPath {
		if s.File == caller.FilePath {
			sawJS = true
		}
		if s.File == handler.FilePath && s.Kind == rules.TaintStepSink {
			sawPySink = true
		}
	}
	if !sawJS || !sawPySink {
		t.Errorf("taint path does not span both files: %+v", f.TaintPath)
	}
	// A cross-file dependency edge must have been added.
	if !containsStr(caller.Calls, handler.ID) {
		t.Errorf("expected cross-file edge caller→handler; caller.Calls=%v", caller.Calls)
	}
	if !containsStr(handler.CalledBy, caller.ID) {
		t.Errorf("expected back-edge handler.CalledBy←caller; handler.CalledBy=%v", handler.CalledBy)
	}
}

// TestLinkServiceBoundaryEdges_NoMatch is the negative matcher unit: an
// outbound path with no registered handler produces nothing.
func TestLinkServiceBoundaryEdges_NoMatch(t *testing.T) {
	cg := NewCallGraph("/proj", "sess")
	cg.AddNode(makeOutboundNode("/proj/web/client.js:caller", "/proj/web/client.js", "/api/products"))
	cg.AddNode(makeHandlerNode("/proj/api/server.py:handler", "/proj/api/server.py", "/api/items", rules.LangPython))

	if findings := linkServiceBoundaryEdges(cg); len(findings) != 0 {
		t.Fatalf("mismatched path must produce no finding, got %d", len(findings))
	}
}

// TestLinkServiceBoundaryEdges_SameFileSkipped ensures a same-file
// outbound→handler pair is left to the in-language layers (the cross-
// language matcher only links across files).
func TestLinkServiceBoundaryEdges_SameFileSkipped(t *testing.T) {
	cg := NewCallGraph("/proj", "sess")
	caller := makeOutboundNode("/proj/app.js:caller", "/proj/app.js", "/api/items")
	handler := makeHandlerNode("/proj/app.js:handler", "/proj/app.js", "/api/items", rules.LangJavaScript)
	cg.AddNode(caller)
	cg.AddNode(handler)

	if findings := linkServiceBoundaryEdges(cg); len(findings) != 0 {
		t.Fatalf("same-file pair must be skipped, got %d", len(findings))
	}
}

// TestLinkServiceBoundaryEdges_MethodMismatch ensures an explicit method
// mismatch (outbound POST vs handler GET) is not linked, while an
// unspecified method matches.
func TestLinkServiceBoundaryEdges_MethodMismatch(t *testing.T) {
	cg := NewCallGraph("/proj", "sess")
	caller := makeOutboundNode("/proj/web/client.js:caller", "/proj/web/client.js", "/api/items")
	caller.OutboundRequests[0].Method = "post"
	handler := makeHandlerNode("/proj/api/server.py:handler", "/proj/api/server.py", "/api/items", rules.LangPython)
	handler.RouteMethod = "get"
	cg.AddNode(caller)
	cg.AddNode(handler)

	if findings := linkServiceBoundaryEdges(cg); len(findings) != 0 {
		t.Fatalf("POST→GET method mismatch must not link, got %d", len(findings))
	}
}
