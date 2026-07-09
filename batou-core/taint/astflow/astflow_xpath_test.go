package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func TestAnalyzeGo_XPath_XmlqueryFind(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

func handler(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("q")
	doc, _ := xmlquery.Parse(r.Body)
	xmlquery.Find(doc, expr)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for URL.Query().Get -> xmlquery.Find")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_XPath_XmlqueryQueryAll(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

func handler(w http.ResponseWriter, r *http.Request) {
	xp := r.FormValue("xp")
	doc, _ := xmlquery.Parse(r.Body)
	xmlquery.QueryAll(doc, xp)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for FormValue -> xmlquery.QueryAll")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_XPath_XmlqueryFindEach(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	doc, _ := xmlquery.Parse(r.Body)
	xmlquery.FindEach(doc, q, func(i int, n *xmlquery.Node) {})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for FormValue -> xmlquery.FindEach")
	}
}

func TestAnalyzeGo_XPath_JsonqueryFind(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/jsonquery"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	doc, _ := jsonquery.Parse(r.Body)
	jsonquery.Find(doc, path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for URL.Query().Get -> jsonquery.Find")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_XPath_JsonqueryQueryAll(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/jsonquery"
)

func handler(w http.ResponseWriter, r *http.Request) {
	expr := r.FormValue("q")
	doc, _ := jsonquery.Parse(r.Body)
	jsonquery.QueryAll(doc, expr)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for FormValue -> jsonquery.QueryAll")
	}
}

func TestAnalyzeGo_XPath_EtreeCompilePath(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/beevik/etree"
)

func handler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("p")
	etree.CompilePath(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for URL.Query().Get -> etree.CompilePath")
	}
}

func TestAnalyzeGo_XPath_AntchfxXpathSelect(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	expr := r.FormValue("expr")
	doc, _ := xmlquery.Parse(r.Body)
	xpath.Select(xmlquery.CreateXPathNavigator(doc), expr)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for FormValue -> xpath.Select")
	}
}

func TestAnalyzeGo_XPath_AntchfxXpathCompileWithNS(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/antchfx/xpath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	xpath.CompileWithNS(expr, map[string]string{"a": "urn:a"})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath taint flow for URL.Query().Get -> xpath.CompileWithNS")
	}
}

func TestCatalogMatcher_XPathSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(cat.Sources(), sinks, cat.Sanitizers(), nil)

	expectedMethods := []string{
		"Find",            // xmlquery, jsonquery, htmlquery
		"FindOne",         // xmlquery, jsonquery
		"Query",           // xmlquery, jsonquery
		"QueryAll",        // xmlquery, jsonquery
		"FindEach",        // xmlquery
		"CompilePath",     // etree
		"MustCompilePath", // etree
		"Select",          // antchfx/xpath
		"CompileWithNS",   // antchfx/xpath
	}

	for _, method := range expectedMethods {
		found := false
		for _, sink := range matcher.sinksByMethod[method] {
			if sink.Category == taint.SnkXPath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as an XPath sink", method)
		}
	}
}
