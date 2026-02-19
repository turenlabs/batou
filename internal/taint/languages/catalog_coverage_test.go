package languages

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// TestNewTaintCatalogEntries verifies that all newly added taint catalog
// entries (sinks, sources) are present in the registered catalogs.
func TestNewTaintCatalogEntries(t *testing.T) {
	// ---------- PHP sinks ----------
	phpSinks := taint.SinksForLanguage(rules.LangPHP)
	requireSinkID(t, phpSinks, "php.smarty.display", taint.SnkTemplate)
	requireSinkID(t, phpSinks, "php.smarty.fetch", taint.SnkTemplate)
	requireSinkID(t, phpSinks, "php.twig.render", taint.SnkTemplate)
	requireSinkID(t, phpSinks, "php.blade.render", taint.SnkTemplate)
	requireSinkID(t, phpSinks, "php.domxpath.query", taint.SnkXPath)
	requireSinkID(t, phpSinks, "php.domxpath.evaluate", taint.SnkXPath)
	requireSinkID(t, phpSinks, "php.simplexml.xpath", taint.SnkXPath)

	// ---------- JavaScript/TypeScript sinks ----------
	jsSinks := taint.SinksForLanguage(rules.LangJavaScript)
	requireSinkID(t, jsSinks, "js.ldapjs.search", taint.SnkLDAP)
	requireSinkID(t, jsSinks, "js.ldapjs.bind", taint.SnkLDAP)
	requireSinkID(t, jsSinks, "js.ldapjs.modify", taint.SnkLDAP)
	requireSinkID(t, jsSinks, "js.xpath.select", taint.SnkXPath)
	requireSinkID(t, jsSinks, "js.xpath.evaluate", taint.SnkXPath)
	requireSinkID(t, jsSinks, "js.xpath.select1", taint.SnkXPath)

	// TypeScript shares the same entries but with "ts." prefix
	tsSinks := taint.SinksForLanguage(rules.LangTypeScript)
	requireSinkID(t, tsSinks, "ts.ldapjs.search", taint.SnkLDAP)
	requireSinkID(t, tsSinks, "ts.xpath.select", taint.SnkXPath)

	// ---------- JavaScript/TypeScript sources ----------
	jsSources := taint.SourcesForLanguage(rules.LangJavaScript)
	requireSourceID(t, jsSources, "js.express.req.headers.xforwardedfor")
	requireSourceID(t, jsSources, "js.express.req.socket.remoteaddress")

	tsSources := taint.SourcesForLanguage(rules.LangTypeScript)
	requireSourceID(t, tsSources, "ts.express.req.headers.xforwardedfor")

	// ---------- Python sources ----------
	pySources := taint.SourcesForLanguage(rules.LangPython)
	requireSourceID(t, pySources, "py.sanic.request.args")
	requireSourceID(t, pySources, "py.sanic.request.json")
	requireSourceID(t, pySources, "py.sanic.request.form")
	requireSourceID(t, pySources, "py.sanic.request.body")

	// ---------- Python sinks ----------
	pySinks := taint.SinksForLanguage(rules.LangPython)
	requireSinkID(t, pySinks, "py.lxml.etree.xpath", taint.SnkXPath)
	requireSinkID(t, pySinks, "py.xml.etree.findall", taint.SnkXPath)
	requireSinkID(t, pySinks, "py.xml.etree.find", taint.SnkXPath)

	// ---------- Go sinks ----------
	goSinks := taint.SinksForLanguage(rules.LangGo)
	requireSinkID(t, goSinks, "go.template.js", taint.SnkTemplate)
	requireSinkID(t, goSinks, "go.template.css", taint.SnkTemplate)
	requireSinkID(t, goSinks, "go.template.htmlattr", taint.SnkTemplate)
}

func requireSinkID(t *testing.T, sinks []taint.SinkDef, id string, cat taint.SinkCategory) {
	t.Helper()
	for _, s := range sinks {
		if s.ID == id {
			if s.Category != cat {
				t.Errorf("sink %s: expected category %v, got %v", id, cat, s.Category)
			}
			return
		}
	}
	t.Errorf("sink %s not found in catalog (expected category %v)", id, cat)
}

func requireSourceID(t *testing.T, sources []taint.SourceDef, id string) {
	t.Helper()
	for _, s := range sources {
		if s.ID == id {
			return
		}
	}
	t.Errorf("source %s not found in catalog", id)
}
