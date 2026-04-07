package languages

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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

	// ---------- Kotlin sinks (XXE + SSRF) ----------
	ktSinks := taint.SinksForLanguage(rules.LangKotlin)
	requireSinkID(t, ktSinks, "kotlin.xml.documentbuilder.parse", taint.SnkXPath)
	requireSinkID(t, ktSinks, "kotlin.xml.saxparser.parse", taint.SnkXPath)
	requireSinkID(t, ktSinks, "kotlin.xml.xmlinputfactory", taint.SnkXPath)
	requireSinkID(t, ktSinks, "kotlin.xml.transformer", taint.SnkXPath)
	requireSinkID(t, ktSinks, "kotlin.fuel.httpget", taint.SnkURLFetch)
	requireSinkID(t, ktSinks, "kotlin.fuel.request", taint.SnkURLFetch)
	requireSinkID(t, ktSinks, "kotlin.retrofit.url", taint.SnkURLFetch)
	requireSinkID(t, ktSinks, "kotlin.httpurlconnection", taint.SnkURLFetch)

	// ---------- C# sanitizers ----------
	csSanitizers := taint.SanitizersForLanguage(rules.LangCSharp)
	// Log injection
	requireSanitizerID(t, csSanitizers, "csharp.serilog.structured", taint.SnkLog)
	requireSanitizerID(t, csSanitizers, "csharp.nlog.structured", taint.SnkLog)
	requireSanitizerID(t, csSanitizers, "csharp.ilogger.structured", taint.SnkLog)
	requireSanitizerID(t, csSanitizers, "csharp.string.replace.crlf", taint.SnkLog)
	// SSRF
	requireSanitizerID(t, csSanitizers, "csharp.uri.trycreate", taint.SnkURLFetch)
	requireSanitizerID(t, csSanitizers, "csharp.uri.escapedatastring", taint.SnkURLFetch)
	requireSanitizerID(t, csSanitizers, "csharp.ipaddress.tryparse", taint.SnkURLFetch)
	// Deserialization
	requireSanitizerID(t, csSanitizers, "csharp.xmldoc.resolver.null", taint.SnkDeserialize)
	requireSanitizerID(t, csSanitizers, "csharp.xdocument.parse", taint.SnkDeserialize)
	requireSanitizerID(t, csSanitizers, "csharp.jsondocument.parse", taint.SnkDeserialize)
	// JavaScript encoding
	requireSanitizerID(t, csSanitizers, "csharp.jsencoder.encode", taint.SnkHTMLOutput)
	// Type-safe parsing
	requireSanitizerID(t, csSanitizers, "csharp.guid.parse", taint.SnkSQLQuery)
	requireSanitizerID(t, csSanitizers, "csharp.enum.parse", taint.SnkSQLQuery)
	requireSanitizerID(t, csSanitizers, "csharp.bool.parse", taint.SnkSQLQuery)
	requireSanitizerID(t, csSanitizers, "csharp.datetime.parse", taint.SnkSQLQuery)
	requireSanitizerID(t, csSanitizers, "csharp.long.parse", taint.SnkSQLQuery)
	// XML safety
	requireSanitizerID(t, csSanitizers, "csharp.securityelement.escape", taint.SnkDeserialize)

	// ---------- Kotlin sanitizers ----------
	ktSanitizers := taint.SanitizersForLanguage(rules.LangKotlin)
	// Command injection
	requireSanitizerID(t, ktSanitizers, "kotlin.processbuilder.list", taint.SnkCommand)
	requireSanitizerID(t, ktSanitizers, "kotlin.runtime.exec.array", taint.SnkCommand)
	requireSanitizerID(t, ktSanitizers, "kotlin.commons.exec.commandline", taint.SnkCommand)
	// Deserialization
	requireSanitizerID(t, ktSanitizers, "kotlin.objectinputfilter", taint.SnkDeserialize)
	requireSanitizerID(t, ktSanitizers, "kotlin.jackson.defaulttyping.safe", taint.SnkDeserialize)
	requireSanitizerID(t, ktSanitizers, "kotlin.kotlinx.serialization.json", taint.SnkDeserialize)
	// Header injection
	requireSanitizerID(t, ktSanitizers, "kotlin.header.newline.strip", taint.SnkHeader)
	requireSanitizerID(t, ktSanitizers, "kotlin.spring.httpheaders", taint.SnkHeader)
	requireSanitizerID(t, ktSanitizers, "kotlin.ktor.respondtext.contenttype", taint.SnkHeader)
	// SSRF
	requireSanitizerID(t, ktSanitizers, "kotlin.url.gethost", taint.SnkURLFetch)
	requireSanitizerID(t, ktSanitizers, "kotlin.inetaddress.issitelocal", taint.SnkURLFetch)
	requireSanitizerID(t, ktSanitizers, "kotlin.apache.urlvalidator", taint.SnkURLFetch)
	requireSanitizerID(t, ktSanitizers, "kotlin.uri.host.check", taint.SnkURLFetch)

	// ---------- Rust sanitizers ----------
	rustSanitizers := taint.SanitizersForLanguage(rules.LangRust)
	// Command injection
	requireSanitizerID(t, rustSanitizers, "rust.shell_escape.escape", taint.SnkCommand)
	requireSanitizerID(t, rustSanitizers, "rust.shlex.try_quote", taint.SnkCommand)
	requireSanitizerID(t, rustSanitizers, "rust.shell_words.join", taint.SnkCommand)
	// Log injection
	requireSanitizerID(t, rustSanitizers, "rust.log.sanitize_newlines", taint.SnkLog)
	requireSanitizerID(t, rustSanitizers, "rust.log.filter_control", taint.SnkLog)
	requireSanitizerID(t, rustSanitizers, "rust.tracing.structured_field", taint.SnkLog)
	// Open redirect
	requireSanitizerID(t, rustSanitizers, "rust.url.host_check", taint.SnkRedirect)
	requireSanitizerID(t, rustSanitizers, "rust.url.origin", taint.SnkRedirect)
	// Deserialization
	requireSanitizerID(t, rustSanitizers, "rust.serde.typed_deser", taint.SnkDeserialize)
	requireSanitizerID(t, rustSanitizers, "rust.serde_valid.validate", taint.SnkDeserialize)
	requireSanitizerID(t, rustSanitizers, "rust.bincode.with_limit", taint.SnkDeserialize)
	requireSanitizerID(t, rustSanitizers, "rust.serde.typed_toml", taint.SnkDeserialize)
	// Header injection
	requireSanitizerID(t, rustSanitizers, "rust.http.header_value_from_str", taint.SnkHeader)
	requireSanitizerID(t, rustSanitizers, "rust.http.header_value_from_bytes", taint.SnkHeader)
	requireSanitizerID(t, rustSanitizers, "rust.header.strip_crlf", taint.SnkHeader)

	// ---------- Lua sinks (SQL + SSRF + XXE) ----------
	luaSinks := taint.SinksForLanguage(rules.LangLua)
	requireSinkID(t, luaSinks, "lua.pgmoon.query", taint.SnkSQLQuery)
	requireSinkID(t, luaSinks, "lua.pgmoon.simple_query", taint.SnkSQLQuery)
	requireSinkID(t, luaSinks, "lua.luasql.execute", taint.SnkSQLQuery)
	requireSinkID(t, luaSinks, "lua.luadbi.prepare", taint.SnkSQLQuery)
	requireSinkID(t, luaSinks, "lua.tarantool.box.execute", taint.SnkSQLQuery)
	requireSinkID(t, luaSinks, "lua.lxp.new", taint.SnkDeserialize)
	requireSinkID(t, luaSinks, "lua.ngx.socket.tcp.connect", taint.SnkURLFetch)
	requireSinkID(t, luaSinks, "lua.socket.tcp.connect", taint.SnkURLFetch)
	requireSinkID(t, luaSinks, "lua.tarantool.box.eval", taint.SnkEval)
	requireSinkID(t, luaSinks, "lua.luasql.env.connect.execute", taint.SnkSQLQuery)
	requireSinkID(t, luaSinks, "lua.lxp.parse", taint.SnkDeserialize)
	requireSinkID(t, luaSinks, "lua.lfs.mkdir", taint.SnkFileWrite)
	requireSinkID(t, luaSinks, "lua.lfs.rmdir", taint.SnkFileWrite)
	requireSinkID(t, luaSinks, "lua.lfs.chdir", taint.SnkFileWrite)
	requireSinkID(t, luaSinks, "lua.ngx.req.set_uri", taint.SnkRedirect)

	// ---------- Lua sanitizers ----------
	luaSanitizers := taint.SanitizersForLanguage(rules.LangLua)
	requireSanitizerID(t, luaSanitizers, "lua.pgmoon.escape_literal", taint.SnkSQLQuery)
	requireSanitizerID(t, luaSanitizers, "lua.pgmoon.escape_identifier", taint.SnkSQLQuery)
	requireSanitizerID(t, luaSanitizers, "lua.pgmoon.parameterized", taint.SnkSQLQuery)
	requireSanitizerID(t, luaSanitizers, "lua.url.parse.host_check", taint.SnkURLFetch)
	requireSanitizerID(t, luaSanitizers, "lua.tostring.sanitizer", taint.SnkSQLQuery)
	requireSanitizerID(t, luaSanitizers, "lua.tarantool.box.execute.params", taint.SnkSQLQuery)
	requireSanitizerID(t, luaSanitizers, "lua.luasql.prepare", taint.SnkSQLQuery)
	requireSanitizerID(t, luaSanitizers, "lua.lxp.threat", taint.SnkDeserialize)
	requireSanitizerID(t, luaSanitizers, "lua.string.sub.limit", taint.SnkLog)

	// ---------- Zig sinks ----------
	zigSinks := taint.SinksForLanguage(rules.LangZig)
	requireSinkID(t, zigSinks, "zig.http.Client.fetch", taint.SnkURLFetch)
	requireSinkID(t, zigSinks, "zig.http.Client.request", taint.SnkURLFetch)
	requireSinkID(t, zigSinks, "zig.http.Client.open", taint.SnkURLFetch)
	requireSinkID(t, zigSinks, "zig.net.tcpConnectToHost", taint.SnkURLFetch)
	requireSinkID(t, zigSinks, "zig.net.Address.resolveIp", taint.SnkURLFetch)
	requireSinkID(t, zigSinks, "zig.builtin.memcpy", taint.SnkCommand)
	requireSinkID(t, zigSinks, "zig.builtin.memset", taint.SnkCommand)
	requireSinkID(t, zigSinks, "zig.mem.copyForwards", taint.SnkCommand)
	requireSinkID(t, zigSinks, "zig.mem.copyBackwards", taint.SnkCommand)
	requireSinkID(t, zigSinks, "zig.crypto.Md5", taint.SnkCrypto)
	requireSinkID(t, zigSinks, "zig.crypto.Sha1", taint.SnkCrypto)
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

// ---------- Perl sinks (XXE + Trust Boundary + Email Injection) ----------
func TestPerlSinkEntries(t *testing.T) {
	sinks := taint.SinksForLanguage(rules.LangPerl)

	// XXE sinks (CWE-611)
	requireSinkID(t, sinks, "perl.xml.simple.xmlin", taint.SnkDeserialize)
	requireSinkID(t, sinks, "perl.xml.parser.parse", taint.SnkDeserialize)
	requireSinkID(t, sinks, "perl.xml.twig.parse", taint.SnkDeserialize)
	requireSinkID(t, sinks, "perl.xml.sax.parse", taint.SnkDeserialize)
	requireSinkID(t, sinks, "perl.xml.libxml.parse", taint.SnkDeserialize)

	// Trust boundary sinks (CWE-501)
	requireSinkID(t, sinks, "perl.cgi.session.param", taint.SnkTrustBoundary)
	requireSinkID(t, sinks, "perl.cgi.session.save_param", taint.SnkTrustBoundary)
	requireSinkID(t, sinks, "perl.apache.session.assign", taint.SnkTrustBoundary)

	// Email header injection sinks (CWE-93)
	requireSinkID(t, sinks, "perl.net.smtp.datasend", taint.SnkHeader)
	requireSinkID(t, sinks, "perl.mime.lite.new", taint.SnkHeader)
	requireSinkID(t, sinks, "perl.mime.lite.add", taint.SnkHeader)
	requireSinkID(t, sinks, "perl.email.simple.create", taint.SnkHeader)
}

// ---------- Perl sanitizers ----------
func TestPerlSanitizerEntries(t *testing.T) {
	sans := taint.SanitizersForLanguage(rules.LangPerl)

	// New SSRF sanitizers
	requireSanitizerID(t, sans, "perl.data.validate.uri", taint.SnkURLFetch)
	requireSanitizerID(t, sans, "perl.uri.host.check", taint.SnkURLFetch)
	requireSanitizerID(t, sans, "perl.lwp.protocols.allowed", taint.SnkURLFetch)

	// New LDAP sanitizers
	requireSanitizerID(t, sans, "perl.net.ldap.escape", taint.SnkLDAP)
	requireSanitizerID(t, sans, "perl.net.ldap.escape.dn", taint.SnkLDAP)

	// New header/log sanitizers
	requireSanitizerID(t, sans, "perl.header.crlf.strip", taint.SnkHeader)
	requireSanitizerID(t, sans, "perl.log.sanitize.crlf", taint.SnkLog)

	// New redirect sanitizer
	requireSanitizerID(t, sans, "perl.redirect.host.allowlist", taint.SnkRedirect)

	// New deserialization sanitizer
	requireSanitizerID(t, sans, "perl.sereal.safe", taint.SnkDeserialize)

	// XXE prevention sanitizers
	requireSanitizerID(t, sans, "perl.xml.twig.no_xxe", taint.SnkDeserialize)
	requireSanitizerID(t, sans, "perl.xml.libxml.safe.xxe", taint.SnkDeserialize)
	requireSanitizerID(t, sans, "perl.xml.parser.externent", taint.SnkDeserialize)

	// Email header injection sanitizers
	requireSanitizerID(t, sans, "perl.email.address.parse", taint.SnkHeader)
	requireSanitizerID(t, sans, "perl.email.crlf.strip", taint.SnkHeader)

	// Trust boundary sanitizer
	requireSanitizerID(t, sans, "perl.session.validate", taint.SnkTrustBoundary)
}

func requireSanitizerID(t *testing.T, sanitizers []taint.SanitizerDef, id string, cat taint.SinkCategory) {
	t.Helper()
	for _, s := range sanitizers {
		if s.ID == id {
			for _, n := range s.Neutralizes {
				if n == cat {
					return
				}
			}
			t.Errorf("sanitizer %s: expected to neutralize %v, got %v", id, cat, s.Neutralizes)
			return
		}
	}
	t.Errorf("sanitizer %s not found in catalog (expected to neutralize %v)", id, cat)
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
