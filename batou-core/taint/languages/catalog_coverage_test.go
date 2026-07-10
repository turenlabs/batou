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
	// DuckDB + Polars SQL injection
	requireSinkID(t, pySinks, "py.duckdb.sql", taint.SnkSQLQuery)
	requireSinkID(t, pySinks, "py.duckdb.execute", taint.SnkSQLQuery)
	requireSinkID(t, pySinks, "py.duckdb.query", taint.SnkSQLQuery)
	requireSinkID(t, pySinks, "py.duckdb.connection.sql", taint.SnkSQLQuery)
	requireSinkID(t, pySinks, "py.polars.read_database", taint.SnkSQLQuery)
	requireSinkID(t, pySinks, "py.polars.read_database_uri", taint.SnkSQLQuery)
	// Cassandra / ScyllaDB CQL injection (CWE-943)
	requireSinkID(t, pySinks, "py.cassandra.simplestatement", taint.SnkNoSQL)
	requireSinkID(t, pySinks, "py.cassandra.session.execute_async", taint.SnkNoSQL)
	requireSinkID(t, pySinks, "py.cassandra.execute_concurrent", taint.SnkNoSQL)
	requireSinkID(t, pySinks, "py.cassandra.execute_concurrent_with_args", taint.SnkNoSQL)
	// CSV / spreadsheet formula injection (CWE-1236)
	requireSinkID(t, pySinks, "py.csv.writer.writerow", taint.SnkCSV)
	requireSinkID(t, pySinks, "py.csv.writer.writerows", taint.SnkCSV)
	requireSinkID(t, pySinks, "py.pandas.to_csv", taint.SnkCSV)

	// ---------- Python sanitizers ----------
	pySans := taint.SanitizersForLanguage(rules.LangPython)
	requireSanitizerID(t, pySans, "py.defusedcsv.writer", taint.SnkCSV)
	requireSanitizerID(t, pySans, "py.defusedcsv.dictwriter", taint.SnkCSV)

	// ---------- JavaScript/TypeScript CSV sinks (CWE-1236) ----------
	requireSinkID(t, jsSinks, "js.papaparse.unparse", taint.SnkCSV)
	requireSinkID(t, jsSinks, "js.fastcsv.writetostring", taint.SnkCSV)
	requireSinkID(t, tsSinks, "ts.papaparse.unparse", taint.SnkCSV)

	// ---------- Java CSV sinks (CWE-1236) ----------
	javaSinks := taint.SinksForLanguage(rules.LangJava)
	requireSinkID(t, javaSinks, "java.opencsv.csvwriter.writenext", taint.SnkCSV)
	requireSinkID(t, javaSinks, "java.opencsv.csvwriter.writeall", taint.SnkCSV)
	requireSinkID(t, javaSinks, "java.commonscsv.csvprinter.printrecord", taint.SnkCSV)
	requireSinkID(t, javaSinks, "java.commonscsv.csvprinter.printrecords", taint.SnkCSV)

	// ---------- PHP CSV sink (CWE-1236) ----------
	requireSinkID(t, phpSinks, "php.fputcsv", taint.SnkCSV)

	// ---------- Ruby CSV sink (CWE-1236) ----------
	rubySinks := taint.SinksForLanguage(rules.LangRuby)
	requireSinkID(t, rubySinks, "ruby.csv.addrow", taint.SnkCSV)

	// ---------- Unrestricted file upload sinks (CWE-434) — SnkUpload ----------
	requireSinkID(t, pySinks, "py.werkzeug.filestorage.save", taint.SnkUpload)
	requireSinkID(t, pySinks, "py.django.storage.save", taint.SnkUpload)
	requireSinkID(t, pySinks, "py.shutil.copyfileobj", taint.SnkUpload)
	requireSinkID(t, jsSinks, "js.expressfileupload.mv", taint.SnkUpload)
	requireSinkID(t, jsSinks, "js.multer.constructor", taint.SnkUpload)
	requireSinkID(t, tsSinks, "ts.expressfileupload.mv", taint.SnkUpload)
	requireSinkID(t, javaSinks, "java.spring.multipartfile.transferto", taint.SnkUpload)
	requireSinkID(t, phpSinks, "php.move_uploaded_file", taint.SnkUpload)
	requireSinkID(t, rubySinks, "ruby.carrierwave.store", taint.SnkUpload)
	requireSinkID(t, rubySinks, "ruby.shrine.upload", taint.SnkUpload)

	// ---------- Unrestricted file upload sanitizers (CWE-434) — SnkUpload ----------
	requireSanitizerID(t, pySans, "py.werkzeug.secure_filename", taint.SnkUpload)
	requireSanitizerID(t, pySans, "py.magic.from_buffer", taint.SnkUpload)
	requireSanitizerID(t, pySans, "py.imghdr.what", taint.SnkUpload)
	jsSanitizers := taint.SanitizersForLanguage(rules.LangJavaScript)
	requireSanitizerID(t, jsSanitizers, "js.filetype.fromtokenizer", taint.SnkUpload)
	javaSanitizers := taint.SanitizersForLanguage(rules.LangJava)
	requireSanitizerID(t, javaSanitizers, "java.tika.detect", taint.SnkUpload)
	requireSanitizerID(t, javaSanitizers, "java.urlconnection.guesscontenttype", taint.SnkUpload)

	// ---------- Go sinks ----------
	goSinks := taint.SinksForLanguage(rules.LangGo)
	requireSinkID(t, goSinks, "go.template.js", taint.SnkTemplate)
	requireSinkID(t, goSinks, "go.template.css", taint.SnkTemplate)
	requireSinkID(t, goSinks, "go.template.htmlattr", taint.SnkTemplate)
	// CSV / spreadsheet formula injection (CWE-1236)
	requireSinkID(t, goSinks, "go.encoding.csv.writeall", taint.SnkCSV)

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
	// LDAP injection sinks (CWE-90)
	requireSinkID(t, ktSinks, "kotlin.ldap.dircontext.bind", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.dircontext.rebind", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.dircontext.createsubcontext", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.dircontext.modifyattributes", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.dircontext.rename", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.spring.search", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.spring.bind", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.spring.authenticate", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.unboundid.search", taint.SnkLDAP)
	requireSinkID(t, ktSinks, "kotlin.ldap.unboundid.bind", taint.SnkLDAP)

	// ---------- C# sinks ----------
	csSinks := taint.SinksForLanguage(rules.LangCSharp)
	// Elasticsearch / OpenSearch DSL + Painless + Mustache injection (CWE-943, CWE-94)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.msearch", taint.SnkNoSQL)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.deletebyquery", taint.SnkNoSQL)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.updatebyquery", taint.SnkEval)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.reindex", taint.SnkEval)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.searchtemplate", taint.SnkEval)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.rendersearchtemplate", taint.SnkEval)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.scriptspainlessexecute", taint.SnkEval)
	requireSinkID(t, csSinks, "csharp.elasticsearch.client.putscript", taint.SnkEval)
	// CSV / spreadsheet formula injection (CWE-1236)
	requireSinkID(t, csSinks, "csharp.csvhelper.writefield", taint.SnkCSV)
	requireSinkID(t, csSinks, "csharp.csvhelper.writerecord", taint.SnkCSV)
	requireSinkID(t, csSinks, "csharp.csvhelper.writerecords", taint.SnkCSV)
	requireSinkID(t, csSinks, "csharp.csvhelper.writerecordsasync", taint.SnkCSV)
	requireSinkID(t, csSinks, "csharp.servicestack.csvserializer.serializetostring", taint.SnkCSV)

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
	// LDAP
	requireSanitizerID(t, ktSanitizers, "kotlin.ldap.ldapname", taint.SnkLDAP)
	requireSanitizerID(t, ktSanitizers, "kotlin.ldap.rdn.escapevalue", taint.SnkLDAP)

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
	// lua.tostring.sanitizer removed — tostring() returns the string unchanged and
	// strips no metacharacters; it was an unsound SQL/Command sanitizer (silent FN).
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

	// ---------- Swift sinks (CryptoSwift + CommonCrypto legacy hashes) ----------
	swiftSinks := taint.SinksForLanguage(rules.LangSwift)
	requireSinkID(t, swiftSinks, "swift.cryptoswift.md5", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.cryptoswift.sha1", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.cryptoswift.des", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.cryptoswift.blowfish", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.cryptoswift.rc4", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.cryptoswift.rc2", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.commoncrypto.cc_md2", taint.SnkCrypto)
	requireSinkID(t, swiftSinks, "swift.commoncrypto.cc_md4", taint.SnkCrypto)
}

// TestCWE73FileNameControlSinks verifies the path-construction file sinks
// (rename / move / copy / hard-link) are registered under SnkFileWrite and
// report CWE-73 (External Control of File Name or Path) — the CWE listed in
// taintCoverableCWEs that previously had no taint sink, causing negative-
// taint confirmation to over-suppress regex-only CWE-73 findings.
func TestCWE73FileNameControlSinks(t *testing.T) {
	want := []struct {
		lang rules.Language
		id   string
	}{
		// Python
		{rules.LangPython, "py.os.rename"},
		{rules.LangPython, "py.os.link"},
		{rules.LangPython, "py.shutil.copy"},
		// JavaScript / TypeScript
		{rules.LangJavaScript, "js.fs.rename"},
		{rules.LangJavaScript, "js.fs.link"},
		{rules.LangJavaScript, "js.fs.copyfile"},
		{rules.LangJavaScript, "js.fs.promises.rename"},
		{rules.LangJavaScript, "js.fs.promises.copyfile"},
		{rules.LangTypeScript, "ts.fs.rename"},
		{rules.LangTypeScript, "ts.fs.copyfile"},
		// Java
		{rules.LangJava, "java.nio.files.move"},
		{rules.LangJava, "java.nio.files.copy"},
		{rules.LangJava, "java.nio.files.createlink"},
		{rules.LangJava, "java.file.renameto"},
		{rules.LangJava, "java.commons.fileutils.copyfile"},
		// Go
		{rules.LangGo, "go.os.rename"},
		{rules.LangGo, "go.os.link"},
		// PHP
		{rules.LangPHP, "php.rename"},
		{rules.LangPHP, "php.copy"},
		{rules.LangPHP, "php.link"},
		// Ruby
		{rules.LangRuby, "ruby.fileutils.mv"},
		{rules.LangRuby, "ruby.fileutils.cp"},
		{rules.LangRuby, "ruby.file.rename"},
		{rules.LangRuby, "ruby.file.link"},
	}
	for _, w := range want {
		requireSinkWithCWE(t, taint.SinksForLanguage(w.lang), w.id, taint.SnkFileWrite, "CWE-73")
	}
}

func requireSinkWithCWE(t *testing.T, sinks []taint.SinkDef, id string, cat taint.SinkCategory, cwe string) {
	t.Helper()
	for _, s := range sinks {
		if s.ID == id {
			if s.Category != cat {
				t.Errorf("sink %s: expected category %v, got %v", id, cat, s.Category)
			}
			if s.CWEID != cwe {
				t.Errorf("sink %s: expected CWEID %q, got %q", id, cwe, s.CWEID)
			}
			return
		}
	}
	t.Errorf("sink %s not found in catalog (expected category %v, CWE %s)", id, cat, cwe)
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

func TestCSharpSanitizerCatalog(t *testing.T) {
	sans := taint.SanitizersForLanguage(rules.LangCSharp)

	// ReDoS prevention
	requireSanitizerID(t, sans, "csharp.regex.nonbacktracking", taint.SnkEval)

	// Reflection type allowlist
	requireSanitizerID(t, sans, "csharp.type.isassignablefrom", taint.SnkEval)

	// Cryptographic PRNG
	requireSanitizerID(t, sans, "csharp.crypto.randomnumbergenerator", taint.SnkCrypto)

	// HTML sanitization (Ganss.Xss)
	requireSanitizerID(t, sans, "csharp.ganss.htmlsanitizer", taint.SnkHTMLOutput)

	// FluentValidation
	requireSanitizerID(t, sans, "csharp.fluentvalidation", taint.SnkSQLQuery)

	// Process shell bypass
	requireSanitizerID(t, sans, "csharp.process.useshellexecute.false", taint.SnkCommand)

	// Data Protection API
	requireSanitizerID(t, sans, "csharp.dataprotection.protect", taint.SnkTrustBoundary)

	// Scriban template sandboxing
	requireSanitizerID(t, sans, "csharp.scriban.memberfilter", taint.SnkTemplate)
}

func TestCCurlProtocolSanitizers(t *testing.T) {
	sans := taint.SanitizersForLanguage(rules.LangC)

	// libcurl scheme/protocol restrictions that mitigate SSRF. The string-form
	// CURLOPT_PROTOCOLS_STR (curl 7.85+) and the redirect-leg restriction
	// CURLOPT_REDIR_PROTOCOLS[_STR] extend the pre-existing bitmask
	// CURLOPT_PROTOCOLS entry, which does not match the `_STR` suffix.
	requireSanitizerID(t, sans, "c.curl.protocols", taint.SnkURLFetch)
	requireSanitizerID(t, sans, "c.curl.protocols_str", taint.SnkURLFetch)
	requireSanitizerID(t, sans, "c.curl.redir_protocols", taint.SnkURLFetch)
	requireSanitizerID(t, sans, "c.curl.redir_protocols", taint.SnkRedirect)
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
