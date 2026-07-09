package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *CSharpCatalog) Sinks() []taint.SinkDef {
	sinks := append(csharpCoreSinks(), csharpCryptoSinks()...)
	sinks = append(sinks, csharpDeserializationSinks()...)
	sinks = append(sinks, csharpTrustBoundarySinks()...)
	sinks = append(sinks, csharpRedirectSinks()...)
	sinks = append(sinks, csharpLogSinks()...)
	sinks = append(sinks, csharpSSRFExtraSinks()...)
	sinks = append(sinks, csharpSSHNetSinks()...)
	sinks = append(sinks, csharpNeo4jSinks()...)
	sinks = append(sinks, csharpCassandraSinks()...)
	sinks = append(sinks, csharpElasticsearchSinks()...)
	sinks = append(sinks, csharpClickHouseSinks()...)
	sinks = append(sinks, csharpCSVInjectionSinks()...)
	return sinks
}

func csharpCoreSinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- SQL Injection (CWE-89) ---
		{
			ID:            "csharp.ef.fromsqlraw",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.FromSqlRaw\(`,
			ObjectType:    "DbSet",
			MethodName:    "FromSqlRaw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Entity Framework raw SQL query with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ef.executesqlraw",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExecuteSqlRaw\(`,
			ObjectType:    "DatabaseFacade",
			MethodName:    "ExecuteSqlRaw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Entity Framework raw SQL execution with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.sqlcommand.text",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+SqlCommand\s*\(|\.CommandText\s*=[^=]`,
			ObjectType:    "SqlCommand",
			MethodName:    "SqlCommand/CommandText",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL command with potentially tainted query string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.sqlcommand.executenonquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExecuteNonQuery\(|\.ExecuteScalar\(|\.ExecuteReader\(`,
			ObjectType:    "SqlCommand",
			MethodName:    "ExecuteNonQuery/ExecuteScalar/ExecuteReader",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "SQL command execution (dangerous if CommandText is tainted)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.dapper.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.Query\(|\.QueryAsync\(|\.QueryFirst\(|\.QuerySingle\(|\.Execute\(|\.ExecuteAsync\(`,
			ObjectType:    "IDbConnection (Dapper)",
			MethodName:    "Query/Execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dapper query with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Command Injection (CWE-78) ---
		{
			ID:            "csharp.process.start",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `Process\.Start\(`,
			ObjectType:    "System.Diagnostics.Process",
			MethodName:    "Process.Start",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "OS process execution with potentially tainted arguments",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.process.startinfo",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `ProcessStartInfo\s*\(|\.FileName\s*=[^=]|\.Arguments\s*=[^=]`,
			ObjectType:    "ProcessStartInfo",
			MethodName:    "ProcessStartInfo",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Process start info with potentially tainted command/arguments",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XSS / HTML Output (CWE-79) ---
		{
			ID:            "csharp.response.write",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `Response\.Write\(`,
			ObjectType:    "HttpResponse",
			MethodName:    "Response.Write",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Direct HTTP response write with potentially tainted data (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.response.writeasync",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `Response\.WriteAsync\(`,
			ObjectType:    "HttpResponse",
			MethodName:    "Response.WriteAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async HTTP response write with potentially tainted data (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.htmlraw",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `Html\.Raw\(`,
			ObjectType:    "IHtmlHelper",
			MethodName:    "Html.Raw",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Unescaped HTML output in Razor view with potentially tainted data",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.content.result",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+ContentResult\s*\{|Content\s*\(.*"text/html"`,
			ObjectType:    "ContentResult",
			MethodName:    "ContentResult",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Content result with HTML content type and potentially tainted data",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XSS additional (CWE-79) ---
		{
			ID:            "csharp.htmlstring",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+HtmlString\s*\(`,
			ObjectType:    "Microsoft.AspNetCore.Html.HtmlString",
			// Keyed under the bare constructed type name "HtmlString" (NOT
			// "new HtmlString"): tsflow keys an object_creation_expression by
			// its type field text, and matchesCatalogEntry's constructor branch
			// bridges the FQN ObjectType when the call name equals the type's
			// last component. A "new " prefix here mangles the index key so the
			// sink never matches.
			MethodName:    "HtmlString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HtmlString bypasses Razor auto-encoding — tainted input renders as raw HTML (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.blazor.markupstring",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+MarkupString\s*\(`,
			ObjectType:    "Microsoft.AspNetCore.Components.MarkupString",
			// Bare constructed type name (see csharp.htmlstring note above).
			MethodName:    "MarkupString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Blazor MarkupString renders tainted input as raw HTML (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.response.body.writeasync",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `Response\.Body\.WriteAsync\s*\(`,
			ObjectType:    "Response.Body",
			MethodName:    "Response.Body.WriteAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Raw byte write to HTTP response body with potentially tainted data (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.razor.writeliteral",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `WriteLiteral\s*\(`,
			ObjectType:    "",
			MethodName:    "WriteLiteral",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Razor WriteLiteral outputs raw unencoded HTML (XSS if tainted)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.viewbag.raw",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangCSharp,
			Pattern:       `Html\.Raw\s*\(`,
			ObjectType:    "IHtmlHelper",
			MethodName:    "Html.Raw",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Html.Raw renders tainted data as unencoded HTML in Razor views (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Open Redirect (CWE-601) ---
		{
			ID:            "csharp.response.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `Response\.Redirect\(|Redirect\(|RedirectPermanent\(`,
			ObjectType:    "HttpResponse/Controller",
			MethodName:    "Redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP redirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ServiceStack: open redirect via HttpResult.Redirect (CWE-601) ---
		// ServiceStack services return a redirect by constructing
		// HttpResult.Redirect(url) or new HttpResult(...) { Location = url }.
		// The existing csharp.response.redirect sink is scoped to
		// HttpResponse/Controller receivers and does not match the static
		// HttpResult.Redirect(...) helper, so a tainted returnUrl reaching it
		// is otherwise unmodelled. ObjectType "HttpResult" matches the static
		// receiver by direct name so this stays scoped to ServiceStack.
		{
			ID:            "csharp.servicestack.httpresult.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `HttpResult\.Redirect\s*\(`,
			ObjectType:    "HttpResult",
			MethodName:    "Redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ServiceStack HttpResult.Redirect(url) with potentially tainted URL (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Path Traversal / File Operations (CWE-22) ---
		{
			ID:            "csharp.file.readalltext",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllText\(|File\.ReadAllBytes\(|File\.ReadAllLines\(|File\.ReadAllTextAsync\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.ReadAll*",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.writealltext",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `File\.WriteAllText\(|File\.WriteAllBytes\(|File\.WriteAllLines\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.WriteAll*",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File write with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.delete",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `File\.Delete\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.Delete",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File deletion with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.path.combine",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `Path\.Combine\(`,
			ObjectType:    "System.IO.Path",
			MethodName:    "Path.Combine",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "File path construction with potentially tainted component",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.filestream.new",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			// FileStream(path, ...) only — its first argument is reliably a file
			// PATH (CWE-22). StreamWriter was deliberately dropped: its dominant
			// constructor overload is `new StreamWriter(Stream stream, ...)`
			// whose arg 0 is an already-open stream, not a path, so keying it
			// here flagged `new StreamWriter(fs, encoding)` as path traversal
			// (verified FP on abp's VoloNugetPackagesVersionUpdater). The
			// `new ` prefix is dropped from MethodName so the bare constructed
			// type name "FileStream" is the index key (tsflow keys an
			// object_creation_expression by its type name; a "new " prefix
			// mangles the key, which is why this sink was previously dead).
			Pattern:       `new\s+FileStream\s*\(`,
			ObjectType:    "System.IO.FileStream",
			MethodName:    "FileStream",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File stream opened with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ZipSlip / archive extraction (CWE-22) ---
		// ZipArchiveEntry.ExtractToFile writes a single entry to a destination
		// path; when that path is derived from the entry's own (attacker-
		// controlled) FullName, a malicious "../" entry escapes the target dir.
		// ObjectType is relaxed to "" because the receiver is a loop variable
		// whose declared type rarely binds, and ExtractToFile is distinctive.
		{
			ID:            "csharp.zip.extracttofile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExtractToFile\s*\(`,
			ObjectType:    "",
			MethodName:    "ExtractToFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Archive entry extracted to a potentially tainted path (ZipSlip — entry name or user path escapes target directory)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- XML External Entity (CWE-611) ---
		{
			ID:            "csharp.xml.loadxml",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `\.LoadXml\(|XmlDocument.*\.Load\(`,
			ObjectType:    "XmlDocument",
			MethodName:    "XmlDocument.LoadXml",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XML document loaded with potentially tainted data (XXE risk)",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		{
			ID:            "csharp.xml.xmlreader",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `XmlReader\.Create\(`,
			ObjectType:    "XmlReader",
			MethodName:    "XmlReader.Create",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "XML reader created from potentially tainted input",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},

		// --- SSRF (CWE-918) ---
		{
			ID:            "csharp.httpclient.getasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `HttpClient.*\.GetAsync\(|HttpClient.*\.GetStringAsync\(|HttpClient.*\.PostAsync\(|HttpClient.*\.SendAsync\(`,
			ObjectType:    "HttpClient",
			MethodName:    "GetAsync/PostAsync/SendAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.webrequest.create",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `WebRequest\.Create\(|WebClient.*\.DownloadString\(|WebClient.*\.DownloadData\(`,
			ObjectType:    "WebRequest/WebClient",
			MethodName:    "WebRequest.Create/WebClient.Download*",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Web request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- LDAP Injection (CWE-90) ---
		{
			ID:            "csharp.ldap.search",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+DirectorySearcher\s*\(`,
			ObjectType:    "DirectorySearcher",
			// Keyed under the bare constructed type name so the
			// `new DirectorySearcher(filter)` form (the idiomatic LDAP-injection
			// vector — IssueBlot.NET LDAPInjection2) actually fires. The prior
			// MethodName "DirectorySearcher.Filter" keyed under "Filter", which
			// no call node carries (Filter is a settable PROPERTY, not a method
			// call), so the sink was dead. The filter argument is constructor
			// arg 0 (`new DirectorySearcher(filter)`) or arg 1
			// (`new DirectorySearcher(entry, filter)`).
			MethodName:    "DirectorySearcher",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "LDAP search with potentially tainted filter",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- LDAP Injection: System.DirectoryServices.Protocols (CWE-90) ---
		{
			ID:            "csharp.ldap.searchrequest",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+SearchRequest\s*\(`,
			ObjectType:    "SearchRequest",
			// Bare constructed type name; the constructor branch of
			// matchesCatalogEntry bridges the ObjectType. The LDAP filter is the
			// 2nd constructor argument: SearchRequest(distinguishedName, filter, scope).
			MethodName:    "SearchRequest",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "LDAP SearchRequest with potentially tainted filter (System.DirectoryServices.Protocols)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.directoryentry",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+DirectoryEntry\s*\(`,
			ObjectType:    "DirectoryEntry",
			// Bare constructed type name; the constructor branch bridges the
			// ObjectType. The LDAP path is the 1st constructor argument.
			MethodName:    "DirectoryEntry",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DirectoryEntry with potentially tainted LDAP path",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.sendrequest",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `LdapConnection.*\.SendRequest\s*\(`,
			ObjectType:    "LdapConnection",
			MethodName:    "LdapConnection.SendRequest",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "LdapConnection.SendRequest with potentially tainted request",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- LDAP Injection: System.DirectoryServices.AccountManagement (CWE-90) ---
		// FindByIdentity overloads accept (PrincipalContext, identityValue) or
		// (PrincipalContext, IdentityType, identityValue). When the identityValue
		// flows from user input, attackers can leverage wildcard / DN syntax to
		// enumerate principals (CA3005, OWASP LDAP Injection Prevention).
		{
			ID:            "csharp.ldap.userprincipal.findbyidentity",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `UserPrincipal\.FindByIdentity\s*\(`,
			ObjectType:    "UserPrincipal",
			MethodName:    "UserPrincipal.FindByIdentity",
			DangerousArgs: []int{1, 2},
			Severity:      rules.High,
			Description:   "UserPrincipal.FindByIdentity with potentially tainted identity value (System.DirectoryServices.AccountManagement)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.groupprincipal.findbyidentity",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `GroupPrincipal\.FindByIdentity\s*\(`,
			ObjectType:    "GroupPrincipal",
			MethodName:    "GroupPrincipal.FindByIdentity",
			DangerousArgs: []int{1, 2},
			Severity:      rules.High,
			Description:   "GroupPrincipal.FindByIdentity with potentially tainted identity value (System.DirectoryServices.AccountManagement)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.computerprincipal.findbyidentity",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `ComputerPrincipal\.FindByIdentity\s*\(`,
			ObjectType:    "ComputerPrincipal",
			MethodName:    "ComputerPrincipal.FindByIdentity",
			DangerousArgs: []int{1, 2},
			Severity:      rules.High,
			Description:   "ComputerPrincipal.FindByIdentity with potentially tainted identity value (System.DirectoryServices.AccountManagement)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.principalcontext.new",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+PrincipalContext\s*\(`,
			ObjectType:    "PrincipalContext",
			MethodName:    "PrincipalContext",
			DangerousArgs: []int{1, 2, 3, 4},
			Severity:      rules.High,
			Description:   "PrincipalContext constructor with potentially tainted name/container/credentials (DN injection / auth-bypass)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.principalcontext.validatecredentials",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `\.ValidateCredentials\s*\(`,
			ObjectType:    "PrincipalContext",
			MethodName:    "PrincipalContext.ValidateCredentials",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "PrincipalContext.ValidateCredentials with potentially tainted username/password (LDAP filter injection during bind)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.principalsearcher.new",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+PrincipalSearcher\s*\(`,
			ObjectType:    "PrincipalSearcher",
			MethodName:    "PrincipalSearcher",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "PrincipalSearcher with potentially tainted query principal (filter injection via principal properties)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.ldap.ldapdirectoryidentifier.new",
			Category:      taint.SnkLDAP,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+LdapDirectoryIdentifier\s*\(`,
			ObjectType:    "LdapDirectoryIdentifier",
			MethodName:    "LdapDirectoryIdentifier",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "LdapDirectoryIdentifier with potentially tainted server URI (auth-bypass via attacker-controlled LDAP server)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Deserialization (CWE-502) ---
		{
			ID:            "csharp.binaryformatter",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `BinaryFormatter.*\.Deserialize\(`,
			ObjectType:    "BinaryFormatter",
			MethodName:    "BinaryFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "BinaryFormatter deserialization of untrusted data (RCE risk)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.xmlserializer",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `XmlSerializer.*\.Deserialize\(`,
			ObjectType:    "XmlSerializer",
			MethodName:    "XmlSerializer.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XML deserialization of potentially tainted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- XAML deserialization RCE (CWE-502) ---
		// System.Windows.Markup.XamlReader.Parse/Load and System.Xaml.XamlServices
		// .Parse/.Load instantiate arbitrary CLR types directly from the XAML
		// markup. A tainted markup string reaches a gadget such as
		// ObjectDataProvider, which the XAML loader uses to invoke arbitrary
		// methods (e.g. Process.Start) — the canonical ysoserial.net
		// "ObjectDataProvider + XamlReader" RCE chain. The methods take the
		// markup/stream/reader as positional arg 0; a string literal there carries
		// no taint and never fires. The receiver is the literal class name
		// (XamlReader / XamlServices) so the ObjectType match is exact and cannot
		// collide with unrelated .Load()/.Parse() calls on other objects.
		{
			ID:            "csharp.xamlreader.parse",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `XamlReader\.Parse\s*\(`,
			ObjectType:    "XamlReader",
			MethodName:    "XamlReader.Parse",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "System.Windows.Markup.XamlReader.Parse on untrusted XAML markup (RCE via ObjectDataProvider gadget)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.xamlreader.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `XamlReader\.Load\s*\(`,
			ObjectType:    "XamlReader",
			MethodName:    "XamlReader.Load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "System.Windows.Markup.XamlReader.Load on an untrusted XAML stream/reader (RCE via ObjectDataProvider gadget)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.xamlservices.parse",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `XamlServices\.Parse\s*\(`,
			ObjectType:    "XamlServices",
			MethodName:    "XamlServices.Parse",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "System.Xaml.XamlServices.Parse on untrusted XAML markup (RCE via ObjectDataProvider gadget)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.xamlservices.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `XamlServices\.Load\s*\(`,
			ObjectType:    "XamlServices",
			MethodName:    "XamlServices.Load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "System.Xaml.XamlServices.Load on an untrusted XAML stream/reader (RCE via ObjectDataProvider gadget)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Dangerous .NET deserializers (CWE-502) ---
		{
			ID:            "csharp.soapformatter",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `SoapFormatter.*\.Deserialize\(`,
			ObjectType:    "SoapFormatter",
			MethodName:    "SoapFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SoapFormatter deserialization of untrusted data (RCE risk, CVE-2020-0646)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.losformatter",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `LosFormatter.*\.Deserialize\(`,
			ObjectType:    "LosFormatter",
			MethodName:    "LosFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "LosFormatter deserialization of untrusted data (ViewState RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.objectstateformatter",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `ObjectStateFormatter.*\.Deserialize\(`,
			ObjectType:    "ObjectStateFormatter",
			MethodName:    "ObjectStateFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ObjectStateFormatter deserialization of untrusted data (ViewState RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.datacontractjsonserializer",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `DataContractJsonSerializer.*\.ReadObject\(`,
			ObjectType:    "DataContractJsonSerializer",
			MethodName:    "DataContractJsonSerializer.ReadObject",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DataContractJsonSerializer deserialization of potentially tainted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.javascriptserializer",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `JavaScriptSerializer.*\.Deserialize\(|JavaScriptSerializer.*\.DeserializeObject\(`,
			ObjectType:    "JavaScriptSerializer",
			MethodName:    "JavaScriptSerializer.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "JavaScriptSerializer deserialization of potentially tainted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.newtonsoft.typenamehandling",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)`,
			ObjectType:    "JsonSerializerSettings",
			MethodName:    "TypeNameHandling.All/Auto/Objects",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Newtonsoft.Json TypeNameHandling enables polymorphic deserialization (RCE via ysoserial.net)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Dynamic code execution (CWE-94) ---
		{
			ID:            "csharp.assembly.load",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `Assembly\.Load\(|Assembly\.LoadFrom\(|Assembly\.LoadFile\(|Assembly\.UnsafeLoadFrom\(`,
			ObjectType:    "System.Reflection.Assembly",
			MethodName:    "Assembly.Load/LoadFrom/LoadFile",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic assembly loading with potentially tainted path or bytes (code execution)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.activator.createinstance",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `Activator\.CreateInstance\(`,
			ObjectType:    "System.Activator",
			MethodName:    "Activator.CreateInstance",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Reflection-based object creation with potentially tainted type name",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.type.invokemember",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.InvokeMember\(|MethodInfo.*\.Invoke\(`,
			ObjectType:    "System.Type/MethodInfo",
			MethodName:    "InvokeMember/MethodInfo.Invoke",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Reflection-based method invocation with potentially tainted member name",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.roslyn.evaluateasync",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `CSharpScript\.EvaluateAsync\(|CSharpScript\.RunAsync\(|CSharpScript\.Create\(`,
			ObjectType:    "Microsoft.CodeAnalysis.CSharp.Scripting",
			MethodName:    "CSharpScript.EvaluateAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Roslyn C# scripting with potentially tainted code string",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		// StackExchange.Redis Lua script evaluation — ScriptEvaluate/ScriptEvaluateAsync
		// on IDatabase/IServer sends the first argument to Redis EVAL. A tainted script
		// body executes arbitrary Lua on the Redis server (CWE-94). ScriptEvaluateReadOnly
		// is the read-only variant added in recent versions — it still executes the script.
		{
			ID:            "csharp.redis.scriptevaluate",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.ScriptEvaluate(?:Async|ReadOnly|ReadOnlyAsync)?\s*\(`,
			ObjectType:    "",
			MethodName:    "ScriptEvaluate/ScriptEvaluateAsync/ScriptEvaluateReadOnly/ScriptEvaluateReadOnlyAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "StackExchange.Redis Lua script evaluation with potentially tainted script (Redis EVAL injection)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		// IServer.ScriptLoad caches a Lua script server-side and returns its SHA1.
		// A tainted script body is still attacker-controlled code that will later be
		// executed via EVALSHA — treat the load site as the code-injection boundary.
		{
			ID:            "csharp.redis.scriptload",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.ScriptLoad(?:Async)?\s*\(`,
			ObjectType:    "",
			MethodName:    "ScriptLoad/ScriptLoadAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "StackExchange.Redis ScriptLoad caches a Lua script for later EVALSHA execution; tainted script enables Redis code injection",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		// Jint (and Microsoft.ClearScript) embed a JavaScript engine in .NET.
		// `engine.Execute(js)` runs a script for its side effects and
		// `engine.Evaluate(js)` evaluates an expression — both execute the
		// first argument as code. A tainted script body is arbitrary code
		// execution inside the host process (CWE-94). The ObjectType keys on the
		// conventional `engine` receiver (Jint's `new Engine()` and ClearScript's
		// `new V8ScriptEngine()` are both idiomatically bound to `engine`), which
		// is what the tsflow matcher uses to scope this sink.
		{
			ID:            "csharp.jint.engine.execute",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `(?:new\s+(?:Engine|V8ScriptEngine|JsEngine)\s*\([^)]*\)|\bengine)\s*\.\s*(?:Execute|Evaluate)\s*\(`,
			ObjectType:    "Jint.Engine",
			MethodName:    "Execute/Evaluate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Jint/ClearScript JavaScript engine executing a potentially tainted script string (code injection)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		// NCalc evaluates mathematical/logical expression strings. The danger
		// boundary is `new Expression(tainted)` — the constructor parses the
		// attacker-controlled formula, which `.Evaluate()` then executes
		// (including any registered/custom functions). Expression injection
		// enables DoS and, depending on registered functions, information
		// disclosure or worse (CWE-95). System.Linq.Expressions.Expression is
		// abstract and cannot be constructed, so `new Expression(...)` is NCalc.
		{
			ID:            "csharp.ncalc.expression.new",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+Expression\s*\(`,
			ObjectType:    "NCalc.Expression",
			MethodName:    "Expression",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "NCalc expression constructed from a potentially tainted formula string (expression injection)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		// Flee (Fast Lightweight Expression Evaluator) compiles an expression
		// string into an executable form. `context.CompileDynamic(expr)` and
		// `context.CompileGeneric<T>(expr)` parse and compile the first argument;
		// a tainted expression is attacker-controlled code over the context's
		// variables and functions (CWE-95). CompileDynamic/CompileGeneric are
		// Flee-specific method names.
		{
			ID:            "csharp.flee.compiledynamic",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.\s*CompileDynamic\s*\(|\.\s*CompileGeneric\s*<`,
			ObjectType:    "ExpressionContext",
			MethodName:    "CompileDynamic/CompileGeneric",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flee ExpressionContext compiling a potentially tainted expression string (expression injection)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.powershell.addscript",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `PowerShell\.Create\(|\.AddScript\(|\.AddCommand\(`,
			ObjectType:    "System.Management.Automation.PowerShell",
			MethodName:    "PowerShell.AddScript/AddCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PowerShell script execution with potentially tainted input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Log Injection (CWE-117) ---
		{
			ID:            "csharp.ilogger.log",
			Category:      taint.SnkLog,
			Language:      rules.LangCSharp,
			Pattern:       `_logger\.Log(?:Information|Warning|Error|Critical|Debug)\(|_logger\.Log\(`,
			ObjectType:    "ILogger",
			MethodName:    "ILogger.Log*",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logger output with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "csharp.console.writeline",
			Category:      taint.SnkLog,
			Language:      rules.LangCSharp,
			Pattern:       `Console\.WriteLine\(|Console\.Write\(`,
			ObjectType:    "System.Console",
			MethodName:    "Console.Write*",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Console output with potentially tainted data",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- Regex DoS (CWE-1333) ---
		{
			ID:            "csharp.regex.new",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+Regex\s*\(`,
			ObjectType:    "System.Text.RegularExpressions.Regex",
			// Bare constructed type name; the constructor branch bridges the FQN
			// ObjectType (last component "Regex"). A "new " prefix mangles the key.
			MethodName:    "Regex",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Regex constructed with potentially tainted pattern (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		// Static Regex.* helpers take the pattern as positional arg 1 — the
		// signatures are Regex.IsMatch(input, pattern), Regex.Match(input,
		// pattern), Regex.Matches(input, pattern), Regex.Replace(input,
		// pattern, replacement), and Regex.Split(input, pattern). When a
		// tainted (attacker-supplied) pattern reaches arg 1, an adversary can
		// craft a catastrophically-backtracking expression (ReDoS, CWE-1333).
		// The haystack at arg 0 is the *subject* being scanned — having user
		// input there is the normal use of regex matching and must NOT fire
		// this sink, so DangerousArgs is restricted to [1]. A literal-string
		// pattern at arg 1 carries no taint and therefore never fires.
		// Classified under SnkRegexDoS (medium-severity DoS) rather than
		// SnkEval (critical RCE) to match the threat. The \bRegex\. anchor
		// prevents substring matches inside identifiers like MyRegex.IsMatch.
		{
			ID:            "csharp.regex.static.tainted",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangCSharp,
			Pattern:       `\bRegex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\(`,
			ObjectType:    "System.Text.RegularExpressions.Regex",
			MethodName:    "Regex.IsMatch/Match/Matches/Replace/Split",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Static Regex.* call with potentially tainted pattern at arg 1 (ReDoS — the haystack at arg 0 is never the dangerous argument)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Template Injection (CWE-1336) ---
		{
			ID:            "csharp.razorengine.compile",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `Engine\.Razor\.RunCompile\s*\(|RazorEngine.*\.RunCompile\s*\(|Razor\.Compile\s*\(`,
			ObjectType:    "RazorEngine",
			MethodName:    "Engine.Razor.RunCompile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RazorEngine template compilation with potentially tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.scriban.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `Template\.Parse\s*\(.*\.Render\s*\(|Scriban.*\.Render\s*\(`,
			ObjectType:    "Scriban",
			MethodName:    "Template.Parse.Render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Scriban template rendering with potentially tainted template",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Template Injection: Handlebars.Net (CWE-1336) ---
		{
			ID:            "csharp.handlebars.compile",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `Handlebars\.Compile\s*\(|Handlebars\.CompileView\s*\(`,
			ObjectType:    "Handlebars.Net",
			MethodName:    "Handlebars.Compile/Handlebars.CompileView",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Handlebars.Net template compilation with potentially tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Template Injection: Fluid (CWE-1336) ---
		{
			ID:            "csharp.fluid.parse",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `FluidParser.*\.Parse\s*\(|FluidTemplate\.Parse\s*\(`,
			ObjectType:    "Fluid",
			MethodName:    "FluidParser.Parse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Fluid (Liquid) template parsing with potentially tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Template Injection: Stubble/Mustache (CWE-1336) ---
		{
			ID:            "csharp.stubble.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `StubbleVisitorRenderer.*\.Render\s*\(|StaticStubbleRenderer\.Render\s*\(|Stubble.*\.Render\s*\(`,
			ObjectType:    "Stubble",
			MethodName:    "StubbleRenderer.Render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Stubble (Mustache) template rendering with potentially tainted template",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Template Injection: DotLiquid (CWE-1336) ---
		{
			ID:            "csharp.dotliquid.template.parse",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `DotLiquid\.Template\.Parse\s*\(`,
			ObjectType:    "DotLiquid.Template",
			MethodName:    "Template.Parse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DotLiquid template parsing with potentially tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Template Injection: RazorLight (CWE-1336) ---
		{
			ID:            "csharp.razorlight.compilerenderstring",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `\.CompileRenderStringAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "CompileRenderStringAsync",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "RazorLight runtime template compilation with potentially tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Template Injection: Cottle (CWE-1336) ---
		{
			ID:            "csharp.cottle.document.createdefault",
			Category:      taint.SnkTemplate,
			Language:      rules.LangCSharp,
			Pattern:       `Cottle\.Document\.CreateDefault\s*\(`,
			ObjectType:    "Cottle.Document",
			MethodName:    "Document.CreateDefault",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Cottle document creation with potentially tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XPath Injection (CWE-643) ---
		{
			ID:            "csharp.xpath.selectnodes",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `\.SelectNodes\s*\(|\.SelectSingleNode\s*\(|XPathExpression\.Compile\s*\(`,
			ObjectType:    "XmlNode",
			MethodName:    "SelectNodes/SelectSingleNode",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPath query with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.xpath.navigator.select",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `(?:XPathNavigator|navigator|nav)\.\s*Select\s*\(`,
			ObjectType:    "Navigator",
			MethodName:    "Select",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPathNavigator.Select with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.xpath.navigator.evaluate",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `(?:XPathNavigator|navigator|nav)\.\s*Evaluate\s*\(`,
			ObjectType:    "Navigator",
			MethodName:    "Evaluate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPathNavigator.Evaluate with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.xpath.navigator.matches",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `(?:XPathNavigator|navigator|nav)\.\s*Matches\s*\(`,
			ObjectType:    "Navigator",
			MethodName:    "Matches",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPathNavigator.Matches with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.xpath.linq.selectelements",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `\.XPathSelectElements\s*\(`,
			ObjectType:    "",
			MethodName:    "XPathSelectElements",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "LINQ to XML XPathSelectElements with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.xpath.linq.selectelement",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `\.XPathSelectElement\s*\(`,
			ObjectType:    "",
			MethodName:    "XPathSelectElement",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "LINQ to XML XPathSelectElement with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.xpath.linq.evaluate",
			Category:      taint.SnkXPath,
			Language:      rules.LangCSharp,
			Pattern:       `\.XPathEvaluate\s*\(`,
			ObjectType:    "",
			MethodName:    "XPathEvaluate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "LINQ to XML XPathEvaluate with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- HTTP Header Injection (CWE-113) ---
		{
			ID:            "csharp.response.headers",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `Response\.Headers\.Add\(|Response\.Headers\.Append\(|Response\.Headers\[`,
			ObjectType:    "HttpResponse",
			MethodName:    "Response.Headers.Add/Append",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "HTTP response header with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Dynamic LINQ (CWE-89) ---
		{
			ID:            "csharp.dynamiclinq",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.Where\s*\(\s*"[^"]*"\s*\+|\.OrderBy\s*\(\s*"[^"]*"\s*\+`,
			ObjectType:    "Dynamic LINQ",
			MethodName:    "Dynamic LINQ Where/OrderBy",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Dynamic LINQ with string concatenation (injection risk)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- File operations (CWE-22) ---
		{
			ID:            "csharp.file.copy",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `File\.Copy\s*\(`,
			ObjectType:    "File",
			MethodName:    "Copy",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File copy with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.move",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `File\.Move\s*\(`,
			ObjectType:    "File",
			MethodName:    "Move",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File move with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.directory.createdirectory",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `Directory\.CreateDirectory\s*\(`,
			ObjectType:    "Directory",
			MethodName:    "CreateDirectory",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- File Read / Path Traversal (CWE-22) ---
		{
			ID:            "csharp.file.readalltext.read",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllText\s*\(`,
			ObjectType:    "File",
			MethodName:    "ReadAllText",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.readallbytes.read",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllBytes\s*\(`,
			ObjectType:    "File",
			MethodName:    "ReadAllBytes",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read bytes with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.readalllines.read",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllLines\s*\(`,
			ObjectType:    "File",
			MethodName:    "ReadAllLines",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read lines with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.openread",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.OpenRead\s*\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.OpenRead",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File open for reading with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.opentext",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.OpenText\s*\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.OpenText",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File open as text with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.open",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.Open\s*\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.Open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File open with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.readlines",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadLines\s*\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.ReadLines",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read lines with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.readalltextasync",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllTextAsync\s*\(`,
			ObjectType:    "File",
			MethodName:    "ReadAllTextAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async file read with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.readallbytesasync",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllBytesAsync\s*\(`,
			ObjectType:    "File",
			MethodName:    "ReadAllBytesAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async file read bytes with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.readalllinesasync",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.ReadAllLinesAsync\s*\(`,
			ObjectType:    "File",
			MethodName:    "ReadAllLinesAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async file read lines with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.file.exists",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `File\.Exists\s*\(`,
			ObjectType:    "System.IO.File",
			MethodName:    "File.Exists",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "File existence check with potentially tainted path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.directory.getfiles",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `Directory\.GetFiles\s*\(`,
			ObjectType:    "Directory",
			MethodName:    "GetFiles",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory listing with potentially tainted path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.directory.enumeratefiles",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `Directory\.EnumerateFiles\s*\(`,
			ObjectType:    "Directory",
			MethodName:    "EnumerateFiles",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory file enumeration with potentially tainted path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.directory.getdirectories",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `Directory\.GetDirectories\s*\(`,
			ObjectType:    "Directory",
			MethodName:    "GetDirectories",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory enumeration with potentially tainted path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.directory.enumeratedirectories",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `Directory\.EnumerateDirectories\s*\(`,
			ObjectType:    "Directory",
			MethodName:    "EnumerateDirectories",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory enumeration with potentially tainted path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.fileinfo.new",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+FileInfo\s*\(`,
			ObjectType:    "System.IO.FileInfo",
			// Bare constructed type name; constructor branch bridges the FQN
			// ObjectType (last component "FileInfo"). A "new " prefix mangles the key.
			MethodName:    "FileInfo",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "FileInfo construction with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.directoryinfo.new",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+DirectoryInfo\s*\(`,
			ObjectType:    "System.IO.DirectoryInfo",
			// Bare constructed type name; constructor branch bridges the FQN
			// ObjectType (last component "DirectoryInfo"). A "new " prefix mangles the key.
			MethodName:    "DirectoryInfo",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DirectoryInfo construction with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ReDoS ---
		{
			ID:            "csharp.regex.new.tainted",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+Regex\s*\(`,
			ObjectType:    "Regex",
			MethodName:    "Regex (constructor)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Regex construction with potentially tainted pattern (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SSRF additional ---
		{
			ID:            "csharp.httpclient.postasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `HttpClient.*\.PostAsync\s*\(|HttpClient.*\.PutAsync\s*\(|HttpClient.*\.SendAsync\s*\(`,
			ObjectType:    "HttpClient",
			MethodName:    "PostAsync/PutAsync/SendAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HttpClient request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		{
			ID:            "csharp.httpclient.getstringasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.GetStringAsync\s*\(|\.GetByteArrayAsync\s*\(|\.GetStreamAsync\s*\(`,
			ObjectType:    "HttpClient",
			MethodName:    "GetStringAsync/GetByteArrayAsync/GetStreamAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HttpClient content-fetching method with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.httpclient.deletepatchasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.DeleteAsync\s*\(|\.PatchAsync\s*\(`,
			ObjectType:    "HttpClient",
			MethodName:    "DeleteAsync/PatchAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HttpClient mutation method with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.webclient.downloadstring",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `WebClient.*\.DownloadString\s*\(|WebClient.*\.DownloadStringAsync\s*\(|WebClient.*\.DownloadStringTaskAsync\s*\(`,
			ObjectType:    "System.Net.WebClient",
			MethodName:    "WebClient.DownloadString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WebClient string download from potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.webclient.downloaddata",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `WebClient.*\.DownloadData\s*\(|WebClient.*\.DownloadDataAsync\s*\(|WebClient.*\.DownloadDataTaskAsync\s*\(`,
			ObjectType:    "System.Net.WebClient",
			MethodName:    "WebClient.DownloadData",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WebClient data download from potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.restclient.execute",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `RestClient.*\.Execute\s*\(|RestClient.*\.ExecuteAsync\s*\(|RestClient.*\.GetAsync\s*\(|RestClient.*\.PostAsync\s*\(`,
			ObjectType:    "RestSharp.RestClient",
			MethodName:    "RestClient.Execute/ExecuteAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RestSharp HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Cookie injection ---
		{
			ID:            "csharp.response.cookies.append",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `Response\.Cookies\.Append\s*\(`,
			ObjectType:    "HttpResponse",
			MethodName:    "Cookies.Append",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Medium,
			Description:   "Cookie set with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Process start with tainted args ---
		{
			ID:            "csharp.process.start.filename",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `ProcessStartInfo.*FileName\s*=`,
			ObjectType:    "ProcessStartInfo",
			MethodName:    "FileName",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Process start with potentially tainted executable path",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.process.start.twoarg",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `Process\.Start\s*\([^,]+,`,
			ObjectType:    "System.Diagnostics.Process",
			MethodName:    "Process.Start(filename, arguments)",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Process.Start two-argument overload with potentially tainted arguments",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.processstartinfo.arguments",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `\.Arguments\s*=\s*\$"|\.Arguments\s*=\s*[a-zA-Z]`,
			ObjectType:    "ProcessStartInfo",
			MethodName:    "ProcessStartInfo.Arguments",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ProcessStartInfo.Arguments set from tainted variable or interpolated string",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cliwrap.cli",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `Cli\.Wrap\s*\(`,
			ObjectType:    "CliWrap.Cli",
			MethodName:    "Cli.Wrap",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "CliWrap command execution with potentially tainted executable",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Entity Framework Core SQL injection (CWE-89) ---
		{
			ID:            "csharp.efcore.sqlqueryraw",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.SqlQueryRaw\(`,
			ObjectType:    "DatabaseFacade",
			MethodName:    "SqlQueryRaw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Entity Framework Core SqlQueryRaw() (EF 8+) with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- ADO.NET provider-specific commands (CWE-89) ---
		{
			ID:            "csharp.npgsql.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+NpgsqlCommand\s*\(`,
			ObjectType:    "NpgsqlCommand",
			MethodName:    "NpgsqlCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Npgsql PostgreSQL command with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.mysql.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+MySqlCommand\s*\(`,
			ObjectType:    "MySqlCommand",
			MethodName:    "MySqlCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MySQL command with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.sqlite.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+SqliteCommand\s*\(`,
			ObjectType:    "SqliteCommand",
			MethodName:    "SqliteCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Microsoft.Data.Sqlite command with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.oracle.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+OracleCommand\s*\(`,
			ObjectType:    "OracleCommand",
			MethodName:    "OracleCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Oracle command with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.oledb.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+OleDbCommand\s*\(`,
			ObjectType:    "OleDbCommand",
			MethodName:    "OleDbCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "OleDb command with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.odbc.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+OdbcCommand\s*\(`,
			ObjectType:    "OdbcCommand",
			MethodName:    "OdbcCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ODBC command with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.sqldataadapter",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+SqlDataAdapter\s*\(`,
			ObjectType:    "SqlDataAdapter",
			MethodName:    "SqlDataAdapter",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SqlDataAdapter with potentially tainted SQL query string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- NHibernate SQL injection (CWE-89) ---
		{
			ID:            "csharp.nhibernate.createsqlquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateSQLQuery\s*\(`,
			ObjectType:    "ISession",
			MethodName:    "CreateSQLQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "NHibernate raw SQL query with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.nhibernate.createquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateQuery\s*\(`,
			ObjectType:    "ISession",
			MethodName:    "CreateQuery",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "NHibernate HQL query with potentially tainted input (HQL injection)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- MongoDB C# driver NoSQL injection (CWE-943) ---
		{
			ID:            "csharp.mongo.bsondocument.parse",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `BsonDocument\.Parse\s*\(`,
			ObjectType:    "BsonDocument",
			MethodName:    "Parse",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB BsonDocument.Parse with potentially tainted JSON string (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.mongo.runcommand",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.RunCommand\s*<`,
			ObjectType:    "IMongoDatabase",
			MethodName:    "RunCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB raw command execution with potentially tainted input",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.mongo.runcommandasync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.RunCommandAsync\s*<`,
			ObjectType:    "IMongoDatabase",
			MethodName:    "RunCommandAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB async raw command execution with potentially tainted input",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.mongo.aggregate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.Aggregate\s*<|\.AggregateAsync\s*<`,
			ObjectType:    "IMongoCollection",
			MethodName:    "Aggregate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoDB aggregation pipeline with potentially tainted stages",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// MongoDB C# driver (IMongoCollection<T>) write/query methods that take a
		// FilterDefinition as the first argument. ObjectType is left empty (wildcard)
		// so the matcher keys on the distinctive method names alone — IMongoCollection
		// handles are bound to widely varying names (collection, _collection, users,
		// etc.) that no receiver heuristic captures (mirrors java.mongodb.collection.*).
		// These PascalCase names are MongoDB-driver-specific in .NET (EF Core uses
		// Update/Remove, not UpdateOne/DeleteOne), keeping the false-positive rate low.
		// Sync and *Async overloads are matched in one entry. DangerousArgs[0] is the
		// filter; a tainted BsonDocument/JSON filter is operator-injection (CWE-943).
		{ID: "csharp.mongo.collection.findasync", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.FindAsync\s*\(`, ObjectType: "", MethodName: "FindAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver FindAsync() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.updateone", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.UpdateOne(?:Async)?\s*\(`, ObjectType: "", MethodName: "UpdateOne/UpdateOneAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver UpdateOne() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.updatemany", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.UpdateMany(?:Async)?\s*\(`, ObjectType: "", MethodName: "UpdateMany/UpdateManyAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver UpdateMany() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.deleteone", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.DeleteOne(?:Async)?\s*\(`, ObjectType: "", MethodName: "DeleteOne/DeleteOneAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver DeleteOne() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.deletemany", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.DeleteMany(?:Async)?\s*\(`, ObjectType: "", MethodName: "DeleteMany/DeleteManyAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver DeleteMany() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.replaceone", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.ReplaceOne(?:Async)?\s*\(`, ObjectType: "", MethodName: "ReplaceOne/ReplaceOneAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver ReplaceOne() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.findoneandupdate", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.FindOneAndUpdate(?:Async)?\s*\(`, ObjectType: "", MethodName: "FindOneAndUpdate/FindOneAndUpdateAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver FindOneAndUpdate() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.findoneanddelete", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.FindOneAndDelete(?:Async)?\s*\(`, ObjectType: "", MethodName: "FindOneAndDelete/FindOneAndDeleteAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver FindOneAndDelete() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.findoneandreplace", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.FindOneAndReplace(?:Async)?\s*\(`, ObjectType: "", MethodName: "FindOneAndReplace/FindOneAndReplaceAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver FindOneAndReplace() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mongo.collection.countdocuments", Category: taint.SnkNoSQL, Language: rules.LangCSharp, Pattern: `\.CountDocuments(?:Async)?\s*\(`, ObjectType: "", MethodName: "CountDocuments/CountDocumentsAsync", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB C# driver CountDocuments() with tainted filter — NoSQL injection (operator injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

		// --- Azure Cosmos DB NoSQL injection (CWE-943) ---
		// Microsoft.Azure.Cosmos (SDK v3) query APIs accept raw SQL strings or
		// QueryDefinition instances. Passing attacker-controlled SQL (e.g. via
		// `new QueryDefinition($"SELECT * FROM c WHERE c.id = '{userId}'")`)
		// enables NoSQL/SQL-API injection. The canonical sanitizer is
		// QueryDefinition.WithParameter("@id", userId).
		{
			ID:            "csharp.cosmos.getitemqueryiterator",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.GetItemQueryIterator\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "Container",
			MethodName:    "GetItemQueryIterator",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Azure Cosmos DB Container.GetItemQueryIterator with tainted query string or QueryDefinition (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cosmos.getitemquerystreamiterator",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.GetItemQueryStreamIterator\s*\(`,
			ObjectType:    "Container",
			MethodName:    "GetItemQueryStreamIterator",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Azure Cosmos DB Container.GetItemQueryStreamIterator with tainted query string (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cosmos.querydefinition.new",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+QueryDefinition\s*\(`,
			ObjectType:    "QueryDefinition",
			MethodName:    "QueryDefinition",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Azure Cosmos DB QueryDefinition constructed from tainted query string (NoSQL injection; use WithParameter for binding)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cosmos.createitemquery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateItemQuery\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "Container",
			MethodName:    "CreateItemQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Azure Cosmos DB Container.CreateItemQuery with tainted SQL expression (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cosmos.createdocumentquery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateDocumentQuery\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "CreateDocumentQuery",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Azure Cosmos DB DocumentClient.CreateDocumentQuery (legacy SDK v2) with tainted SQL expression (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}

// csharpCryptoSinks returns sink definitions for detecting weak cryptographic
// algorithm usage in C#. These patterns identify code that should be flagged.
func csharpCryptoSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.crypto.md5",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `MD5\.Create\(|MD5CryptoServiceProvider`,
			ObjectType:    "System.Security.Cryptography",
			MethodName:    "MD5.Create",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "MD5 hash usage (weak, vulnerable to collision attacks)",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "csharp.crypto.sha1",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `SHA1\.Create\(|SHA1CryptoServiceProvider|SHA1Managed`,
			ObjectType:    "System.Security.Cryptography",
			MethodName:    "SHA1.Create",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "SHA1 hash usage (weak, vulnerable to collision attacks)",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "csharp.crypto.rc2",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `RC2CryptoServiceProvider|RC2\.Create\s*\(`,
			ObjectType:    "System.Security.Cryptography",
			MethodName:    "RC2.Create",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "RC2 cipher usage (weak 64-bit block cipher, vulnerable to attacks; use AES)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "csharp.crypto.insecure_random",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+Random\s*\(`,
			ObjectType:    "System.Random",
			MethodName:    "Random()",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "System.Random is not cryptographically secure (use RandomNumberGenerator for security contexts)",
			CWEID:         "CWE-338",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "csharp.crypto.weak_symmetric",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `(?:^|[^a-zA-Z])` + `D` + `E` + `S` + `\.Create\(|` + `D` + `E` + `SCryptoServiceProvider|Triple` + `D` + `E` + `S` + `\.Create\(`,
			ObjectType:    "System.Security.Cryptography",
			MethodName:    "Weak symmetric cipher",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Weak symmetric cipher usage (use AES instead)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		// --- JWT signature bypass (CWE-345 / CWE-347) ---
		// JwtSecurityTokenHandler.ReadJwtToken parses the encoded JWT but DOES
		// NOT verify the signature. Using the resulting claims for any
		// authorisation decision is a critical CWE-345 (Insufficient
		// Verification of Data Authenticity). Use ValidateToken instead.
		// ObjectType is intentionally empty: ReadJwtToken is distinctive and
		// receivers are commonly named "handler" / "tokenHandler" / "_handler"
		// rather than the full type name.
		{
			ID:            "csharp.jwt.handler.readjwttoken",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `\.ReadJwtToken\s*\(`,
			ObjectType:    "",
			MethodName:    "ReadJwtToken",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "JwtSecurityTokenHandler.ReadJwtToken parses a JWT without signature verification (use ValidateToken instead)",
			CWEID:         "CWE-345",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		// jose-jwt: Jose.JWT.Payload and Jose.JWT.Headers are documented in the
		// upstream README as parsing helpers that DO NOT verify the signature.
		// Both have caused real-world auth bypasses when used to authorise
		// requests. Use Jose.JWT.Decode(token, key, algorithm) instead.
		{
			ID:            "csharp.jose.jwt.payload",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `Jose\.JWT\.Payload\s*\(`,
			ObjectType:    "Jose.JWT",
			MethodName:    "Payload",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Jose.JWT.Payload extracts JWT claims without signature verification (jose-jwt)",
			CWEID:         "CWE-345",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "csharp.jose.jwt.headers",
			Category:      taint.SnkCrypto,
			Language:      rules.LangCSharp,
			Pattern:       `Jose\.JWT\.Headers\s*\(`,
			ObjectType:    "Jose.JWT",
			MethodName:    "Headers",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Jose.JWT.Headers reads JWT headers without signature verification (jose-jwt)",
			CWEID:         "CWE-345",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
	}
}

// csharpDeserializationSinks returns sink definitions for dangerous .NET
// deserializers and dynamic code loading. These have caused major CVEs
// (CVE-2020-0688 Exchange RCE via ObjectStateFormatter, ysoserial.net chains).
func csharpDeserializationSinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- Dangerous Deserializers (CWE-502) ---
		// These formatters allow arbitrary type instantiation from untrusted data,
		// enabling remote code execution via gadget chains (ysoserial.net).
		{
			ID:            "csharp.objectstateformatter.deserialize",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `ObjectStateFormatter.*\.Deserialize\s*\(`,
			ObjectType:    "ObjectStateFormatter",
			MethodName:    "ObjectStateFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ObjectStateFormatter deserialization (ViewState RCE — CVE-2020-0688)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.soapformatter.deserialize",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `SoapFormatter.*\.Deserialize\s*\(`,
			ObjectType:    "SoapFormatter",
			MethodName:    "SoapFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SoapFormatter deserialization of untrusted data (RCE via gadget chains)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.losformatter.deserialize",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `LosFormatter.*\.Deserialize\s*\(`,
			ObjectType:    "LosFormatter",
			MethodName:    "LosFormatter.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "LosFormatter deserialization of untrusted data (RCE risk)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.netdatacontractserializer.readobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `NetDataContractSerializer.*\.Deserialize\s*\(|NetDataContractSerializer.*\.ReadObject\s*\(`,
			ObjectType:    "NetDataContractSerializer",
			MethodName:    "NetDataContractSerializer.Deserialize/ReadObject",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "NetDataContractSerializer deserialization (RCE via type confusion)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.json.typenamehandling",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`,
			ObjectType:    "JsonSerializerSettings",
			MethodName:    "TypeNameHandling.All/Auto/Objects/Arrays",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Newtonsoft.Json TypeNameHandling enables type-based deserialization attacks",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.javascriptserializer.deserialize",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `JavaScriptSerializer.*\.Deserialize\s*\(`,
			ObjectType:    "JavaScriptSerializer",
			MethodName:    "JavaScriptSerializer.Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "JavaScriptSerializer deserialization (dangerous with custom TypeResolver)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "csharp.datacontractjsonserializer.readobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `DataContractJsonSerializer.*\.ReadObject\s*\(`,
			ObjectType:    "DataContractJsonSerializer",
			MethodName:    "DataContractJsonSerializer.ReadObject",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DataContractJsonSerializer deserialization of untrusted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		// MBrace.FsPickler — Deserialize<T>(stream) reconstructs arbitrary .NET
		// object graphs. Without a registered type filter / SerializationBinder
		// equivalent it is a polymorphic deserialization sink.
		{
			ID:            "csharp.fspickler.deserialize",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `(?:FsPickler|pickler)\s*\.\s*Deserialize\s*<`,
			ObjectType:    "MBrace.FsPickler.FsPicklerSerializer",
			MethodName:    "Deserialize",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MBrace.FsPickler Deserialize<T>(stream) reconstructs arbitrary object graphs from a tainted stream (polymorphic deserialization, CWE-502)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		// fastJSON — JSON.ToObject / JSON.Parse honour the embedded "$types"
		// directive when Global.TypeNameHandling is enabled, instantiating
		// attacker-named types (same class of bug as Json.NET TypeNameHandling).
		{
			ID:            "csharp.fastjson.toobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `\bfastJSON\.JSON\.(?:ToObject|Parse)\s*(?:<[^>]*>\s*)?\(`,
			ObjectType:    "fastJSON.JSON",
			MethodName:    "fastJSON.JSON.ToObject/Parse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "fastJSON JSON.ToObject/Parse honours the embedded $types directive (Global.TypeNameHandling), deserializing attacker-named types (CWE-502)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		// System.Data.DataSet / DataTable ReadXml — reading attacker-controlled
		// XML into a DataSet is a documented .NET deserialization gadget: the
		// schema embedded in the XML (an inline XSD) drives type construction, so
		// a crafted document with a forged column type (e.g. an ObjectDataProvider
		// or an arbitrary serializable type) yields type-confusion RCE — the same
		// vector exploited in the "DataSet/DataTable" gadget family. ReadXml is a
		// distinctive method (no collision with the generic XmlDocument.Load /
		// XmlReader.Create XXE sinks above), and the receiver is conventionally
		// `ds`/`dataset`/`dt`/`datatable`/`table` — aliased in the matcher.
		{
			ID:            "csharp.dataset.readxml",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `\.ReadXml\s*\(`,
			ObjectType:    "System.Data.DataSet",
			MethodName:    "ReadXml",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DataSet/DataTable.ReadXml on attacker-controlled XML reconstructs types named by the embedded inline schema (type-confusion deserialization gadget, CWE-502). Validate the XML against a fixed, trusted XSD via ReadXmlSchema before ReadXml, or parse into a strongly-typed DTO instead.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		// ServiceStack.Text TypeSerializer.DeserializeFromString<T> / the
		// JsConfig.TypeAttr-driven `__type` resolution reconstruct attacker-named
		// types from a tainted string the same way Json.NET TypeNameHandling does.
		// `DeserializeFromString` is distinctive to ServiceStack.Text (no overlap
		// with System.Text.Json / Newtonsoft method names), so binding is precise
		// even though the receiver is a static type. The polymorphic `__type`
		// payload is the gadget vector.
		{
			ID:            "csharp.servicestack.text.deserializefromstring",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangCSharp,
			Pattern:       `(?:TypeSerializer|JsonSerializer)\.DeserializeFromString\s*<`,
			ObjectType:    "ServiceStack.Text.TypeSerializer",
			MethodName:    "DeserializeFromString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ServiceStack.Text TypeSerializer/JsonSerializer.DeserializeFromString<T> resolves the embedded __type directive, instantiating attacker-named types from a tainted string (polymorphic deserialization, CWE-502). Deserialize into a fixed concrete type and disable JsConfig type resolution for untrusted input.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- XSLT injection (CWE-91) ---
		// System.Xml.Xsl.XslCompiledTransform executes the loaded stylesheet. A
		// stylesheet built from untrusted input is code execution: XSLT supports
		// embedded <msxsl:script> blocks (full .NET code) and the document()
		// function (file/SSRF read), so a tainted stylesheet reaching Transform
		// is arbitrary-code/-data execution. The danger is the STYLESHEET, not the
		// input document — `Load` carries the stylesheet, `Transform` executes it.
		// `Load` collides with Assembly.Load/XamlReader.Load, so this is anchored
		// on the XslCompiledTransform-exclusive ObjectType plus the conventional
		// `xslt`/`transform`/`xsl` receiver alias. The XsltSettings.Default (no
		// script, no document()) safe path is recognised by the paired sanitizer.
		{
			ID:            "csharp.xslt.load",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.Load\s*\(`,
			ObjectType:    "System.Xml.Xsl.XslCompiledTransform",
			MethodName:    "Load",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XslCompiledTransform.Load on a tainted stylesheet — XSLT supports embedded <msxsl:script> (.NET code) and document() (file/SSRF), so an attacker-controlled stylesheet is code execution (XSLT injection, CWE-91). Load only trusted, application-bundled stylesheets and disable scripts via XsltSettings.Default.",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Dynamic Code Loading (CWE-94) ---
		{
			ID:            "csharp.assembly.load",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `Assembly\.Load\s*\(|Assembly\.LoadFrom\s*\(|Assembly\.LoadFile\s*\(|Assembly\.UnsafeLoadFrom\s*\(`,
			ObjectType:    "System.Reflection.Assembly",
			MethodName:    "Assembly.Load/LoadFrom/LoadFile",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic assembly loading with potentially tainted path or bytes",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.csharpscript.evaluate",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `CSharpScript\.EvaluateAsync\s*\(|CSharpScript\.RunAsync\s*\(|CSharpScript\.Create\s*\(`,
			ObjectType:    "Microsoft.CodeAnalysis.CSharp.Scripting",
			MethodName:    "CSharpScript.EvaluateAsync/RunAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Roslyn C# scripting with potentially tainted code string",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.activator.createinstance",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `Activator\.CreateInstance\s*\(.*Type\.GetType\s*\(`,
			ObjectType:    "System.Activator",
			MethodName:    "Activator.CreateInstance(Type.GetType())",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Dynamic type instantiation from user-controlled type name",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Expression Tree Injection (CWE-94) ---
		{
			ID:            "csharp.expression.compile",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `DynamicExpression\.Parse\s*\(|DynamicExpressionParser\.ParseLambda\s*\(`,
			ObjectType:    "System.Linq.Dynamic",
			MethodName:    "DynamicExpression.Parse/ParseLambda",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Dynamic LINQ expression parsing with potentially tainted input",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Email Injection (CWE-93) ---
		{
			ID:            "csharp.smtpclient.send",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `SmtpClient.*\.Send\s*\(|SmtpClient.*\.SendMailAsync\s*\(|MailMessage\s*\(`,
			ObjectType:    "SmtpClient",
			MethodName:    "SmtpClient.Send/SendMailAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Email sending with potentially tainted headers/subject (email injection)",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},
		// System.Net.Mail.MailAddress — displayName (2nd ctor arg) is not
		// CRLF-validated. Tainted display name becomes part of From/To header
		// and enables RFC-5322 header injection.
		{
			ID:            "csharp.mailaddress.ctor",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `\bnew\s+MailAddress\s*\(`,
			ObjectType:    "MailAddress",
			MethodName:    "MailAddress",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "System.Net.Mail.MailAddress constructor with tainted address/displayName (CRLF header injection, CWE-93)",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},
		// MimeKit MailboxAddress — name and address args accept arbitrary
		// strings. CVE-2026-30227 confirmed CRLF injection via the quoted
		// local-part of address, enabling SMTP command injection.
		{
			ID:            "csharp.mimekit.mailboxaddress.ctor",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `\bnew\s+MailboxAddress\s*\(`,
			ObjectType:    "MailboxAddress",
			MethodName:    "MailboxAddress",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "MimeKit MailboxAddress constructor with tainted name/address (CRLF injection — CVE-2026-30227, CWE-93)",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},
		// System.Net.Mail.MailMessage.Headers is a NameValueCollection — Add
		// with tainted name or value writes raw bytes into the SMTP DATA
		// section, allowing arbitrary header injection (Bcc, Reply-To, ...).
		{
			ID:            "csharp.mailmessage.headers.add",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `\.Headers\.Add\s*\(`,
			ObjectType:    "MailMessage.Headers",
			MethodName:    "MailMessage.Headers.Add",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "MailMessage.Headers.Add with tainted header name/value (CRLF email header injection, CWE-93)",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},
		// AddHeader(name, value) — matches SendGridMessage.AddHeader and the
		// legacy ASP.NET System.Web.HttpResponse.AddHeader API. Both write a
		// tainted name/value pair verbatim into outgoing MIME/HTTP headers.
		{
			ID:            "csharp.addheader",
			Category:      taint.SnkHeader,
			Language:      rules.LangCSharp,
			Pattern:       `\.AddHeader\s*\(`,
			ObjectType:    "",
			MethodName:    "AddHeader",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "AddHeader(name, value) with tainted input — covers SendGridMessage and System.Web.HttpResponse (CRLF injection, CWE-93/113)",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}

// csharpTrustBoundarySinks returns sink definitions for trust boundary violations
// in ASP.NET / ASP.NET Core (CWE-501). Storing tainted data in session, TempData,
// or ViewBag without validation crosses a trust boundary.
func csharpTrustBoundarySinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.session.setstring",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `HttpContext\.Session\.Set(?:String|Int32)\s*\(|\.Session\.Set(?:String|Int32)\s*\(`,
			ObjectType:    "ISession",
			MethodName:    "Session.SetString/SetInt32",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Trust boundary violation: tainted data stored in ASP.NET Core session",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.session.indexer",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `Session\s*\[\s*["'][^"']+["']\s*\]\s*=[^=]`,
			ObjectType:    "HttpSessionState",
			MethodName:    "Session[]",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Trust boundary violation: tainted data stored in ASP.NET session via indexer",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.tempdata.store",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `TempData\s*\[\s*["'][^"']+["']\s*\]\s*=[^=]`,
			ObjectType:    "ITempDataDictionary",
			MethodName:    "TempData[]",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Trust boundary violation: tainted data stored in TempData (serialized across redirects)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.viewdata.store",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `ViewData\s*\[\s*["'][^"']+["']\s*\]\s*=[^=]|ViewBag\.\w+\s*=[^=]`,
			ObjectType:    "ViewDataDictionary/ViewBag",
			MethodName:    "ViewData[]/ViewBag",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Trust boundary violation: tainted data passed to view without validation",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Message broker / task queue producer trust boundary (CWE-501) ---
		// Producer-side sinks: a web handler publishes user-controlled values
		// into a broker (RabbitMQ / Kafka / Azure Service Bus / Azure Event
		// Grid / AWS SQS). The payload is serialized into the broker and
		// later deserialized + re-processed by a consumer running in a
		// privileged context. That crossing is a trust-boundary violation —
		// consumer code that assumes internal/validated payloads is exposed
		// to secondary injection, logic bypass, or deserialization exploits.
		//
		// C# already has the consumer-side sources (csharp.rabbitmq.body,
		// csharp.kafka.consume.value, csharp.azure.servicebus.body,
		// csharp.azure.eventhub.body, csharp.azure.eventgrid.data,
		// csharp.aws.sqs.receivemessage, csharp.masstransit.message) but no
		// producer-side sinks — this brings the C# side in line with Java
		// (PR #426), Rust (PR #424), Kotlin, Python Celery/RQ, Ruby
		// Sidekiq/ActiveJob, and JS BullMQ/amqplib.
		{
			ID:            "csharp.rabbitmq.channel.basicpublish",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `\.BasicPublish\s*\(`,
			ObjectType:    "",
			MethodName:    "BasicPublish",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "RabbitMQ.Client IModel/IChannel.BasicPublish with tainted body crosses trust boundary (delivered via AMQP broker, re-processed by consumer in a privileged context)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.kafka.producer.produceasync",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `\.ProduceAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "ProduceAsync",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Confluent.Kafka IProducer.ProduceAsync with tainted message crosses trust boundary (serialized to Kafka topic, re-processed by consumer in a privileged context)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.azure.servicebus.sendmessageasync",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `\.SendMessageAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "SendMessageAsync",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Azure Service Bus ServiceBusSender.SendMessageAsync or AWS SQS AmazonSQSClient.SendMessageAsync with tainted body crosses trust boundary (enqueued to subscriber, re-processed in privileged context)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.azure.servicebus.sendmessagesasync",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `\.SendMessagesAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "SendMessagesAsync",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Azure Service Bus ServiceBusSender.SendMessagesAsync batch with tainted messages crosses trust boundary (enqueued to subscriber, re-processed in privileged context)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.azure.eventgrid.sendevent",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangCSharp,
			Pattern:       `\.SendEventAsync\s*\(|\.SendEventsAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "SendEventAsync/SendEventsAsync",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Azure Event Grid EventGridPublisherClient.SendEventAsync/SendEventsAsync with tainted event data crosses trust boundary (delivered to subscriber, re-processed in privileged context)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
	}
}

// csharpRedirectSinks returns additional open redirect sinks beyond the core
// Response.Redirect/Redirect/RedirectPermanent already in csharpCoreSinks.
func csharpRedirectSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.controller.redirecttoaction",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `RedirectToAction\s*\(|RedirectToRoute\s*\(|RedirectToActionPermanent\s*\(|RedirectToRoutePermanent\s*\(`,
			ObjectType:    "Controller",
			MethodName:    "RedirectToAction/RedirectToRoute",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Redirect with potentially tainted action/route values (open redirect risk)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.blazor.navigationmanager.navigateto",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `NavigationManager\.NavigateTo\s*\(`,
			ObjectType:    "NavigationManager",
			MethodName:    "NavigateTo",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Blazor NavigationManager.NavigateTo with potentially tainted URL (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.results.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `Results\.Redirect\s*\(`,
			ObjectType:    "Results",
			MethodName:    "Results.Redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ASP.NET Core Minimal API Results.Redirect with tainted URL (open redirect — use Results.LocalRedirect for local-only)",
			// RedirectPreserveMethod / RedirectPermanentPreserveMethod are highly
			// ASP.NET-specific names; ObjectType="" allows matching on bare calls
			// (`return RedirectPreserveMethod(url)`) common in Controller methods.
		},
		{
			ID:            "csharp.controller.redirectpreservemethod",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `RedirectPreserveMethod\s*\(|RedirectPermanentPreserveMethod\s*\(`,
			ObjectType:    "",
			MethodName:    "RedirectPreserveMethod/RedirectPermanentPreserveMethod",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ASP.NET Core 307/308 redirect preserving HTTP method with potentially tainted URL (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.typedresults.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `TypedResults\.Redirect\s*\(`,
			ObjectType:    "TypedResults",
			MethodName:    "TypedResults.Redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ASP.NET Core Minimal API TypedResults.Redirect with tainted URL (open redirect — use TypedResults.LocalRedirect for local-only)",
			// RedirectToPage* are Razor Pages / Controller methods normally
			// called without an explicit receiver.
		},
		{
			ID:            "csharp.controller.redirecttopage",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `RedirectToPage\s*\(|RedirectToPagePermanent\s*\(|RedirectToPagePreserveMethod\s*\(|RedirectToPagePermanentPreserveMethod\s*\(`,
			ObjectType:    "",
			MethodName:    "RedirectToPage/RedirectToPagePermanent/RedirectToPagePreserveMethod/RedirectToPagePermanentPreserveMethod",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Razor Pages RedirectToPage with tainted page name — trust-boundary violation (can bypass page-level auth)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.result.redirectresult",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+RedirectResult\s*\(`,
			ObjectType:    "RedirectResult",
			MethodName:    "RedirectResult",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ASP.NET Core RedirectResult constructor with tainted URL (open redirect — use LocalRedirectResult for local-only)",
		},
		{
			ID:            "csharp.server.transfer",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `Server\.Transfer\s*\(|Server\.TransferRequest\s*\(`,
			ObjectType:    "Server",
			MethodName:    "Server.Transfer/Server.TransferRequest",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Legacy ASP.NET HttpServerUtility.Transfer with tainted path (server-side redirect, may expose unintended pages)",
			// Constructor sinks for the three non-local ActionResult redirect
			// classes. ObjectType="" so the MethodName list drives matching.
		},
		{
			ID:            "csharp.result.redirecttoresult",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+RedirectToActionResult\s*\(|new\s+RedirectToRouteResult\s*\(|new\s+RedirectToPageResult\s*\(`,
			ObjectType:    "",
			MethodName:    "RedirectToActionResult/RedirectToRouteResult/RedirectToPageResult",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "ActionResult redirect constructor with tainted action/route/page name (trust-boundary violation)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
	}
}

// csharpLogSinks returns additional log injection sinks beyond the core
// ILogger and Console.WriteLine already in csharpCoreSinks.
func csharpLogSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.serilog.log",
			Category:      taint.SnkLog,
			Language:      rules.LangCSharp,
			Pattern:       `Log\.(?:Information|Warning|Error|Debug|Fatal|Verbose)\s*\(`,
			ObjectType:    "Serilog.Log",
			MethodName:    "Log.Information/Warning/Error",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Serilog logging with potentially tainted message template (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "csharp.nlog.logger",
			Category:      taint.SnkLog,
			Language:      rules.LangCSharp,
			Pattern:       `(?:_logger|logger|Logger)\.(?:Info|Warn|Error|Debug|Fatal|Trace)\s*\(`,
			ObjectType:    "NLog.ILogger",
			MethodName:    "Logger.Info/Warn/Error",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "NLog logger with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "csharp.diagnostics.trace",
			Category:      taint.SnkLog,
			Language:      rules.LangCSharp,
			Pattern:       `Trace\.Trace(?:Information|Warning|Error)\s*\(|Trace\.Write(?:Line)?\s*\(`,
			ObjectType:    "System.Diagnostics.Trace",
			MethodName:    "Trace.TraceInformation/Write",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "System.Diagnostics.Trace output with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "csharp.eventlog.writeentry",
			Category:      taint.SnkLog,
			Language:      rules.LangCSharp,
			Pattern:       `EventLog\.WriteEntry\s*\(`,
			ObjectType:    "System.Diagnostics.EventLog",
			MethodName:    "EventLog.WriteEntry",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Windows EventLog with potentially tainted message (log injection into system log)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
	}
}

// csharpSSRFExtraSinks covers modern .NET HTTP client libraries and transports
// not already in csharpCoreSinks: Flurl, System.Net.Http.Json extension
// methods, HttpRequestMessage construction, and grpc-dotnet channel
// creation. All are real-world CWE-918 sinks where a tainted URL leads to
// an outbound request. ObjectType is intentionally left empty for
// method names that are distinctive enough (e.g. PostJsonAsync is Flurl-only,
// PostAsJsonAsync is System.Net.Http.Json-only) so that receiver naming
// does not block detection.
func csharpSSRFExtraSinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- Flurl (tmenier/Flurl) ---
		{
			ID:            "csharp.flurl.getjsonasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.GetJsonAsync\s*[<(]`,
			ObjectType:    "",
			MethodName:    "GetJsonAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flurl GetJsonAsync from potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.flurl.postjsonasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.PostJsonAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "PostJsonAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flurl PostJsonAsync to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.flurl.putjsonasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.PutJsonAsync\s*\(|\.PatchJsonAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "PutJsonAsync/PatchJsonAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flurl PutJsonAsync/PatchJsonAsync to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.flurl.poststringasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.PostStringAsync\s*\(|\.PostUrlEncodedAsync\s*\(|\.PostMultipartAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "PostStringAsync/PostUrlEncodedAsync/PostMultipartAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flurl Post*Async variant to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.flurl.downloadfileasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.DownloadFileAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "DownloadFileAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flurl/WebClient DownloadFileAsync from potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- System.Net.Http.Json extension methods (.NET 5+) ---
		{
			ID:            "csharp.httpclient.postasjsonasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.PostAsJsonAsync\s*\(|\.PutAsJsonAsync\s*\(|\.PatchAsJsonAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "PostAsJsonAsync/PutAsJsonAsync/PatchAsJsonAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HttpClient System.Net.Http.Json extension method with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.httpclient.getfromjsonasync",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.GetFromJsonAsync\s*[<(]|\.DeleteFromJsonAsync\s*[<(]`,
			ObjectType:    "",
			MethodName:    "GetFromJsonAsync/DeleteFromJsonAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HttpClient System.Net.Http.Json extension method with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- HttpRequestMessage construction ---
		{
			ID:            "csharp.httprequestmessage.new",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+HttpRequestMessage\s*\(`,
			ObjectType:    "System.Net.Http.HttpRequestMessage",
			MethodName:    "HttpRequestMessage",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "HttpRequestMessage constructed with potentially tainted URL (SSRF when sent via HttpClient)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- grpc-dotnet ---
		{
			ID:            "csharp.grpc.channel.foraddress",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `GrpcChannel\.ForAddress\s*\(`,
			ObjectType:    "Grpc.Net.Client.GrpcChannel",
			MethodName:    "GrpcChannel.ForAddress",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "gRPC channel opened against potentially tainted address (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- WebClient.UploadString/UploadData/UploadValues variants not in
		// core. UploadString/UploadData/UploadValues are WebClient-specific
		// method names in practice; empty ObjectType keeps matching resilient to
		// receiver naming (client vs webClient) without generating broad FPs.
		{
			ID:            "csharp.webclient.uploadstring",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.UploadString\s*\(|\.UploadStringAsync\s*\(|\.UploadStringTaskAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "UploadString/UploadStringAsync/UploadStringTaskAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WebClient string upload to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "csharp.webclient.uploaddata",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.UploadData\s*\(|\.UploadDataAsync\s*\(|\.UploadDataTaskAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "UploadData/UploadDataAsync/UploadDataTaskAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WebClient data upload to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		// WebClient.UploadValues(url, NameValueCollection) (and its
		// async/overload forms) is the form-POST sibling of UploadString /
		// UploadData — same WebClient-specific method name, same SSRF surface:
		// the first argument is the request URL. Like the other Upload* sinks an
		// empty ObjectType + call-anchored Pattern keeps matching resilient to
		// receiver naming (client vs webClient vs wc) without the FQN-ObjectType
		// dead-keying that left the core Download* sinks unreachable pre-#1253.
		// SINK MATCH only — a finding still requires a tainted URL in arg 0, so a
		// const/literal URL produces no flow. The 3-arg overload
		// UploadValues(url, "POST", coll) still has the URL in arg 0.
		{
			ID:            "csharp.webclient.uploadvalues",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCSharp,
			Pattern:       `\.UploadValues\s*\(|\.UploadValuesAsync\s*\(|\.UploadValuesTaskAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "UploadValues/UploadValuesAsync/UploadValuesTaskAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WebClient form-values upload to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
	}
}

// csharpSSHNetSinks covers Renci.SshNet (SSH.NET) — the dominant .NET SSH
// library (100M+ NuGet downloads). Tainted input flowing into
// SshClient.RunCommand / CreateCommand is command injection on the remote
// host. Tainted input flowing into SftpClient / ScpClient path arguments is
// path traversal on the remote filesystem.
//
// Method names here (RunCommand, CreateCommand on SshClient; UploadFile /
// DownloadFile / ReadAllText etc. on SftpClient / ScpClient) are scoped via
// ObjectType receiver heuristics so they don't fire on unrelated .NET APIs
// (e.g. File.ReadAllText, WebClient.UploadFile, IDbConnection.CreateCommand
// which is arg-less).
func csharpSSHNetSinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- SSH remote command execution (CWE-78) ---
		// SshClient.RunCommand is SSH.NET-unique; tainted command text is
		// executed directly on the remote host's shell.
		// SshClient.RunCommand is SSH.NET-unique — no stdlib or other
		// common .NET API uses the method name "RunCommand" on a connection-
		// like object. ObjectType left empty so receiver-naming (client,
		// sshClient, ssh) doesn't block the match.
		{
			ID:            "csharp.sshnet.runcommand",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `\.RunCommand\s*\(`,
			ObjectType:    "",
			MethodName:    "RunCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SSH.NET SshClient.RunCommand with potentially tainted command text (RCE on remote host)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		// SshClient.CreateCommand(commandText) returns an SshCommand that
		// runs on .Execute(). IDbConnection.CreateCommand() is arg-less, so
		// the DangerousArgs[0] check keeps this SSH-specific in practice.
		{
			ID:            "csharp.sshnet.createcommand",
			Category:      taint.SnkCommand,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateCommand\s*\(\s*[^)]`,
			ObjectType:    "",
			MethodName:    "CreateCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SSH.NET SshClient.CreateCommand with potentially tainted command text (RCE on remote host when Execute() is called)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SFTP remote file reads (CWE-22) ---
		{
			ID:            "csharp.sshnet.sftp.readalltext",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `\.ReadAllText\s*\(|\.ReadAllTextAsync\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "ReadAllText/ReadAllTextAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.ReadAllText with potentially tainted remote path (path traversal on remote filesystem)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.readallbytes",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `\.ReadAllBytes\s*\(|\.ReadAllBytesAsync\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "ReadAllBytes/ReadAllBytesAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.ReadAllBytes with potentially tainted remote path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.openread",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `\.OpenRead\s*\(|\.Open\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "OpenRead/Open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.OpenRead with potentially tainted remote path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.downloadfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `\.DownloadFile\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "DownloadFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.DownloadFile with potentially tainted remote path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- SFTP remote file writes (CWE-22) ---
		{
			ID:            "csharp.sshnet.sftp.writealltext",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.WriteAllText\s*\(|\.WriteAllTextAsync\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "WriteAllText/WriteAllTextAsync",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.WriteAllText with potentially tainted remote path/content (path traversal on remote filesystem)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.writeallbytes",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.WriteAllBytes\s*\(|\.WriteAllBytesAsync\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "WriteAllBytes/WriteAllBytesAsync",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.WriteAllBytes with potentially tainted remote path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.appendalltext",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.AppendAllText\s*\(|\.AppendAllTextAsync\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "AppendAllText/AppendAllTextAsync",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.AppendAllText with potentially tainted remote path/content (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.uploadfile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.UploadFile\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "UploadFile",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.UploadFile with potentially tainted remote path (path traversal on remote filesystem)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.deletefile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.DeleteFile\s*\(|\.Delete\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "DeleteFile/Delete",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.DeleteFile with potentially tainted remote path (destructive path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.sftp.createdirectory",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateDirectory\s*\(`,
			ObjectType:    "Renci.SshNet.SftpClient",
			MethodName:    "CreateDirectory",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET SftpClient.CreateDirectory with potentially tainted remote path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- SCP remote file transfers (CWE-22) ---
		// ScpClient.Upload(sourceFile, remotePath) / Download(remotePath, destFile).
		// The remote-path argument is the injection surface.
		{
			ID:            "csharp.sshnet.scp.upload",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCSharp,
			Pattern:       `\.Upload\s*\(`,
			ObjectType:    "Renci.SshNet.ScpClient",
			MethodName:    "Upload",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "SSH.NET ScpClient.Upload with potentially tainted remote destination path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "csharp.sshnet.scp.download",
			Category:      taint.SnkFileRead,
			Language:      rules.LangCSharp,
			Pattern:       `\.Download\s*\(`,
			ObjectType:    "Renci.SshNet.ScpClient",
			MethodName:    "Download",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSH.NET ScpClient.Download with potentially tainted remote source path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
	}
}

// csharpNeo4jSinks returns sink definitions for Neo4j Cypher injection (CWE-943)
// in C#. Covers the official Neo4j.Driver (IAsyncSession.RunAsync, IAsyncTransaction.RunAsync,
// IDriver.ExecutableQuery) and the older Neo4jClient fluent API (.Cypher.Match / .Cypher.Where).
//
// Neo4j Cypher allows parameterised queries via $name placeholders bound through a
// parameters dictionary or .WithParam(); concatenating user input directly into
// Cypher text enables Cypher injection — analogous to SQL injection on a graph DB.
// See https://neo4j.com/developer/kb/protecting-against-cypher-injection/
func csharpNeo4jSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.neo4j.session.run",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `(?:session|sess|asyncSession|neo4jSession)\.Run\s*\(`,
			ObjectType:    "Session",
			MethodName:    "Run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j.Driver ISession.Run() with tainted Cypher string (Cypher injection); pass user values via parameters dictionary instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.neo4j.session.runasync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `(?:session|sess|asyncSession|neo4jSession)\.RunAsync\s*\(`,
			ObjectType:    "Session",
			MethodName:    "RunAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j.Driver IAsyncSession.RunAsync() with tainted Cypher string (Cypher injection); pass user values via parameters dictionary instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.neo4j.tx.runasync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `(?:tx|txc|neo4jTx|asyncTx)\.RunAsync\s*\(`,
			ObjectType:    "Tx",
			MethodName:    "RunAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j.Driver IAsyncTransaction.RunAsync() (inside ExecuteReadAsync/ExecuteWriteAsync or BeginTransactionAsync block) with tainted Cypher string (Cypher injection); pass user values via parameters dictionary instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.neo4j.driver.executablequery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExecutableQuery\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "ExecutableQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j.Driver IDriver.ExecutableQuery() (driver 5.8+) with tainted Cypher string (Cypher injection); chain .WithParameters(new { name = userValue }) and use $name placeholders in the Cypher instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.neo4jclient.cypher.match",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.Cypher\.Match\s*\(`,
			ObjectType:    "Cypher",
			MethodName:    "Match",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4jClient ICypherFluentQuery.Match() with tainted Cypher fragment (Cypher injection); use .WithParam(name, value) and reference $name in the pattern instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.neo4jclient.cypher.where",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.Cypher\.Where\s*\(`,
			ObjectType:    "Cypher",
			MethodName:    "Where",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4jClient ICypherFluentQuery.Where(string) with tainted Cypher predicate (Cypher injection); use the Expression<Func<...>> overload or .WithParam() with a $name placeholder instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}

// csharpCassandraSinks returns sink definitions for DataStax Apache Cassandra
// CQL injection (CWE-943) in C#. Covers the official CassandraCSharpDriver
// (NuGet package "CassandraCSharpDriver", namespace Cassandra) ISession
// surface — Execute(string), Prepare(string), PrepareAsync(string) — plus the
// SimpleStatement(string) constructor.
//
// Note: ISession.ExecuteAsync(...) does NOT take a raw CQL string in the
// modern driver (only IStatement overloads exist), so it is not a sink. The
// safe form is Prepare(constantCql).Bind(values...) followed by
// session.Execute(boundStmt) / ExecuteAsync(boundStmt), or
// new SimpleStatement(constantCql, params...) with ? placeholders. Concatenating
// user input into the CQL string passed to Prepare() still produces an
// injectable query, so Prepare/PrepareAsync are listed as sinks here.
//
// See https://docs.datastax.com/en/latest-csharp-driver-api/api/Cassandra.ISession.html
func csharpCassandraSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.cassandra.session.execute",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `(?:session|sess|cqlSession|cassandraSession|cassSession)\.Execute\s*\(`,
			ObjectType:    "Session",
			MethodName:    "Execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax CassandraCSharpDriver ISession.Execute(string) with tainted CQL string (CQL injection); use Prepare() with ? placeholders + Bind(values), or new SimpleStatement(cql, values) with ? placeholders, instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cassandra.session.prepare",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `(?:session|sess|cqlSession|cassandraSession|cassSession)\.Prepare\s*\(`,
			ObjectType:    "Session",
			MethodName:    "Prepare",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax CassandraCSharpDriver ISession.Prepare(string) with tainted CQL string is still injectable — the prepared statement compiles whatever CQL it receives, so user input must use ? placeholders (bound via prepared.Bind) rather than string concatenation",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cassandra.session.prepareasync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `(?:session|sess|cqlSession|cassandraSession|cassSession)\.PrepareAsync\s*\(`,
			ObjectType:    "Session",
			MethodName:    "PrepareAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax CassandraCSharpDriver ISession.PrepareAsync(string) with tainted CQL string is still injectable — bind user values via the returned PreparedStatement.Bind(...) and reference them with ? placeholders in a constant CQL string instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.cassandra.simplestatement.ctor",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+SimpleStatement\s*\(`,
			ObjectType:    "SimpleStatement",
			MethodName:    "SimpleStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax CassandraCSharpDriver new SimpleStatement(cql, ...) seeded with tainted CQL string enables CQL injection; pass a constant CQL with ? placeholders and supply user values as the params object[] argument instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Google Cloud Data Warehouse SQL injection (CWE-89) ---
		// BigQuery and Spanner expose direct-SQL APIs that take a query string as
		// the first argument; tainting the SQL string causes SQL injection. Use
		// parameterized queries via BigQueryParameter / SpannerParameter instead.
		{
			ID:            "csharp.bigquery.client.executequery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExecuteQuery(?:Async)?\s*\(`,
			ObjectType:    "BigQueryClient",
			MethodName:    "ExecuteQuery/ExecuteQueryAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Google.Cloud.BigQuery.V2 BigQueryClient.ExecuteQuery(sql, parameters, ...) with tainted SQL string causes SQL injection; pass user values via the BigQueryParameter[] argument and reference them with @name placeholders in a constant SQL string instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.bigquery.client.createqueryjob",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateQueryJob(?:Async)?\s*\(`,
			ObjectType:    "BigQueryClient",
			MethodName:    "CreateQueryJob/CreateQueryJobAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Google.Cloud.BigQuery.V2 BigQueryClient.CreateQueryJob(sql, parameters, ...) with tainted SQL string causes SQL injection; bind user values via BigQueryParameter[] with @name placeholders in a constant SQL string instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.spanner.connection.createselectcommand",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateSelectCommand\s*\(`,
			ObjectType:    "SpannerConnection",
			MethodName:    "CreateSelectCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Google.Cloud.Spanner.Data SpannerConnection.CreateSelectCommand(sqlQueryStatement, parameters) with tainted SQL string causes SQL injection; supply user values via SpannerParameterCollection and reference them with @name placeholders in a constant SQL string instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.spanner.connection.createdmlcommand",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.CreateDmlCommand\s*\(`,
			ObjectType:    "SpannerConnection",
			MethodName:    "CreateDmlCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Google.Cloud.Spanner.Data SpannerConnection.CreateDmlCommand(sqlDmlStatement, parameters) with tainted SQL string allows DML (UPDATE/DELETE/INSERT) injection; bind user values via SpannerParameterCollection with @name placeholders in a constant DML statement instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.spanner.command.ctor",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+SpannerCommand\s*\(`,
			ObjectType:    "SpannerCommand",
			MethodName:    "SpannerCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Google.Cloud.Spanner.Data new SpannerCommand(commandText, connection, ...) seeded with tainted SQL string causes SQL injection; bind user values via the SpannerParameterCollection argument with @name placeholders in a constant SQL string instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}

// csharpElasticsearchSinks returns sink definitions for Elasticsearch /
// OpenSearch DSL injection (CWE-943) and Painless / Mustache template
// injection (CWE-94) in C#.
//
// Covers three first-party clients that share the same generated method
// surface (the Elasticsearch low-level transport is auto-generated from the
// REST spec, and OpenSearch.Client is a fork of NEST):
//
//   - NEST v7              — Nest.ElasticClient + Elasticsearch.Net.IElasticLowLevelClient
//   - Elastic.Clients.Elasticsearch v8 — ElasticsearchClient (replaces NEST)
//   - OpenSearch.Client v1+ — OpenSearch.Client.OpenSearchClient
//
// Only ES/OS-distinctive method names are listed (Msearch, DeleteByQuery,
// UpdateByQuery, Reindex, SearchTemplate, RenderSearchTemplate,
// ScriptsPainlessExecute, PutScript). Each entry covers both the sync and
// the *Async overload via the compound MethodName "X/XAsync" form. Generic
// names like Search / Index / Bulk are intentionally NOT listed here — they
// would FP on stdlib / EF Core / Mongo / SqlBulkCopy receivers, while these
// eight names are unique enough to keep ObjectType empty without false
// positives.
//
// All entries use DangerousArgs []int{-1} (usage-based) because the body
// position varies between the v7/v8 overloads — NEST v7 takes a request
// object or descriptor lambda; v8 takes either a request object or a
// LowLevel PostData body; OpenSearch mirrors NEST. Treating any tainted
// argument as the body matches all three shapes without missing the
// LowLevel.<method>(PostData.String(rawJson)) escape hatch.
//
// Refs:
//
//	https://www.elastic.co/guide/en/elasticsearch/painless/current/painless-execute-api.html
//	https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-security.html
//	https://opensearch.org/docs/latest/clients/dot-net/
//	CVE-2014-3120 (Painless/dynamic-script RCE class — same injection pattern)
func csharpElasticsearchSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.elasticsearch.client.msearch",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.Msearch(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "MsearchAsync/Msearch",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch / OpenSearch Msearch (multi-search) with tainted NDJSON body — DSL injection across mixed per-shard queries (CWE-943); use a typed request descriptor with parameterized fields instead of concatenating user input into the body",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.deletebyquery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangCSharp,
			Pattern:       `\.DeleteByQuery(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "DeleteByQueryAsync/DeleteByQuery",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch / OpenSearch DeleteByQuery with tainted query body — DSL injection on a destructive bulk operation (mass document deletion outside intended scope, CWE-943); use a typed Query DSL builder with parameterized term/match fields",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.updatebyquery",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.UpdateByQuery(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "UpdateByQueryAsync/UpdateByQuery",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch / OpenSearch UpdateByQuery body accepts a Painless script.source — tainted source = arbitrary Painless code execution on the cluster (CWE-94), plus DSL injection over the matching query",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.reindex",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.Reindex(?:OnServer)?(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "ReindexAsync/Reindex/ReindexOnServerAsync/ReindexOnServer",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch / OpenSearch Reindex body accepts a Painless script.source plus tainted source/dest selectors — Painless code execution and cross-index data movement (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.searchtemplate",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.SearchTemplate(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "SearchTemplateAsync/SearchTemplate",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Elasticsearch / OpenSearch SearchTemplate body accepts an inline Mustache template source — tainted template = template-source injection that compiles to attacker-shaped queries (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.rendersearchtemplate",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.RenderSearchTemplate(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "RenderSearchTemplateAsync/RenderSearchTemplate",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Elasticsearch / OpenSearch RenderSearchTemplate compiles a Mustache template source on the cluster — tainted source = template-source injection equivalent to SearchTemplate (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.scriptspainlessexecute",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.ScriptsPainlessExecute(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "ScriptsPainlessExecuteAsync/ScriptsPainlessExecute",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch / OpenSearch ScriptsPainlessExecute runs an ad-hoc Painless script on the cluster — tainted body = remote Painless code evaluation (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.elasticsearch.client.putscript",
			Category:      taint.SnkEval,
			Language:      rules.LangCSharp,
			Pattern:       `\.PutScript(?:Async)?\s*(?:<[^>]*>)?\s*\(`,
			ObjectType:    "",
			MethodName:    "PutScriptAsync/PutScript",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch / OpenSearch PutScript persists a tainted Painless script under a stored ID — every later request that invokes that ID executes attacker-controlled code on the cluster (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}

// csharpClickHouseSinks returns sink definitions for ClickHouse OLAP database
// SQL injection (CWE-89) in C#. Covers the two most-deployed .NET drivers
// for distinctive entry points (i.e. ones that don't overlap with Dapper /
// EF Core / SqlClient / Npgsql / MySqlConnector):
//
//   - DarkWanderer/ClickHouse.Client (NuGet "ClickHouse.Client", now also
//     republished as "ClickHouse.Driver"): ships extension methods on
//     DbConnection in ClickHouse.Client.Utility — ExecuteStatementAsync and
//     ExecuteDataTable — which take a raw SQL string as arg 0 with no
//     parameter-binding overload at the entry point. Real code typically
//     writes `await conn.ExecuteStatementAsync(sql)` or
//     `var dt = conn.ExecuteDataTable(sql)`. Parameter binding is available
//     only via the ClickHouseCommand.AddParameter API, which these helpers
//     bypass entirely when the SQL is built by string concatenation.
//
//   - killwort/ClickHouse.Ado (NuGet "ClickHouse.Ado"): older, still in use
//     in legacy codebases. Exposes `new ClickHouseCommand(commandText)` and
//     `new ClickHouseCommand(commandText, ClickHouseConnection)` ctors that
//     seed CommandText directly from a constructor argument.
//
// CreateCommand(sql) on Octonica.ClickHouseClient and ClickHouse.Ado is
// already covered by the existing csharp.sshnet.createcommand entry's
// overly-broad ObjectType:"" matcher — adding a second sink at the same
// call site would just clobber the dedup winner.
//
// Method/constructor names are unique to ClickHouse: ExecuteStatementAsync
// and ExecuteDataTable have no overlap with the standard ADO surface. The
// connection-extension entries scope by ObjectType "ClickHouseConnection"
// (matched as conn / connection / db via tsflow's "connection" alias
// heuristic).
//
// Refs:
//
//	https://github.com/DarkWanderer/ClickHouse.Client (ConnectionExtensions.cs)
//	https://github.com/killwort/ClickHouse-Net
//	https://clickhouse.com/docs/integrations/csharp
func csharpClickHouseSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.clickhouse.connection.executestatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExecuteStatementAsync\s*\(`,
			ObjectType:    "ClickHouseConnection",
			MethodName:    "ExecuteStatementAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DarkWanderer ClickHouse.Client ConnectionExtensions.ExecuteStatementAsync(this DbConnection, string sql, ...) executes a raw SQL string with no parameter-binding overload — tainted SQL is injectable (CWE-89). Use a ClickHouseCommand with `cmd.AddParameter(name, type, value)` and reference parameters with `{name:Type}` placeholders in a constant SQL string instead.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.clickhouse.connection.executedatatable",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `\.ExecuteDataTable\s*\(`,
			ObjectType:    "ClickHouseConnection",
			MethodName:    "ExecuteDataTable",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DarkWanderer ClickHouse.Client ConnectionExtensions.ExecuteDataTable(this DbConnection, string sql) populates a DataTable from a raw SQL string with no parameter-binding overload — tainted SQL is injectable (CWE-89). Use a ClickHouseCommand with parameter binding via `cmd.AddParameter(name, type, value)` and reference values with `{name:Type}` placeholders in a constant SQL string instead.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.clickhouse.command.ctor",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangCSharp,
			Pattern:       `new\s+ClickHouseCommand\s*\(\s*[^)]`,
			ObjectType:    "ClickHouseCommand",
			MethodName:    "ClickHouseCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ClickHouse.Ado new ClickHouseCommand(commandText) / new ClickHouseCommand(commandText, ClickHouseConnection) seeded with tainted SQL string causes SQL injection (CWE-89). Construct the command with `new ClickHouseCommand(connection)` (no SQL), then set `cmd.CommandText` to a constant SQL with `{name:Type}` placeholders and bind user values via cmd.Parameters.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}

// csharpCSVInjectionSinks returns sink definitions for CSV / spreadsheet
// formula injection (CWE-1236) in C#. When untrusted data is written into a
// CSV/TSV cell and the resulting file is later opened in Excel / LibreOffice
// Calc / Google Sheets, a value beginning with =, +, -, @, tab or CR is
// interpreted as a formula — enabling DDE / hyperlink-exfil / command
// execution on the viewer's machine. The fix is to prefix at-risk cells with
// a single quote / tab, or use a writer with injection protection enabled.
//
// Coverage:
//
//   - CsvHelper (NuGet "CsvHelper", ~100M+ downloads — the dominant .NET CSV
//     library): the canonical write surface is `csv.WriteField(field)`,
//     `csv.WriteRecord(record)`, `csv.WriteRecords(records)` and the async
//     `csv.WriteRecordsAsync(records)`, where `csv` is a CsvHelper.CsvWriter.
//     CsvHelper has opt-in injection protection via
//     `CsvConfiguration.InjectionOptions = InjectionOptions.Escape|Strip`
//     (off by default in 30.x), so a default-configured writer is vulnerable.
//
//   - ServiceStack.Text CsvSerializer.SerializeToString<T>(value): returns a
//     CSV string built from arbitrary records — same formula-injection risk.
//     Scoped by ObjectType so it doesn't fire on the sibling
//     JsonSerializer/XmlSerializer.SerializeToString static methods.
//
// All four CsvHelper entries scope by ObjectType "CsvHelper.CsvWriter" so
// tsflow only matches receivers whose name is a prefix of "csvwriter"
// (the idiomatic `csv` / `csvWriter`); a bare `writer.WriteField(...)` on an
// unrelated object does not match. WriteField / WriteRecord(s) are CsvHelper-
// distinctive method names with no overlap on the .NET BCL or popular Excel
// libraries (EPPlus / ClosedXML / NPOI use cell-value setters, not WriteField).
//
// Refs:
//
//	https://owasp.org/www-community/attacks/CSV_Injection
//	https://joshclose.github.io/CsvHelper/   (WriteField / WriteRecords API)
//	https://github.com/JoshClose/CsvHelper/blob/master/src/CsvHelper/Configuration/InjectionOptions.cs
func csharpCSVInjectionSinks() []taint.SinkDef {
	return []taint.SinkDef{
		{
			ID:            "csharp.csvhelper.writefield",
			Category:      taint.SnkCSV,
			Language:      rules.LangCSharp,
			Pattern:       `\.WriteField\s*\(`,
			ObjectType:    "CsvHelper.CsvWriter",
			MethodName:    "WriteField",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CsvHelper CsvWriter.WriteField(field) with a user-controlled value — a field beginning with =, +, -, @, tab or CR becomes a formula when the CSV is opened in a spreadsheet (CSV/formula injection, CWE-1236). Prefix at-risk values with a single quote, or set CsvConfiguration.InjectionOptions = InjectionOptions.Escape.",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.csvhelper.writerecord",
			Category:      taint.SnkCSV,
			Language:      rules.LangCSharp,
			Pattern:       `\.WriteRecord\s*\(`,
			ObjectType:    "CsvHelper.CsvWriter",
			MethodName:    "WriteRecord",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CsvHelper CsvWriter.WriteRecord(record) with a user-controlled record — string members beginning with =, +, -, @, tab or CR become formulas when the CSV is opened in a spreadsheet (CSV/formula injection, CWE-1236). Enable CsvConfiguration.InjectionOptions or sanitize the record's string fields first.",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.csvhelper.writerecords",
			Category:      taint.SnkCSV,
			Language:      rules.LangCSharp,
			Pattern:       `\.WriteRecords\s*\(`,
			ObjectType:    "CsvHelper.CsvWriter",
			MethodName:    "WriteRecords",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CsvHelper CsvWriter.WriteRecords(records) with user-controlled records — string members beginning with =, +, -, @, tab or CR become formulas when the CSV is opened in a spreadsheet (CSV/formula injection, CWE-1236). Enable CsvConfiguration.InjectionOptions = InjectionOptions.Escape, or sanitize the records' string fields first.",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.csvhelper.writerecordsasync",
			Category:      taint.SnkCSV,
			Language:      rules.LangCSharp,
			Pattern:       `\.WriteRecordsAsync\s*\(`,
			ObjectType:    "CsvHelper.CsvWriter",
			MethodName:    "WriteRecordsAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CsvHelper CsvWriter.WriteRecordsAsync(records) with user-controlled records — string members beginning with =, +, -, @, tab or CR become formulas when the CSV is opened in a spreadsheet (CSV/formula injection, CWE-1236). Enable CsvConfiguration.InjectionOptions = InjectionOptions.Escape, or sanitize the records' string fields first.",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "csharp.servicestack.csvserializer.serializetostring",
			Category:      taint.SnkCSV,
			Language:      rules.LangCSharp,
			Pattern:       `CsvSerializer(?:<[^>]+>)?\.SerializeToString\s*\(`,
			ObjectType:    "ServiceStack.Text.CsvSerializer",
			MethodName:    "SerializeToString",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "ServiceStack.Text CsvSerializer.SerializeToString(records) builds a CSV string from user-controlled records — string members beginning with =, +, -, @, tab or CR become formulas when the CSV is opened in a spreadsheet (CSV/formula injection, CWE-1236). Sanitize at-risk string fields (prefix with a single quote) before serializing.",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- File-upload sinks (CWE-434) ---
		// ASP.NET (.NET Framework) HttpPostedFile.SaveAs / .NET Core
		// IFormFile.CopyTo(Async) persist a client-uploaded file. Without
		// extension / MIME validation against an allowlist and a clamped,
		// non-web-served destination, this is unrestricted file upload.
		{
			ID:            "csharp.httppostedfile.saveas",
			Category:      taint.SnkUpload,
			Language:      rules.LangCSharp,
			Pattern:       `\.SaveAs\s*\(`,
			ObjectType:    "System.Web.HttpPostedFile",
			MethodName:    "SaveAs",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HttpPostedFile.SaveAs(filename) persists a Request.Files upload without enforced extension/MIME validation; tainted destination path also enables path traversal (CWE-434 / CWE-22).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.iformfile.copyto",
			Category:      taint.SnkUpload,
			Language:      rules.LangCSharp,
			Pattern:       `\.CopyTo(?:Async)?\s*\(`,
			ObjectType:    "Microsoft.AspNetCore.Http.IFormFile",
			MethodName:    "CopyTo/CopyToAsync",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "IFormFile.CopyTo(Async) writes an uploaded file's bytes to a destination stream — when paired with a tainted-path FileStream the upload is unrestricted (CWE-434).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "csharp.iformfile.opnreadstream",
			Category:      taint.SnkUpload,
			Language:      rules.LangCSharp,
			Pattern:       `\.OpenReadStream\s*\(\s*\)`,
			ObjectType:    "Microsoft.AspNetCore.Http.IFormFile",
			MethodName:    "OpenReadStream",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "IFormFile.OpenReadStream() — returns the client's uploaded byte stream; downstream File.WriteAllBytes / new FileStream(uploadedPath) is unrestricted file upload (CWE-434).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// =================================================================
		// Mined from public MIT-licensed security-model data.
		// Dapper, Microsoft.ApplicationBlocks, .NET stdlib, NHibernate, EF,
		// MongoDB.Driver, Amazon.Lambda, etc.
		// =================================================================

		{ID: "csharp.dapper.sqlmapper.executereaderasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteReaderAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "ExecuteReaderAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.ExecuteReaderAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.executescalarasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteScalarAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "ExecuteScalarAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.ExecuteScalarAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.queryasync", Category: taint.SnkSQLQuery, Pattern: `\.QueryAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.queryfirst", Category: taint.SnkSQLQuery, Pattern: `\.QueryFirst\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryFirst", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryFirst — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.queryfirstasync", Category: taint.SnkSQLQuery, Pattern: `\.QueryFirstAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryFirstAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryFirstAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.queryfirstordefault", Category: taint.SnkSQLQuery, Pattern: `\.QueryFirstOrDefault\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryFirstOrDefault", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryFirstOrDefault — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.queryfirstordefaultasync", Category: taint.SnkSQLQuery, Pattern: `\.QueryFirstOrDefaultAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryFirstOrDefaultAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryFirstOrDefaultAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.querymultiple", Category: taint.SnkSQLQuery, Pattern: `\.QueryMultiple\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryMultiple", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryMultiple — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.querymultipleasync", Category: taint.SnkSQLQuery, Pattern: `\.QueryMultipleAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryMultipleAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QueryMultipleAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.querysingle", Category: taint.SnkSQLQuery, Pattern: `\.QuerySingle\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QuerySingle", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QuerySingle — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.querysingleasync", Category: taint.SnkSQLQuery, Pattern: `\.QuerySingleAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QuerySingleAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QuerySingleAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.querysingleordefault", Category: taint.SnkSQLQuery, Pattern: `\.QuerySingleOrDefault\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QuerySingleOrDefault", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QuerySingleOrDefault — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.dapper.sqlmapper.querysingleordefaultasync", Category: taint.SnkSQLQuery, Pattern: `\.QuerySingleOrDefaultAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QuerySingleOrDefaultAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Dapper.SqlMapper.QuerySingleOrDefaultAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.data.sqlhelper.executedataset", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteDataset\s*\(`, ObjectType: "Microsoft.ApplicationBlocks.Data.SqlHelper", MethodName: "ExecuteDataset", DangerousArgs: []int{2}, Severity: rules.Critical, Description: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteDataset — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.data.sqlhelper.executexmlreader", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteXmlReader\s*\(`, ObjectType: "Microsoft.ApplicationBlocks.Data.SqlHelper", MethodName: "ExecuteXmlReader", DangerousArgs: []int{2}, Severity: rules.Critical, Description: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteXmlReader — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.entityframeworkcore.relationaldatabasefacadeextensions.executesqlrawasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteSqlRawAsync\s*\(`, ObjectType: "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions", MethodName: "ExecuteSqlRawAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRawAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executedatarow", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteDataRow\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteDataRow", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRow — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executedatarowasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteDataRowAsync\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteDataRowAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRowAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executedataset", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteDataset\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteDataset", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDataset — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executedatasetasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteDatasetAsync\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteDatasetAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDatasetAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executenonqueryasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteNonQueryAsync\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteNonQueryAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQueryAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executereaderasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteReaderAsync\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteReaderAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteReaderAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.executescalarasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteScalarAsync\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "ExecuteScalarAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.ExecuteScalarAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.updatedataset", Category: taint.SnkSQLQuery, Pattern: `\.UpdateDataset\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "UpdateDataset", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.UpdateDataset — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.mysqlclient.mysqlhelper.updatedatasetasync", Category: taint.SnkSQLQuery, Pattern: `\.UpdateDatasetAsync\s*\(`, ObjectType: "MySql.Data.MySqlClient.MySqlHelper", MethodName: "UpdateDatasetAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "MySql.Data.MySqlClient.MySqlHelper.UpdateDatasetAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.iuntypedsqlexpression.unsafeand", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeAnd\s*\(`, ObjectType: "ServiceStack.OrmLite.IUntypedSqlExpression", MethodName: "UnsafeAnd", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.IUntypedSqlExpression.UnsafeAnd — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.iuntypedsqlexpression.unsafefrom", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeFrom\s*\(`, ObjectType: "ServiceStack.OrmLite.IUntypedSqlExpression", MethodName: "UnsafeFrom", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.IUntypedSqlExpression.UnsafeFrom — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.iuntypedsqlexpression.unsafeor", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeOr\s*\(`, ObjectType: "ServiceStack.OrmLite.IUntypedSqlExpression", MethodName: "UnsafeOr", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.IUntypedSqlExpression.UnsafeOr — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.iuntypedsqlexpression.unsafeselect", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeSelect\s*\(`, ObjectType: "ServiceStack.OrmLite.IUntypedSqlExpression", MethodName: "UnsafeSelect", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.IUntypedSqlExpression.UnsafeSelect — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.iuntypedsqlexpression.unsafewhere", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeWhere\s*\(`, ObjectType: "ServiceStack.OrmLite.IUntypedSqlExpression", MethodName: "UnsafeWhere", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.IUntypedSqlExpression.UnsafeWhere — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.column", Category: taint.SnkSQLQuery, Pattern: `\.Column\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "Column", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.Column — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.columndistinct", Category: taint.SnkSQLQuery, Pattern: `\.ColumnDistinct\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "ColumnDistinct", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.ColumnDistinct — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.columnlazy", Category: taint.SnkSQLQuery, Pattern: `\.ColumnLazy\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "ColumnLazy", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.ColumnLazy — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.dictionary", Category: taint.SnkSQLQuery, Pattern: `\.Dictionary\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "Dictionary", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.Dictionary — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.exists", Category: taint.SnkSQLQuery, Pattern: `\.Exists\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "Exists", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.Exists — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.keyvaluepairs", Category: taint.SnkSQLQuery, Pattern: `\.KeyValuePairs\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "KeyValuePairs", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.KeyValuePairs — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.lookup", Category: taint.SnkSQLQuery, Pattern: `\.Lookup\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "Lookup", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.Lookup — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.scalar", Category: taint.SnkSQLQuery, Pattern: `\.Scalar\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "Scalar", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.Scalar — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.selectlazy", Category: taint.SnkSQLQuery, Pattern: `\.SelectLazy\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "SelectLazy", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.SelectLazy — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.selectnondefaults", Category: taint.SnkSQLQuery, Pattern: `\.SelectNonDefaults\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "SelectNonDefaults", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.SelectNonDefaults — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.single", Category: taint.SnkSQLQuery, Pattern: `\.Single\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "Single", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.Single — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.sqlcolumn", Category: taint.SnkSQLQuery, Pattern: `\.SqlColumn\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "SqlColumn", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.SqlColumn — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.sqllist", Category: taint.SnkSQLQuery, Pattern: `\.SqlList\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "SqlList", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.SqlList — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapi.sqlscalar", Category: taint.SnkSQLQuery, Pattern: `\.SqlScalar\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApi", MethodName: "SqlScalar", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApi.SqlScalar — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.columnasync", Category: taint.SnkSQLQuery, Pattern: `\.ColumnAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "ColumnAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.ColumnAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.columndistinctasync", Category: taint.SnkSQLQuery, Pattern: `\.ColumnDistinctAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "ColumnDistinctAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.ColumnDistinctAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.dictionaryasync", Category: taint.SnkSQLQuery, Pattern: `\.DictionaryAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "DictionaryAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.DictionaryAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.executenonqueryasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteNonQueryAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "ExecuteNonQueryAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.ExecuteNonQueryAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.existsasync", Category: taint.SnkSQLQuery, Pattern: `\.ExistsAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "ExistsAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.ExistsAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.keyvaluepairsasync", Category: taint.SnkSQLQuery, Pattern: `\.KeyValuePairsAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "KeyValuePairsAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.KeyValuePairsAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.lookupasync", Category: taint.SnkSQLQuery, Pattern: `\.LookupAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "LookupAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.LookupAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.scalarasync", Category: taint.SnkSQLQuery, Pattern: `\.ScalarAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "ScalarAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.ScalarAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.selectasync", Category: taint.SnkSQLQuery, Pattern: `\.SelectAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "SelectAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.SelectAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.selectnondefaultsasync", Category: taint.SnkSQLQuery, Pattern: `\.SelectNonDefaultsAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "SelectNonDefaultsAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.SelectNonDefaultsAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.singleasync", Category: taint.SnkSQLQuery, Pattern: `\.SingleAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "SingleAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.SingleAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.sqlcolumnasync", Category: taint.SnkSQLQuery, Pattern: `\.SqlColumnAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "SqlColumnAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.SqlColumnAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.sqllistasync", Category: taint.SnkSQLQuery, Pattern: `\.SqlListAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "SqlListAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.SqlListAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadapiasync.sqlscalarasync", Category: taint.SnkSQLQuery, Pattern: `\.SqlScalarAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadApiAsync", MethodName: "SqlScalarAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadApiAsync.SqlScalarAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadexpressionsapi.rowcount", Category: taint.SnkSQLQuery, Pattern: `\.RowCount\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadExpressionsApi", MethodName: "RowCount", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadExpressionsApi.RowCount — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitereadexpressionsapiasync.rowcountasync", Category: taint.SnkSQLQuery, Pattern: `\.RowCountAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteReadExpressionsApiAsync", MethodName: "RowCountAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteReadExpressionsApiAsync.RowCountAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitewriteapi.executesql", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteSql\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteWriteApi", MethodName: "ExecuteSql", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteWriteApi.ExecuteSql — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.ormlitewriteapiasync.executesqlasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteSqlAsync\s*\(`, ObjectType: "ServiceStack.OrmLite.OrmLiteWriteApiAsync", MethodName: "ExecuteSqlAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.OrmLiteWriteApiAsync.ExecuteSqlAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafeand", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeAnd\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeAnd", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeAnd — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafefrom", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeFrom\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeFrom", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeFrom — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafegroupby", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeGroupBy\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeGroupBy", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeGroupBy — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafehaving", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeHaving\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeHaving", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeHaving — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafeor", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeOr\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeOr", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeOr — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafeorderby", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeOrderBy\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeOrderBy", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeOrderBy — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafeselect", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeSelect\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeSelect", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeSelect — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.ormlite.sqlexpressiont.unsafewhere", Category: taint.SnkSQLQuery, Pattern: `\.UnsafeWhere\s*\(`, ObjectType: "ServiceStack.OrmLite.SqlExpression<T>", MethodName: "UnsafeWhere", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "ServiceStack.OrmLite.SqlExpression<T>.UnsafeWhere — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.ionewayclient.sendalloneway", Category: taint.SnkFileWrite, Pattern: `\.SendAllOneWay\s*\(`, ObjectType: "ServiceStack.IOneWayClient", MethodName: "SendAllOneWay", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "ServiceStack.IOneWayClient.SendAllOneWay — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.ionewayclient.sendoneway", Category: taint.SnkFileWrite, Pattern: `\.SendOneWay\s*\(`, ObjectType: "ServiceStack.IOneWayClient", MethodName: "SendOneWay", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IOneWayClient.SendOneWay — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclient.patch", Category: taint.SnkFileWrite, Pattern: `\.Patch\s*\(`, ObjectType: "ServiceStack.IRestClient", MethodName: "Patch", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "ServiceStack.IRestClient.Patch — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclient.post", Category: taint.SnkFileWrite, Pattern: `\.Post\s*\(`, ObjectType: "ServiceStack.IRestClient", MethodName: "Post", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "ServiceStack.IRestClient.Post — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclient.put", Category: taint.SnkFileWrite, Pattern: `\.Put\s*\(`, ObjectType: "ServiceStack.IRestClient", MethodName: "Put", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "ServiceStack.IRestClient.Put — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclient.send", Category: taint.SnkFileWrite, Pattern: `\.Send\s*\(`, ObjectType: "ServiceStack.IRestClient", MethodName: "Send", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "ServiceStack.IRestClient.Send — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclientasync.custommethodasync", Category: taint.SnkFileWrite, Pattern: `\.CustomMethodAsync\s*\(`, ObjectType: "ServiceStack.IRestClientAsync", MethodName: "CustomMethodAsync", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "ServiceStack.IRestClientAsync.CustomMethodAsync — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclientsync.custommethod", Category: taint.SnkFileWrite, Pattern: `\.CustomMethod\s*\(`, ObjectType: "ServiceStack.IRestClientSync", MethodName: "CustomMethod", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "ServiceStack.IRestClientSync.CustomMethod — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclientsync.get", Category: taint.SnkFileWrite, Pattern: `\.Get\s*\(`, ObjectType: "ServiceStack.IRestClientSync", MethodName: "Get", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestClientSync.Get — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclientsync.patch", Category: taint.SnkFileWrite, Pattern: `\.Patch\s*\(`, ObjectType: "ServiceStack.IRestClientSync", MethodName: "Patch", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestClientSync.Patch — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclientsync.post", Category: taint.SnkFileWrite, Pattern: `\.Post\s*\(`, ObjectType: "ServiceStack.IRestClientSync", MethodName: "Post", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestClientSync.Post — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestclientsync.put", Category: taint.SnkFileWrite, Pattern: `\.Put\s*\(`, ObjectType: "ServiceStack.IRestClientSync", MethodName: "Put", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestClientSync.Put — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestgateway.get", Category: taint.SnkFileWrite, Pattern: `\.Get\s*\(`, ObjectType: "ServiceStack.IRestGateway", MethodName: "Get", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestGateway.Get — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestgateway.post", Category: taint.SnkFileWrite, Pattern: `\.Post\s*\(`, ObjectType: "ServiceStack.IRestGateway", MethodName: "Post", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestGateway.Post — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestgateway.put", Category: taint.SnkFileWrite, Pattern: `\.Put\s*\(`, ObjectType: "ServiceStack.IRestGateway", MethodName: "Put", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestGateway.Put — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.irestgateway.send", Category: taint.SnkFileWrite, Pattern: `\.Send\s*\(`, ObjectType: "ServiceStack.IRestGateway", MethodName: "Send", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IRestGateway.Send — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegateway.publish", Category: taint.SnkFileWrite, Pattern: `\.Publish\s*\(`, ObjectType: "ServiceStack.IServiceGateway", MethodName: "Publish", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGateway.Publish — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegateway.publishall", Category: taint.SnkFileWrite, Pattern: `\.PublishAll\s*\(`, ObjectType: "ServiceStack.IServiceGateway", MethodName: "PublishAll", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGateway.PublishAll — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegateway.send", Category: taint.SnkFileWrite, Pattern: `\.Send\s*\(`, ObjectType: "ServiceStack.IServiceGateway", MethodName: "Send", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGateway.Send — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegateway.sendall", Category: taint.SnkFileWrite, Pattern: `\.SendAll\s*\(`, ObjectType: "ServiceStack.IServiceGateway", MethodName: "SendAll", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGateway.SendAll — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegatewayasync.publishallasync", Category: taint.SnkFileWrite, Pattern: `\.PublishAllAsync\s*\(`, ObjectType: "ServiceStack.IServiceGatewayAsync", MethodName: "PublishAllAsync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGatewayAsync.PublishAllAsync — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegatewayasync.publishasync", Category: taint.SnkFileWrite, Pattern: `\.PublishAsync\s*\(`, ObjectType: "ServiceStack.IServiceGatewayAsync", MethodName: "PublishAsync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGatewayAsync.PublishAsync — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.iservicegatewayasync.sendallasync", Category: taint.SnkFileWrite, Pattern: `\.SendAllAsync\s*\(`, ObjectType: "ServiceStack.IServiceGatewayAsync", MethodName: "SendAllAsync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.IServiceGatewayAsync.SendAllAsync — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.custommethod", Category: taint.SnkFileWrite, Pattern: `\.CustomMethod\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "CustomMethod", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.CustomMethod — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.custommethodasync", Category: taint.SnkFileWrite, Pattern: `\.CustomMethodAsync\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "CustomMethodAsync", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.CustomMethodAsync — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.downloadbytes", Category: taint.SnkFileWrite, Pattern: `\.DownloadBytes\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "DownloadBytes", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.DownloadBytes — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.downloadbytesasync", Category: taint.SnkFileWrite, Pattern: `\.DownloadBytesAsync\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "DownloadBytesAsync", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.DownloadBytesAsync — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.get", Category: taint.SnkFileWrite, Pattern: `\.Get\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "Get", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.Get — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.head", Category: taint.SnkFileWrite, Pattern: `\.Head\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "Head", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.Head — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.patch", Category: taint.SnkFileWrite, Pattern: `\.Patch\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "Patch", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.Patch — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.post", Category: taint.SnkFileWrite, Pattern: `\.Post\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "Post", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.Post — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.publish", Category: taint.SnkFileWrite, Pattern: `\.Publish\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "Publish", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.Publish — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.servicestack.serviceclientbase.put", Category: taint.SnkFileWrite, Pattern: `\.Put\s*\(`, ObjectType: "ServiceStack.ServiceClientBase", MethodName: "Put", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "ServiceStack.ServiceClientBase.Put — file content store sink", CWEID: "CWE-22", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.entity.database.executesqlcommand", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteSqlCommand\s*\(`, ObjectType: "System.Data.Entity.Database", MethodName: "ExecuteSqlCommand", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "System.Data.Entity.Database.ExecuteSqlCommand — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.entity.database.executesqlcommandasync", Category: taint.SnkSQLQuery, Pattern: `\.ExecuteSqlCommandAsync\s*\(`, ObjectType: "System.Data.Entity.Database", MethodName: "ExecuteSqlCommandAsync", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "System.Data.Entity.Database.ExecuteSqlCommandAsync — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.entity.database.sqlquery", Category: taint.SnkSQLQuery, Pattern: `\.SqlQuery\s*\(`, ObjectType: "System.Data.Entity.Database", MethodName: "SqlQuery", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "System.Data.Entity.Database.SqlQuery — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.entity.dbset.sqlquery", Category: taint.SnkSQLQuery, Pattern: `\.SqlQuery\s*\(`, ObjectType: "System.Data.Entity.DbSet", MethodName: "SqlQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "System.Data.Entity.DbSet.SqlQuery — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.entityclient.entitycommand.entitycommand", Category: taint.SnkSQLQuery, Pattern: `\.EntityCommand\s*\(`, ObjectType: "System.Data.EntityClient.EntityCommand", MethodName: "EntityCommand", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "System.Data.EntityClient.EntityCommand.EntityCommand — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.sqlite.sqlitecommand.sqlitecommand", Category: taint.SnkSQLQuery, Pattern: `\.SQLiteCommand\s*\(`, ObjectType: "System.Data.SQLite.SQLiteCommand", MethodName: "SQLiteCommand", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "System.Data.SQLite.SQLiteCommand.SQLiteCommand — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "csharp.sqlite.sqlitedataadapter.sqlitedataadapter", Category: taint.SnkSQLQuery, Pattern: `\.SQLiteDataAdapter\s*\(`, ObjectType: "System.Data.SQLite.SQLiteDataAdapter", MethodName: "SQLiteDataAdapter", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "System.Data.SQLite.SQLiteDataAdapter.SQLiteDataAdapter — SQL injection sink", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	}
}
