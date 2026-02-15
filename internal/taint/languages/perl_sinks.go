package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (perlCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// Command injection (CWE-78)
		{ID: "perl.system", Category: taint.SnkCommand, Language: rules.LangPerl, Pattern: `\bsystem\s*\(`, ObjectType: "", MethodName: "system", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via system()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.exec", Category: taint.SnkCommand, Language: rules.LangPerl, Pattern: `\bexec\s*\(`, ObjectType: "", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via exec()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.backticks", Category: taint.SnkCommand, Language: rules.LangPerl, Pattern: "`.+`", ObjectType: "", MethodName: "backticks", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via backticks", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.qx", Category: taint.SnkCommand, Language: rules.LangPerl, Pattern: `qx\s*[\({/]`, ObjectType: "", MethodName: "qx", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via qx()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.open.pipe", Category: taint.SnkCommand, Language: rules.LangPerl, Pattern: `open\s*\(\s*\$?\w+\s*,\s*["']\|`, ObjectType: "", MethodName: "open|", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Command execution via open() with pipe", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.ipc.open2", Category: taint.SnkCommand, Language: rules.LangPerl, Pattern: `IPC::Open[23]`, ObjectType: "IPC", MethodName: "Open2/Open3", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Command execution via IPC::Open2/Open3", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// SQL injection (CWE-89)
		{ID: "perl.dbi.do", Category: taint.SnkSQLQuery, Language: rules.LangPerl, Pattern: `\$dbh->do\s*\(`, ObjectType: "DBI", MethodName: "do", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL execution via DBI do()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.dbi.prepare", Category: taint.SnkSQLQuery, Language: rules.LangPerl, Pattern: `\$dbh->prepare\s*\(`, ObjectType: "DBI", MethodName: "prepare", DangerousArgs: []int{0}, Severity: rules.High, Description: "SQL preparation via DBI prepare()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.dbi.selectrow", Category: taint.SnkSQLQuery, Language: rules.LangPerl, Pattern: `\$dbh->selectrow_\w+\s*\(`, ObjectType: "DBI", MethodName: "selectrow_*", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL query via DBI selectrow", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.dbi.selectall", Category: taint.SnkSQLQuery, Language: rules.LangPerl, Pattern: `\$dbh->selectall_\w+\s*\(`, ObjectType: "DBI", MethodName: "selectall_*", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL query via DBI selectall", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Code injection (CWE-94)
		{ID: "perl.eval", Category: taint.SnkEval, Language: rules.LangPerl, Pattern: `\beval\s*\(|\beval\s+"|\beval\s+'|\beval\s+\$`, ObjectType: "", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via eval()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

		// File operations / Path traversal (CWE-22)
		{ID: "perl.open", Category: taint.SnkFileWrite, Language: rules.LangPerl, Pattern: `\bopen\s*\(`, ObjectType: "", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "File open with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "perl.file.slurp.write", Category: taint.SnkFileWrite, Language: rules.LangPerl, Pattern: `write_file\s*\(`, ObjectType: "File::Slurp", MethodName: "write_file", DangerousArgs: []int{0}, Severity: rules.High, Description: "File write via File::Slurp", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "perl.unlink", Category: taint.SnkFileWrite, Language: rules.LangPerl, Pattern: `\bunlink\s*\(`, ObjectType: "", MethodName: "unlink", DangerousArgs: []int{0}, Severity: rules.High, Description: "File deletion with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "perl.rename", Category: taint.SnkFileWrite, Language: rules.LangPerl, Pattern: `\brename\s*\(`, ObjectType: "", MethodName: "rename", DangerousArgs: []int{0}, Severity: rules.High, Description: "File rename with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// XSS / HTML output (CWE-79)
		{ID: "perl.print.cgi", Category: taint.SnkHTMLOutput, Language: rules.LangPerl, Pattern: `print\s+.*\$cgi->param|print\s+.*\$q->param|print\s+.*param\(`, ObjectType: "", MethodName: "print", DangerousArgs: []int{0}, Severity: rules.High, Description: "Printing CGI parameters without encoding (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// Deserialization (CWE-502)
		{ID: "perl.storable.thaw", Category: taint.SnkDeserialize, Language: rules.LangPerl, Pattern: `Storable::thaw\s*\(|\bthaw\s*\(`, ObjectType: "Storable", MethodName: "thaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via Storable::thaw", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "perl.storable.retrieve", Category: taint.SnkDeserialize, Language: rules.LangPerl, Pattern: `Storable::retrieve\s*\(|\bretrieve\s*\(`, ObjectType: "Storable", MethodName: "retrieve", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via Storable::retrieve", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "perl.yaml.load", Category: taint.SnkDeserialize, Language: rules.LangPerl, Pattern: `YAML::Load\s*\(|YAML::Syck::Load\s*\(|Load\s*\(\s*\$`, ObjectType: "YAML", MethodName: "Load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe YAML deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// SSRF / URL fetch (CWE-918)
		{ID: "perl.lwp.get", Category: taint.SnkURLFetch, Language: rules.LangPerl, Pattern: `\$ua->get\s*\(|LWP::UserAgent.*->get\s*\(|LWP::Simple::get\s*\(`, ObjectType: "LWP::UserAgent", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via LWP::UserAgent get()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "perl.http.tiny.get", Category: taint.SnkURLFetch, Language: rules.LangPerl, Pattern: `HTTP::Tiny.*->get\s*\(`, ObjectType: "HTTP::Tiny", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via HTTP::Tiny get()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// Redirect (CWE-601)
		{ID: "perl.cgi.redirect", Category: taint.SnkRedirect, Language: rules.LangPerl, Pattern: `\$cgi->redirect\s*\(|\$q->redirect\s*\(|redirect\s*\(`, ObjectType: "CGI", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTTP redirect with potentially tainted URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// LDAP injection (CWE-90)
		{ID: "perl.net.ldap.search", Category: taint.SnkLDAP, Language: rules.LangPerl, Pattern: `\$ldap->search\s*\(`, ObjectType: "Net::LDAP", MethodName: "search", DangerousArgs: []int{0}, Severity: rules.High, Description: "LDAP search with potentially tainted filter", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// Log injection (CWE-117)
		{ID: "perl.log.warn", Category: taint.SnkLog, Language: rules.LangPerl, Pattern: `\$log->warn\s*\(|\$log->info\s*\(|\$log->error\s*\(|\$log->debug\s*\(`, ObjectType: "Log", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// Weak crypto (CWE-328)
		{ID: "perl.digest.md5", Category: taint.SnkCrypto, Language: rules.LangPerl, Pattern: `Digest::MD5`, ObjectType: "Digest::MD5", MethodName: "MD5", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak MD5 hash algorithm usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "perl.digest.sha1", Category: taint.SnkCrypto, Language: rules.LangPerl, Pattern: `Digest::SHA1|Digest::SHA\b.*\bsha1\b`, ObjectType: "Digest::SHA1", MethodName: "SHA1", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak SHA1 hash algorithm usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Insecure random (CWE-338)
		{ID: "perl.rand", Category: taint.SnkCrypto, Language: rules.LangPerl, Pattern: `\brand\s*\(`, ObjectType: "", MethodName: "rand", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "Non-cryptographic random (use Crypt::URandom instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Template injection (CWE-1336)
		{ID: "perl.tt.process", Category: taint.SnkTemplate, Language: rules.LangPerl, Pattern: `\$tt->process\s*\(|\$template->process\s*\(|Template->new.*process`, ObjectType: "Template::Toolkit", MethodName: "process", DangerousArgs: []int{0}, Severity: rules.High, Description: "Template::Toolkit processing with potentially tainted data", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.mojo.render", Category: taint.SnkTemplate, Language: rules.LangPerl, Pattern: `\$c->render\s*\(|\$self->render\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Mojolicious template rendering with potentially tainted data", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

		// XPath injection (CWE-643)
		{ID: "perl.xml.xpath", Category: taint.SnkXPath, Language: rules.LangPerl, Pattern: `XML::XPath->new.*find\s*\(|->findnodes\s*\(|->find\s*\(.*\$`, ObjectType: "XML::XPath", MethodName: "find/findnodes", DangerousArgs: []int{0}, Severity: rules.High, Description: "XPath query with potentially tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.xml.libxml.xpath", Category: taint.SnkXPath, Language: rules.LangPerl, Pattern: `->findnodes\s*\(|->find\s*\(|XML::LibXML::XPathContext`, ObjectType: "XML::LibXML", MethodName: "findnodes", DangerousArgs: []int{0}, Severity: rules.High, Description: "XML::LibXML XPath query with potentially tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},

		// HTTP header injection (CWE-113)
		{ID: "perl.cgi.header", Category: taint.SnkHeader, Language: rules.LangPerl, Pattern: `\$cgi->header\s*\(|\$q->header\s*\(|print\s+.*"HTTP/`, ObjectType: "CGI", MethodName: "header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP response header with potentially tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "perl.mojo.res.headers", Category: taint.SnkHeader, Language: rules.LangPerl, Pattern: `\$c->res->headers->header\s*\(|\$self->res->headers->header\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "res->headers->header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Mojolicious response header with potentially tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// Additional XSS sinks
		{ID: "perl.mojo.render.text", Category: taint.SnkHTMLOutput, Language: rules.LangPerl, Pattern: `\$c->render\(\s*text\s*=>|\$self->render\(\s*text\s*=>`, ObjectType: "Mojolicious::Controller", MethodName: "render(text =>)", DangerousArgs: []int{0}, Severity: rules.High, Description: "Mojolicious text rendering without encoding (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// Additional logging
		{ID: "perl.mojo.log", Category: taint.SnkLog, Language: rules.LangPerl, Pattern: `\$c->app->log->(?:info|warn|error|debug)\s*\(`, ObjectType: "Mojo::Log", MethodName: "app->log->*", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Mojolicious logger with potentially tainted data", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// --- File operations (CWE-22) ---
		{
			ID:            "perl.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPerl,
			Pattern:       `\brename\s*\(`,
			ObjectType:    "",
			MethodName:    "rename",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File rename with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "perl.symlink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPerl,
			Pattern:       `\bsymlink\s*\(`,
			ObjectType:    "",
			MethodName:    "symlink",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Symlink creation with potentially tainted paths (symlink attack)",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "perl.mkdir",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPerl,
			Pattern:       `\bmkdir\s*\(`,
			ObjectType:    "",
			MethodName:    "mkdir",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Dynamic code (CWE-94) ---
		{
			ID:            "perl.require",
			Category:      taint.SnkEval,
			Language:      rules.LangPerl,
			Pattern:       `\brequire\s+\$|do\s+\$`,
			ObjectType:    "",
			MethodName:    "require/do (variable)",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic module loading with potentially tainted filename",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- ReDoS (CWE-1333) ---
		{
			ID:            "perl.regex.tainted",
			Category:      taint.SnkEval,
			Language:      rules.LangPerl,
			Pattern:       `qr/\$|m/\$`,
			ObjectType:    "",
			MethodName:    "qr// (tainted)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Regex compilation with interpolated tainted variable (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SSRF additional ---
		{
			ID:            "perl.http.tiny.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPerl,
			Pattern:       `HTTP::Tiny.*->get\s*\(|HTTP::Tiny.*->post\s*\(`,
			ObjectType:    "HTTP::Tiny",
			MethodName:    "get/post",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP::Tiny request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
	}
}
