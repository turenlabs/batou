package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

func (perlCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// DBI parameterized queries
		{ID: "perl.dbi.placeholder", Language: rules.LangPerl, Pattern: `\$dbh->do\s*\(\s*["'].*\?.*["']\s*,\s*undef\s*,|->execute\s*\(`, ObjectType: "DBI", MethodName: "placeholder", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "DBI parameterized query with placeholders"},
		{ID: "perl.dbi.quote", Language: rules.LangPerl, Pattern: `\$dbh->quote\s*\(`, ObjectType: "DBI", MethodName: "quote", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "DBI quote() escaping for SQL values"},

		// HTML encoding
		{ID: "perl.html.entities.encode", Language: rules.LangPerl, Pattern: `HTML::Entities::encode_entities\s*\(|encode_entities\s*\(`, ObjectType: "HTML::Entities", MethodName: "encode_entities", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML entity encoding"},
		{ID: "perl.cgi.escapehtml", Language: rules.LangPerl, Pattern: `CGI::escapeHTML\s*\(|escapeHTML\s*\(|\$cgi->escapeHTML\s*\(`, ObjectType: "CGI", MethodName: "escapeHTML", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "CGI HTML escaping"},
		{ID: "perl.html.escape", Language: rules.LangPerl, Pattern: `HTML::Escape::escape_html\s*\(|escape_html\s*\(`, ObjectType: "HTML::Escape", MethodName: "escape_html", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML::Escape HTML escaping"},

		// URL encoding
		{ID: "perl.uri.escape", Language: rules.LangPerl, Pattern: `URI::Escape::uri_escape\s*\(|uri_escape\s*\(`, ObjectType: "URI::Escape", MethodName: "uri_escape", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput}, Description: "URI escape encoding"},

		// Regex quoting (prevents regex injection)
		{ID: "perl.quotemeta", Language: rules.LangPerl, Pattern: `\bquotemeta\s*\(|\\Q.*\\E`, ObjectType: "", MethodName: "quotemeta", Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery}, Description: "Perl regex metacharacter escaping"},

		// Taint checking
		{ID: "perl.taint.check", Language: rules.LangPerl, Pattern: `Scalar::Util::tainted\s*\(|tainted\s*\(`, ObjectType: "Scalar::Util", MethodName: "tainted", Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkFileWrite}, Description: "Perl taint mode validation"},

		// Regex capture (untainting pattern)
		{ID: "perl.untaint.regex", Language: rules.LangPerl, Pattern: `=~\s*m?/\^?\[`, ObjectType: "", MethodName: "regex validation", Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkFileWrite}, Description: "Regex-based input validation (untainting)"},

		// Numeric validation
		{ID: "perl.int.coerce", Language: rules.LangPerl, Pattern: `int\s*\(|\+ 0\b`, ObjectType: "", MethodName: "int()", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer conversion (restricts to numeric values)"},

		// Path sanitization
		{ID: "perl.file.basename", Language: rules.LangPerl, Pattern: `File::Basename::basename\s*\(|basename\s*\(`, ObjectType: "File::Basename", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Filename extraction (strips directory traversal)"},
		{ID: "perl.file.spec.canonpath", Language: rules.LangPerl, Pattern: `File::Spec->canonpath\s*\(`, ObjectType: "File::Spec", MethodName: "canonpath", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Canonical path normalization"},

		// List-form system calls
		{ID: "perl.system.list", Language: rules.LangPerl, Pattern: `system\s*\(\s*["'][^"']+["']\s*,`, ObjectType: "", MethodName: "system (list form)", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "List-form system() bypasses shell interpretation"},

		// Safe YAML
		{ID: "perl.yaml.safeload", Language: rules.LangPerl, Pattern: `YAML::Safe|YAML::XS::SafeLoad|SafeLoader`, ObjectType: "YAML", MethodName: "SafeLoad", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Safe YAML loading"},

		// Crypto sanitizers
		{ID: "perl.crypt.urandom", Language: rules.LangPerl, Pattern: `Crypt::URandom|urandom_ub\s*\(`, ObjectType: "Crypt::URandom", MethodName: "urandom", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random generation"},
		{ID: "perl.crypt.bcrypt", Language: rules.LangPerl, Pattern: `Crypt::Bcrypt|bcrypt\s*\(`, ObjectType: "Crypt::Bcrypt", MethodName: "bcrypt", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Bcrypt password hashing"},
	}
}
