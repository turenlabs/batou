package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
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

		// Template auto-escaping
		{ID: "perl.tt.autoescape", Language: rules.LangPerl, Pattern: `html_filter|Template.*FILTERS|ENCODING\s*=>\s*1`, ObjectType: "Template::Toolkit", MethodName: "html_filter", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Template::Toolkit HTML filtering/encoding"},

		// Mojolicious input validation
		{ID: "perl.mojo.validation", Language: rules.LangPerl, Pattern: `\$c->validation|\$self->validation|Mojolicious::Validator`, ObjectType: "Mojolicious::Validator", MethodName: "validation", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Mojolicious input validation"},

		// XML safe options
		{ID: "perl.xml.libxml.safe", Language: rules.LangPerl, Pattern: `no_network\s*=>\s*1|expand_entities\s*=>\s*0|load_ext_dtd\s*=>\s*0`, ObjectType: "XML::LibXML", MethodName: "safe parser options", Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkDeserialize}, Description: "XML::LibXML parser with safe options (XXE prevention)"},

		// Dancer2 input validation
		{ID: "perl.dancer2.validation", Language: rules.LangPerl, Pattern: `Dancer2::Plugin::FormValidator|validated_params`, ObjectType: "Dancer2", MethodName: "FormValidator", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Dancer2 form validation plugin"},

		// Catalyst input validation
		{ID: "perl.catalyst.validate", Language: rules.LangPerl, Pattern: `Catalyst::Plugin::FormValidator|\$c->form`, ObjectType: "Catalyst", MethodName: "FormValidator", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Catalyst form validation plugin"},

		// --- Regex escaping ---
		{
			ID:          "perl.quotemeta",
			Language:    rules.LangPerl,
			Pattern:     `quotemeta\s*\(|\\\Q`,
			ObjectType:  "",
			MethodName:  "quotemeta/\\Q",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Perl regex metacharacter escaping (prevents ReDoS and injection)",
		},

		// --- Path resolution ---
		{
			ID:          "perl.cwd.abs_path",
			Language:    rules.LangPerl,
			Pattern:     `Cwd::abs_path\s*\(|Cwd::realpath\s*\(|File::Spec->canonpath\s*\(`,
			ObjectType:  "Cwd",
			MethodName:  "abs_path/realpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Absolute/canonical path resolution (path traversal prevention)",
		},

		// --- Taint mode checking ---
		{
			ID:          "perl.taint.check",
			Language:    rules.LangPerl,
			Pattern:     `Scalar::Util::tainted\s*\(|tainted\s*\(`,
			ObjectType:  "Scalar::Util",
			MethodName:  "tainted",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkFileWrite, taint.SnkSQLQuery},
			Description: "Perl taint mode checking (validates data is untainted)",
		},
	}
}
