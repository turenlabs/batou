package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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
		{ID: "perl.string.shellquote", Language: rules.LangPerl, Pattern: `String::ShellQuote|shell_quote\s*\(`, ObjectType: "", MethodName: "shell_quote", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Shell argument quoting (prevents command injection)"},

		// Log injection sanitizers
		{ID: "perl.log.sanitize.encode", Language: rules.LangPerl, Pattern: `Encode::encode\s*\(\s*["']utf-?8|encode_utf8\s*\(`, ObjectType: "Encode", MethodName: "encode_utf8", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "UTF-8 encoding to sanitize log output (prevents multi-byte injection)"},

		// Safe YAML
		{ID: "perl.yaml.safeload", Language: rules.LangPerl, Pattern: `YAML::Safe|YAML::XS::SafeLoad|SafeLoader`, ObjectType: "YAML", MethodName: "SafeLoad", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Safe YAML loading"},

		// Crypto sanitizers
		{ID: "perl.crypt.urandom", Language: rules.LangPerl, Pattern: `Crypt::URandom|urandom_ub\s*\(`, ObjectType: "Crypt::URandom", MethodName: "urandom", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random generation"},
		{ID: "perl.crypt.bcrypt", Language: rules.LangPerl, Pattern: `Crypt::Bcrypt|bcrypt\s*\(`, ObjectType: "Crypt::Bcrypt", MethodName: "bcrypt", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Bcrypt password hashing"},
		{ID: "perl.digest.sha256", Language: rules.LangPerl, Pattern: `Digest::SHA.*sha256|Digest::SHA256|sha256_hex\s*\(|sha256_base64\s*\(`, ObjectType: "Digest::SHA", MethodName: "sha256", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Strong SHA-256 hash algorithm (use instead of MD5/SHA1)"},
		{ID: "perl.crypt.argon2", Language: rules.LangPerl, Pattern: `Crypt::Argon2|argon2id_pass\s*\(|argon2i_pass\s*\(`, ObjectType: "Crypt::Argon2", MethodName: "argon2_pass", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Argon2 password hashing (strong key derivation)"},

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
			ID:          "perl.quotemeta.eval",
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
			ID:          "perl.taint.check.v2",
			Language:    rules.LangPerl,
			Pattern:     `Scalar::Util::tainted\s*\(|tainted\s*\(`,
			ObjectType:  "Scalar::Util",
			MethodName:  "tainted",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkFileWrite, taint.SnkSQLQuery},
			Description: "Perl taint mode checking (validates data is untainted)",
		},

		// --- SSRF / URL fetch sanitizers (SnkURLFetch) ---
		{
			ID:          "perl.data.validate.uri",
			Language:    rules.LangPerl,
			Pattern:     `Data::Validate::URI|is_https?_uri\s*\(`,
			ObjectType:  "Data::Validate::URI",
			MethodName:  "is_http_uri/is_https_uri",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URL format validation via Data::Validate::URI",
		},
		{
			ID:          "perl.uri.host.check",
			Language:    rules.LangPerl,
			Pattern:     `URI->new\s*\(.*->host\b|URI->new\s*\(.*->scheme\b`,
			ObjectType:  "URI",
			MethodName:  "host/scheme",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI parsing with host/scheme validation (SSRF prevention)",
		},
		{
			ID:          "perl.lwp.protocols.allowed",
			Language:    rules.LangPerl,
			Pattern:     `protocols_allowed\s*\(\s*\[`,
			ObjectType:  "LWP::UserAgent",
			MethodName:  "protocols_allowed",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "LWP::UserAgent protocol restriction (SSRF prevention)",
		},

		// --- LDAP injection sanitizers (SnkLDAP) ---
		{
			ID:          "perl.net.ldap.escape",
			Language:    rules.LangPerl,
			Pattern:     `Net::LDAP::Util::escape_filter_value\s*\(|escape_filter_value\s*\(`,
			ObjectType:  "Net::LDAP::Util",
			MethodName:  "escape_filter_value",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter value escaping (RFC 4515)",
		},
		{
			ID:          "perl.net.ldap.escape.dn",
			Language:    rules.LangPerl,
			Pattern:     `Net::LDAP::Util::escape_dn_value\s*\(|escape_dn_value\s*\(|ldap_explode_dn\s*\(`,
			ObjectType:  "Net::LDAP::Util",
			MethodName:  "escape_dn_value",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP distinguished name value escaping",
		},

		// --- HTTP header injection sanitizers (SnkHeader) ---
		{
			ID:          "perl.header.crlf.strip",
			Language:    rules.LangPerl,
			Pattern:     `s/\[\\r\\n\]//g|s/\[\\n\\r\]//g|=~\s*s/\\r|\\n`,
			ObjectType:  "",
			MethodName:  "CRLF strip regex",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "CRLF stripping to prevent header/log injection",
		},

		// --- Log injection sanitizers (SnkLog) ---
		{
			ID:          "perl.log.sanitize.crlf",
			Language:    rules.LangPerl,
			Pattern:     `s/[\r\n]+/ /g|s/\\n/ /g|s/\\r\\n/ /g`,
			ObjectType:  "",
			MethodName:  "CRLF replacement",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Newline replacement to prevent log/header injection",
		},

		// --- Redirect sanitizers (SnkRedirect) ---
		{
			ID:          "perl.redirect.host.allowlist",
			Language:    rules.LangPerl,
			Pattern:     `allowed_hosts\{.*->host\}|->host\s*eq\s|->host\s*=~`,
			ObjectType:  "",
			MethodName:  "host allowlist check",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Redirect URL host allowlist validation",
		},

		// --- Deserialization sanitizers (SnkDeserialize) ---
		{
			ID:          "perl.sereal.safe",
			Language:    rules.LangPerl,
			Pattern:     `Sereal::Decoder.*refuse_objects|Sereal.*no_bless`,
			ObjectType:  "Sereal::Decoder",
			MethodName:  "refuse_objects/no_bless",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Sereal decoder with safe options (blocks object deserialization)",
		},

		// --- XXE prevention sanitizers (SnkDeserialize for CWE-611) ---
		{
			ID:          "perl.xml.twig.no_xxe",
			Language:    rules.LangPerl,
			Pattern:     `XML::Twig->new\s*\(.*no_xxe\s*=>\s*1`,
			ObjectType:  "XML::Twig",
			MethodName:  "no_xxe => 1",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XML::Twig with no_xxe option (prevents XXE attacks)",
		},
		{
			ID:          "perl.xml.libxml.safe.xxe",
			Language:    rules.LangPerl,
			Pattern:     `expand_entities\s*=>\s*0.*no_network\s*=>\s*1|no_network\s*=>\s*1.*expand_entities\s*=>\s*0`,
			ObjectType:  "XML::LibXML",
			MethodName:  "expand_entities=>0, no_network=>1",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath},
			Description: "XML::LibXML with safe parser options (XXE prevention)",
		},
		{
			ID:          "perl.xml.parser.externent",
			Language:    rules.LangPerl,
			Pattern:     `ExternEnt\s*=>\s*sub\s*\{.*return\s+undef|ExternEnt\s*=>\s*sub\s*\{.*return\s*""`,
			ObjectType:  "XML::Parser",
			MethodName:  "ExternEnt handler",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XML::Parser with custom ExternEnt handler blocking external entities",
		},

		// --- Email header injection sanitizers (SnkHeader for CWE-93) ---
		{
			ID:          "perl.email.address.parse",
			Language:    rules.LangPerl,
			Pattern:     `Email::Address->parse\s*\(|Email::Valid->address\s*\(`,
			ObjectType:  "Email::Address",
			MethodName:  "parse/address",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Email address validation/parsing (prevents injection via malformed addresses)",
		},
		{
			ID:          "perl.email.crlf.strip",
			Language:    rules.LangPerl,
			Pattern:     `s/[\r\n]//g|=~\s*tr/\\r\\n//d|s/\\r\\n//g`,
			ObjectType:  "",
			MethodName:  "CRLF strip",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "CRLF stripping to prevent email/SMTP header injection",
		},

		// --- Trust boundary sanitizers (SnkTrustBoundary for CWE-501) ---
		{
			ID:          "perl.session.validate",
			Language:    rules.LangPerl,
			Pattern:     `\$session->param\s*\(.*if\s+.*=~|validate_session|session_is_valid`,
			ObjectType:  "",
			MethodName:  "session validation",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Session parameter validation before trust boundary crossing",
		},
	}
}
