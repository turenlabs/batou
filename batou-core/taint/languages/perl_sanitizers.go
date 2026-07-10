package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
		{ID: "perl.uri.escape_utf8", Language: rules.LangPerl, Pattern: `URI::Escape::uri_escape_utf8\s*\(|uri_escape_utf8\s*\(`, ObjectType: "", MethodName: "uri_escape_utf8", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput}, Description: "URI::Escape::uri_escape_utf8 — UTF-8-aware percent-encoding (recommended for non-ASCII input); escapes every byte outside the RFC 3986 unreserved set, neutralizing open-redirect and reflected-XSS in URL contexts"},

		// Regex quoting (prevents regex injection)
		{ID: "perl.quotemeta", Language: rules.LangPerl, Pattern: `\bquotemeta\s*\(|\\Q.*\\E`, ObjectType: "", MethodName: "quotemeta", Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery}, Description: "Perl regex metacharacter escaping"},

		// Taint checking

		// Regex capture (untainting pattern)

		// Numeric validation
		{ID: "perl.int.coerce", Language: rules.LangPerl, Pattern: `\bint\s*\(|\+ 0\b`, ObjectType: "", MethodName: "int()", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer conversion (restricts to numeric values)"},

		// Path sanitization
		{ID: "perl.file.basename", Language: rules.LangPerl, Pattern: `File::Basename::basename\s*\(|\bbasename\s*\(`, ObjectType: "File::Basename", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Filename extraction (strips directory traversal)"},
		{ID: "perl.file.spec.canonpath", Language: rules.LangPerl, Pattern: `File::Spec->canonpath\s*\(`, ObjectType: "File::Spec", MethodName: "canonpath", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Canonical path normalization"},

		// List-form system calls
		{ID: "perl.system.list", Language: rules.LangPerl, Pattern: `system\s*\(\s*["'][^"']+["']\s*,`, ObjectType: "", MethodName: "system (list form)", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "List-form system() bypasses shell interpretation"},
		{ID: "perl.string.shellquote", Language: rules.LangPerl, Pattern: `String::ShellQuote|shell_quote\s*\(`, ObjectType: "", MethodName: "shell_quote", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Shell argument quoting (prevents command injection)"},
		{ID: "perl.string.shellquote_best_effort", Language: rules.LangPerl, Pattern: `String::ShellQuote::shell_quote_best_effort\s*\(|shell_quote_best_effort\s*\(`, ObjectType: "", MethodName: "shell_quote_best_effort", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "String::ShellQuote::shell_quote_best_effort quotes shell arguments without dying on un-quotable input (best-effort variant of shell_quote) — prevents command injection"},

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

		// XML safe options
		{ID: "perl.xml.libxml.safe", Language: rules.LangPerl, Pattern: `no_network\s*=>\s*1|expand_entities\s*=>\s*0|load_ext_dtd\s*=>\s*0`, ObjectType: "XML::LibXML", MethodName: "safe parser options", Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkDeserialize}, Description: "XML::LibXML parser with safe options (XXE prevention)"},

		// Dancer2 input validation

		// Catalyst input validation

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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Absolute/canonical path resolution (path traversal prevention)",
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
		{
			ID:          "perl.net.ldap.canonical_dn",
			Language:    rules.LangPerl,
			Pattern:     `Net::LDAP::Util::canonical_dn\s*\(|canonical_dn\s*\(`,
			ObjectType:  "Net::LDAP::Util",
			MethodName:  "canonical_dn",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP DN canonicalization — normalizes and validates DN structure (RFC 4514)",
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

		// CBOR::XS with tag filtering (blocks object reconstruction)
		{
			ID:          "perl.cbor.safe",
			Language:    rules.LangPerl,
			Pattern:     `CBOR::XS.*->filter\s*\(|CBOR::XS.*allow_tags\s*\(\s*0`,
			ObjectType:  "CBOR::XS",
			MethodName:  "filter/allow_tags(0)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "CBOR::XS with tag filtering or disabled tags (blocks object reconstruction)",
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
		{
			ID:          "perl.params.validate",
			Language:    rules.LangPerl,
			Pattern:     `Params::Validate::validate\s*\(|validate_pos\s*\(|validate_with\s*\(`,
			ObjectType:  "",
			MethodName:  "validate/validate_pos/validate_with",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Params::Validate parameter validation (type and constraint checking)",
		},
		{
			ID:          "perl.data.formvalidator",
			Language:    rules.LangPerl,
			Pattern:     `Data::FormValidator->check\s*\(`,
			ObjectType:  "Data::FormValidator",
			MethodName:  "check",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Data::FormValidator form input validation before trust boundary",
		},
		{
			ID:          "perl.type.params",
			Language:    rules.LangPerl,
			Pattern:     `Type::Params::compile\s*\(|Type::Params::validate\s*\(|Type::Params::compile_named\s*\(`,
			ObjectType:  "Type::Params",
			MethodName:  "compile/validate/compile_named",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Type::Params type-safe parameter validation (Type::Tiny ecosystem)",
		},
		{
			ID:          "perl.cgi.untaint",
			Language:    rules.LangPerl,
			Pattern:     `CGI::Untaint->new\s*\(|->extract\s*\(\s*-as_`,
			ObjectType:  "CGI::Untaint",
			MethodName:  "new/extract",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkSQLQuery, taint.SnkCommand},
			Description: "CGI::Untaint parameter extraction with type-safe untainting",
		},
		{
			ID:          "perl.formvalidator.simple",
			Language:    rules.LangPerl,
			Pattern:     `FormValidator::Simple->check\s*\(`,
			ObjectType:  "FormValidator::Simple",
			MethodName:  "check",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "FormValidator::Simple input validation before trust boundary crossing",
		},
		{
			ID:          "perl.html.strip",
			Language:    rules.LangPerl,
			Pattern:     `HTML::Strip->new\s*\(|HTML::Strip.*->parse\s*\(`,
			ObjectType:  "HTML::Strip",
			MethodName:  "new/parse",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkHTMLOutput},
			Description: "HTML::Strip removes all HTML tags (prevents stored XSS across trust boundaries)",
		},
		{
			ID:          "perl.dancer2.formvalidator",
			Language:    rules.LangPerl,
			Pattern:     `validate_form\s*\(|Dancer2::Plugin::FormValidator`,
			ObjectType:  "Dancer2::Plugin::FormValidator",
			MethodName:  "validate_form",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Dancer2 form validation plugin — validates input before session storage",
		},
		{
			ID:          "perl.html.formhandler",
			Language:    rules.LangPerl,
			Pattern:     `HTML::FormHandler.*->process\s*\(|HTML::FormHandler->new\s*\(`,
			ObjectType:  "HTML::FormHandler",
			MethodName:  "process/new",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "HTML::FormHandler form processing with validation (Catalyst/Moose integration)",
		},

		// --- File read/write path sanitizers (SnkFileRead/SnkFileWrite for CWE-22) ---
		{
			ID:          "perl.file.spec.catfile",
			Language:    rules.LangPerl,
			Pattern:     `File::Spec->catfile\s*\(`,
			ObjectType:  "File::Spec",
			MethodName:  "catfile",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Safe path construction via File::Spec->catfile (joins components without traversal)",
		},
		{
			ID:          "perl.file.spec.no_upwards",
			Language:    rules.LangPerl,
			Pattern:     `File::Spec->no_upwards\s*\(`,
			ObjectType:  "File::Spec",
			MethodName:  "no_upwards",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Removes . and .. from path components (path traversal prevention)",
		},
		{
			ID:          "perl.path.tiny.child",
			Language:    rules.LangPerl,
			Pattern:     `path\s*\([^)]+\)->child\s*\(`,
			ObjectType:  "Path::Tiny",
			MethodName:  "child",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Path::Tiny safe child path resolution (dies on traversal attempts)",
		},

		// --- SQL parameterization sanitizers (SnkSQLQuery for CWE-89) ---
		{
			ID:          "perl.dbic.search",
			Language:    rules.LangPerl,
			Pattern:     `->search\s*\(\s*\{`,
			ObjectType:  "DBIx::Class::ResultSet",
			MethodName:  "search",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "DBIx::Class hash-ref search conditions (auto-parameterized by SQL::Abstract)",
		},
		{
			ID:          "perl.sql.abstract",
			Language:    rules.LangPerl,
			Pattern:     `SQL::Abstract->new|SQL::Abstract::Limit->new`,
			ObjectType:  "SQL::Abstract",
			MethodName:  "new",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQL::Abstract query builder (generates parameterized SQL from Perl data structures)",
		},
		{
			ID:          "perl.mojo.pg.query",
			Language:    rules.LangPerl,
			Pattern:     `->db->query\s*\(\s*["'].*\?`,
			ObjectType:  "Mojo::Pg",
			MethodName:  "db->query",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Mojo::Pg placeholder-based query (auto-parameterized)",
		},
		{
			ID:          "perl.dbi.quote_identifier",
			Language:    rules.LangPerl,
			Pattern:     `->quote_identifier\s*\(`,
			ObjectType:  "DBI",
			MethodName:  "quote_identifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "DBI identifier quoting (safe for table/column names in SQL)",
		},

		// --- SSRF / URL sanitizers (SnkURLFetch for CWE-918) ---
		{
			ID:          "perl.data.validate.ip",
			Language:    rules.LangPerl,
			Pattern:     `Data::Validate::IP|is_(?:ipv[46]|private_ipv4|loopback_ipv4|linklocal_ipv4)\s*\(`,
			ObjectType:  "Data::Validate::IP",
			MethodName:  "is_ipv4/is_private_ipv4",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address validation via Data::Validate::IP (SSRF prevention)",
		},
		{
			ID:          "perl.uri.scheme.check",
			Language:    rules.LangPerl,
			Pattern:     `URI->new\s*\(.*->scheme\b`,
			ObjectType:  "URI",
			MethodName:  "scheme",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI scheme extraction for protocol validation (restricts to http/https)",
		},

		// --- HTML sanitizers (SnkHTMLOutput for CWE-79) ---
		{
			ID:          "perl.html.scrubber",
			Language:    rules.LangPerl,
			Pattern:     `HTML::Scrubber->new.*->scrub\s*\(|HTML::Scrubber.*scrub\s*\(`,
			ObjectType:  "HTML::Scrubber",
			MethodName:  "scrub",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML::Scrubber tag/attribute whitelist sanitization (XSS prevention)",
		},

		// --- Command injection sanitizers (SnkCommand for CWE-78) ---
		{
			ID:          "perl.ipc.run.list",
			Language:    rules.LangPerl,
			Pattern:     `IPC::Run::run\s*\(\s*\[|IPC::Run3::run3\s*\(\s*\[`,
			ObjectType:  "IPC::Run",
			MethodName:  "run/run3",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "IPC::Run/Run3 list-form command execution (bypasses shell interpretation)",
		},
		{
			ID:          "perl.open.list.form",
			Language:    rules.LangPerl,
			Pattern:     `open\s*\(\s*(?:my\s+)?\$\w+\s*,\s*["']-\|["']\s*,`,
			ObjectType:  "",
			MethodName:  "open (3-arg pipe list form)",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Three-argument pipe open with list form (bypasses shell interpretation)",
		},

		// --- Log injection sanitizers (SnkLog for CWE-117) ---
		{
			ID:          "perl.json.encode",
			Language:    rules.LangPerl,
			Pattern:     `JSON::encode_json\s*\(|JSON->new.*->encode\s*\(|encode_json\s*\(`,
			ObjectType:  "",
			MethodName:  "encode_json/encode",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "JSON encoding escapes control characters (safe for structured log/header output)",
		},

		// --- Redirect sanitizers (SnkRedirect for CWE-601) ---
		{
			ID:          "perl.mojo.url.host",
			Language:    rules.LangPerl,
			Pattern:     `Mojo::URL->new\s*\(.*->host|->to_abs.*->host`,
			ObjectType:  "Mojo::URL",
			MethodName:  "host",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Mojo::URL host extraction for domain allowlist validation",
		},

		// --- File path sanitizers (SnkFileRead/SnkFileWrite for CWE-22) ---
		{
			ID:          "perl.file.spec.rel2abs",
			Language:    rules.LangPerl,
			Pattern:     `File::Spec->rel2abs\s*\(`,
			ObjectType:  "File::Spec",
			MethodName:  "rel2abs",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Convert relative path to absolute (path traversal prevention when combined with prefix check)",
		},

		// --- Code eval sanitizers (SnkEval for CWE-94) ---
		{
			ID:          "perl.safe.reval",
			Language:    rules.LangPerl,
			Pattern:     `->reval\s*\(`,
			ObjectType:  "Safe",
			MethodName:  "reval",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Safe module restricted eval compartment (sandboxed code execution)",
		},
		{
			ID:          "perl.safe.compartment",
			Language:    rules.LangPerl,
			Pattern:     `Safe->new.*->(?:deny|permit_only)\s*\(`,
			ObjectType:  "Safe",
			MethodName:  "deny/permit_only",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Safe compartment with restricted opcodes (deny/permit_only limits available operations)",
		},

		// --- Template injection sanitizers (SnkTemplate for CWE-1336) ---
		{
			ID:          "perl.mojo.util.xml_escape",
			Language:    rules.LangPerl,
			Pattern:     `Mojo::Util::xml_escape\s*\(`,
			ObjectType:  "Mojo::Util",
			MethodName:  "xml_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Mojolicious XML/HTML escaping for template output",
		},

		// --- SSRF prevention sanitizers (SnkURLFetch for CWE-918) ---
		{
			ID:          "perl.data.validate.ip",
			Language:    rules.LangPerl,
			Pattern:     `Data::Validate::IP|is_(?:public|private)_ipv[46]\s*\(`,
			ObjectType:  "",
			MethodName:  "is_public_ipv4/is_private_ipv4/is_public_ipv6/is_private_ipv6",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Data::Validate::IP public/private IP classification (SSRF prevention)",
		},

		// --- Deserialization safety sanitizers (SnkDeserialize for CWE-502) ---
		{
			ID:          "perl.json.decode.safe",
			Language:    rules.LangPerl,
			Pattern:     `decode_json\s*\(|JSON::XS.*->decode\s*\(|Cpanel::JSON::XS.*->decode\s*\(`,
			ObjectType:  "",
			MethodName:  "decode_json",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JSON decoding produces only basic data structures (inherently safe format, no object instantiation)",
		},
		{
			ID:          "perl.hmac.verify",
			Language:    rules.LangPerl,
			Pattern:     `Digest::HMAC->new\s*\(|hmac_sha\d+\s*\(|hmac_sha\d+_hex\s*\(`,
			ObjectType:  "",
			MethodName:  "hmac_sha256/hmac_sha256_hex/hmac_sha1/hmac_sha1_hex/hmac_sha512/hmac_sha512_hex",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkCrypto},
			Description: "HMAC digest computation for data integrity verification before deserialization",
		},

		// --- Cryptographic sanitizers (SnkCrypto for CWE-327, CWE-338) ---
		{
			ID:          "perl.bytes.random.secure",
			Language:    rules.LangPerl,
			Pattern:     `Bytes::Random::Secure|random_bytes_hex\s*\(|random_string_from\s*\(`,
			ObjectType:  "",
			MethodName:  "random_bytes_hex/random_string_from",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random byte generation (CSPRNG alternative to rand())",
		},
		{
			ID:          "perl.crypt.pbkdf2",
			Language:    rules.LangPerl,
			Pattern:     `Crypt::PBKDF2->new\s*\(|Crypt::PBKDF2.*->generate\s*\(|Crypt::PBKDF2.*->validate\s*\(`,
			ObjectType:  "Crypt::PBKDF2",
			MethodName:  "generate/validate",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation function (secure password hashing)",
		},
		{
			ID:          "perl.crypt.scryptkdf",
			Language:    rules.LangPerl,
			Pattern:     `Crypt::ScryptKDF|scrypt_hash\s*\(|scrypt_hash_verify\s*\(`,
			ObjectType:  "",
			MethodName:  "scrypt_hash/scrypt_hash_verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "scrypt key derivation function (memory-hard password hashing)",
		},

		// --- Log injection sanitizers (SnkLog for CWE-117) ---
		{
			ID:          "perl.log.json.encode",
			Language:    rules.LangPerl,
			Pattern:     `encode_json\s*\(`,
			ObjectType:  "",
			MethodName:  "encode_json",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "JSON encoding escapes control characters including CR/LF (prevents log and header injection)",
		},

		// --- HTTP header injection sanitizers (SnkHeader for CWE-113) ---
		{
			ID:          "perl.http.headers.new",
			Language:    rules.LangPerl,
			Pattern:     `HTTP::Headers->new\s*\(`,
			ObjectType:  "HTTP::Headers",
			MethodName:  "new",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "HTTP::Headers object construction (validates and normalizes header values)",
		},
		{
			ID:          "perl.cgi.cookie.new",
			Language:    rules.LangPerl,
			Pattern:     `CGI::Cookie->new\s*\(`,
			ObjectType:  "CGI::Cookie",
			MethodName:  "new",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "CGI::Cookie safe cookie construction (proper value escaping and formatting)",
		},
		{
			ID:          "perl.plack.response.header",
			Language:    rules.LangPerl,
			Pattern:     `Plack::Response.*->header\s*\(|Plack::Response->new\s*\(`,
			ObjectType:  "Plack::Response",
			MethodName:  "header",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Plack::Response header method (safe header value setting via PSGI API)",
		},

		// --- XSLT trust boundary (SnkXPath for CWE-91) ---
		// XML::LibXSLT::Security registers callbacks that veto FILE_READ /
		// FILE_WRITE / READ_NETWORK / WRITE_NETWORK / CREATE_DIR before
		// xsltApplyStylesheet runs. Presence of security_callbacks() with
		// an XML::LibXSLT::Security instance indicates the application has
		// tightened the XSLT trust boundary, so untrusted stylesheets can
		// no longer reach the filesystem, network, or shell.
		{
			ID:          "perl.xml.libxslt.security_callbacks",
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->security_callbacks\s*\(`,
			ObjectType:  "XML::LibXSLT",
			MethodName:  "security_callbacks",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XML::LibXSLT security callbacks deny stylesheet file/network/process access",
		},

		// --- Crypt::OpenSSL::Random CSPRNG (CWE-338) ---
		// random_bytes/random_pseudo_bytes wrap OpenSSL's RAND_bytes API,
		// returning cryptographically-secure random bytes seeded from the
		// system entropy pool. Use as alternative to Perl's rand() when a
		// caller chooses the byte length and it must remain unpredictable.
		// ObjectType is empty because Perl callers invoke these as fully
		// qualified function calls (`Crypt::OpenSSL::Random::random_bytes($n)`)
		// with no `->` receiver — the matcher requires ObjectType="" for
		// function-form calls.
		{
			ID:          "perl.crypt.openssl.random_bytes",
			Language:    rules.LangPerl,
			Pattern:     `Crypt::OpenSSL::Random::random_bytes\s*\(|Crypt::OpenSSL::Random::random_pseudo_bytes\s*\(`,
			ObjectType:  "",
			MethodName:  "random_bytes/random_pseudo_bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL CSPRNG random byte generation (cryptographically secure alternative to rand())",
		},

		// --- IDN homograph normalization (CWE-601, CWE-918) ---
		// domain_to_ascii() converts internationalized domain names to
		// punycode, neutralizing homograph attacks (e.g. "exаmple.com" with a
		// Cyrillic 'а') that bypass naive host allowlists for redirects/SSRF.
		// ObjectType is empty for function-call form (no `->` receiver).
		{
			ID:          "perl.net.idn.encode.domain_to_ascii",
			Language:    rules.LangPerl,
			Pattern:     `Net::IDN::Encode::domain_to_ascii\s*\(|\bdomain_to_ascii\s*\(`,
			ObjectType:  "",
			MethodName:  "domain_to_ascii",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "IDN punycode conversion (prevents homograph-based phishing/SSRF host bypass)",
		},

		// --- URI::Encode percent-encoding (CWE-79, CWE-601) ---
		// Distinct CPAN module from URI::Escape. Provides uri_encode() with
		// configurable reserved-character handling for URL components.
		// ObjectType is empty so the function-call form
		// `URI::Encode::uri_encode($val)` matches.
		{
			ID:          "perl.uri.encode.uri_encode",
			Language:    rules.LangPerl,
			Pattern:     `URI::Encode::uri_encode\s*\(|\buri_encode\s*\(`,
			ObjectType:  "",
			MethodName:  "uri_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "URI::Encode percent-encoding for URL components (CPAN module distinct from URI::Escape)",
		},

		// --- HTML::Restrict tag/attribute whitelist (CWE-79) ---
		// Modern alternative to HTML::Scrubber. Default rules strip every tag
		// not on its allowlist; process() returns the cleaned HTML string.
		{
			ID:          "perl.html.restrict.process",
			Language:    rules.LangPerl,
			Pattern:     `HTML::Restrict->new\b|->process\s*\(`,
			ObjectType:  "HTML::Restrict",
			MethodName:  "process",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML::Restrict tag/attribute whitelist sanitization (XSS prevention)",
		},

		// --- HTML::Defang content defanger (CWE-79) ---
		// Neutralizes script/style/event-handler attributes and unsafe URLs.
		// defang() returns the cleaned HTML; widely used in webmail and
		// comment-rendering pipelines (Zimbra, Roundcube ports).
		{
			ID:          "perl.html.defang.defang",
			Language:    rules.LangPerl,
			Pattern:     `HTML::Defang->new\b|->defang\s*\(`,
			ObjectType:  "HTML::Defang",
			MethodName:  "defang",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML::Defang neutralizes script/style/event handlers and javascript: URLs (XSS prevention)",
		},

		// --- NoSQL: MongoDB.pm BSON / OID construction ---
		{
			ID:          "perl.mongodb.bson_oid_new",
			Language:    rules.LangPerl,
			Pattern:     `BSON::OID->new\b`,
			ObjectType:  "BSON::OID",
			MethodName:  "new",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.pm BSON::OID->new validates the hex string and returns a typed OID (rejects malformed input, cannot smuggle MongoDB operators)",
		},
		{
			ID:          "perl.mongodb.bson_doc_new",
			Language:    rules.LangPerl,
			Pattern:     `BSON::Doc->new\b`,
			ObjectType:  "BSON::Doc",
			MethodName:  "new",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.pm BSON::Doc->new constructs an ordered BSON document with typed key/value pairs (values bound as data, not interpolated)",
		},
		{
			ID:          "perl.mongodb.bson_string",
			Language:    rules.LangPerl,
			Pattern:     `BSON::String->new\b|bson_string\s*\(`,
			ObjectType:  "BSON::String",
			MethodName:  "BSON::String",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.pm BSON::String wraps a Perl scalar as a BSON string value (forces string typing, so a hash/operator reference cannot smuggle a $where clause)",
		},

		// --- ReDoS sanitizer (SnkRegexDoS for CWE-1333) ---
		// quotemeta() / \Q...\E escape every regex metacharacter, so an
		// otherwise-tainted value interpolated into qr//, m//, or s/// can no
		// longer introduce nested quantifiers or alternations that cause
		// catastrophic backtracking — it is matched literally. Neutralizes the
		// perl.regexdos.qr_interp / perl.regexdos.match_interp sinks.
		{
			ID:          "perl.regexdos.quotemeta",
			Language:    rules.LangPerl,
			Pattern:     `\bquotemeta\s*\(|\\Q`,
			ObjectType:  "",
			MethodName:  "quotemeta/\\Q",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "quotemeta() / \\Q...\\E escapes regex metacharacters so a tainted value is matched literally (prevents ReDoS via attacker-supplied quantifiers/alternation)",
		},

		// --- CSV formula-injection sanitizer (SnkCSV for CWE-1236) ---
		// The canonical defense is to prefix any cell that begins with a
		// formula trigger (=, +, -, @, tab, CR) with a single quote so the
		// spreadsheet treats it as text. The substitution idiom
		// `s/^[=+...]/'.../` (with or without a capture group) is the reliable
		// signal; a plain `s/foo/bar/` or `s/^\s+//` does not match.
		{
			ID:          "perl.csv.formula_prefix",
			Language:    rules.LangPerl,
			Pattern:     `=~\s*s/\^\(?\[[=+@]`,
			ObjectType:  "",
			MethodName:  "formula-char prefix substitution",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Leading formula-character escaping (s/^[=+@-]/'.../) prepends a quote to cells starting with =,+,-,@ so spreadsheets treat them as text (CSV/formula-injection prevention, CWE-1236)",
		},

		// --- File-upload content-type sanitizer (SnkUpload for CWE-434) ---
		// Validating the *content* (magic bytes) rather than trusting the
		// client-supplied filename/Content-Type is the correct upload defense.
		// File::Type, File::MimeInfo(::Magic), and File::LibMagic all sniff the
		// actual bytes; their presence on the upload path indicates the
		// application gates the file by detected type before persisting it.
		{
			ID:          "perl.upload.content_type_detect",
			Language:    rules.LangPerl,
			Pattern:     `File::Type\b|File::MimeInfo\b|File::LibMagic\b`,
			ObjectType:  "",
			MethodName:  "File::Type/File::MimeInfo/File::LibMagic",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Magic-byte content-type detection (File::Type / File::MimeInfo::Magic / File::LibMagic) validates the real file type instead of trusting the client filename/Content-Type (unrestricted-upload prevention, CWE-434)",
		},

		// --- JWT algorithm pinning sanitizer (SnkCrypto for CWE-347) ---
		// Passing an explicit `accepted_alg => [...]` allowlist to Crypt::JWT
		// decode_jwt(), or selecting a keyed algorithm (HS*/RS*/ES*/PS*) on a
		// Mojo::JWT object, forces signature verification under a server-chosen
		// algorithm and rejects "none"/algorithm-confusion forgeries.
		{
			ID:          "perl.jwt.accepted_alg",
			Language:    rules.LangPerl,
			Pattern:     `\baccepted_alg\s*=>|->algorithm\s*\(\s*['"](?:HS|RS|ES|PS)\d`,
			ObjectType:  "",
			MethodName:  "accepted_alg/algorithm(HS*|RS*|ES*|PS*)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "JWT algorithm pinning — Crypt::JWT `accepted_alg => [...]` allowlist or a keyed Mojo::JWT algorithm (HS256/RS256/ES256/PS256) verifies the signature under a server-chosen algorithm and rejects alg:none / algorithm-confusion forgeries (CWE-347)",
		},

		// --- CGI::Application HTML escaping sanitizer ---
		// CGI::Application apps escape user data for HTML output through the
		// underlying CGI/CGI::Simple query object that $self->query exposes:
		// `$self->query->escapeHTML($val)` is the framework-idiomatic XSS
		// neutralizer when emitting attacker data into a run-mode's HTML body
		// or an HTML::Template parameter. (Plain CGI::escapeHTML / escapeHTML
		// is already covered by perl.cgi.escapehtml; this entry adds the
		// chained `$self->query->escapeHTML(...)` form that the CGI::App
		// run-mode object uses.)
		{
			ID:          "perl.cgiapp.query.escapehtml",
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->escapeHTML\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeHTML",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "CGI::Application $self->query->escapeHTML() — HTML-entity escaping of request data before it reaches an HTML body / HTML::Template parameter (XSS prevention, CWE-79)",
		},

		// --- Mojo::Util output encoders (Mojolicious) — CWE-116 ---
		// Companion to the existing perl.mojo.util.xml_escape entry. All three
		// are exported functions that return a sanitized copy of their first
		// argument, so the tsflow sanitizer model (return-value, arg[0]) applies.
		{
			ID:          "perl.mojo.util.url_escape",
			Language:    rules.LangPerl,
			Pattern:     `Mojo::Util::url_escape\s*\(|\burl_escape\s*\(`,
			ObjectType:  "",
			MethodName:  "url_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHeader, taint.SnkHTMLOutput},
			Description: "Mojolicious Mojo::Util::url_escape percent-encodes every byte outside the RFC 3986 unreserved set (A-Za-z0-9-._~) — CR/LF become %0D%0A, ':' '/' and HTML metacharacters become %XX, neutralizing open-redirect, header (CRLF) and reflected-XSS injection in URL/header contexts",
		},
		{
			ID:          "perl.mojo.util.term_escape",
			Language:    rules.LangPerl,
			Pattern:     `Mojo::Util::term_escape\s*\(|\bterm_escape\s*\(`,
			ObjectType:  "",
			MethodName:  "term_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Mojolicious Mojo::Util::term_escape escapes POSIX terminal control characters (ANSI/escape sequences), preventing terminal-escape log injection (CWE-117) when tainted data is written to a log that is later viewed in a terminal",
		},
		{
			ID:          "perl.mojo.util.slugify",
			Language:    rules.LangPerl,
			Pattern:     `Mojo::Util::slugify\s*\(|\bslugify\s*\(`,
			ObjectType:  "",
			MethodName:  "slugify",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkFileRead, taint.SnkFileWrite, taint.SnkHTMLOutput},
			Description: "Mojolicious Mojo::Util::slugify reduces input to a lowercase [a-z0-9-] ASCII slug, stripping all non-word characters, path separators, quotes and shell metacharacters — a strict allowlist transform that neutralizes command, SQL, path-traversal and XSS injection",
		},
	}
}
