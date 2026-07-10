package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (rubyCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// HTML escaping
		{ID: "ruby.erb.html_escape", Language: rules.LangRuby, Pattern: `ERB::Util\.html_escape\s*\(`, ObjectType: "ERB::Util", MethodName: "html_escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "ERB HTML escape"},
		{ID: "ruby.rails.h", Language: rules.LangRuby, Pattern: `\bh\s*\(`, ObjectType: "", MethodName: "h", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Rails h() helper (HTML escape)"},
		{ID: "ruby.rails.sanitize", Language: rules.LangRuby, Pattern: `\bsanitize\s*\(`, ObjectType: "", MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Rails sanitize helper"},

		// Command escaping
		{ID: "ruby.shellwords.escape", Language: rules.LangRuby, Pattern: `Shellwords\.escape\s*\(`, ObjectType: "Shellwords", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Shell argument escaping"},
		{ID: "ruby.shellwords.shellescape", Language: rules.LangRuby, Pattern: `Shellwords\.shellescape\s*\(`, ObjectType: "Shellwords", MethodName: "shellescape", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Shell argument escaping (alias)"},

		// Type coercion
		{ID: "ruby.to_i", Language: rules.LangRuby, Pattern: `\.to_i\b`, ObjectType: "", MethodName: "to_i", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer conversion"},
		{ID: "ruby.to_f", Language: rules.LangRuby, Pattern: `\.to_f\b`, ObjectType: "", MethodName: "to_f", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Float conversion"},

		// Path sanitization
		{ID: "ruby.file.basename", Language: rules.LangRuby, Pattern: `File\.basename\s*\(`, ObjectType: "File", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "Filename extraction (strips directory traversal)"},

		// SQL sanitization
		{ID: "ruby.activerecord.sanitize_sql", Language: rules.LangRuby, Pattern: `ActiveRecord::Base\.sanitize_sql\s*\(`, ObjectType: "ActiveRecord::Base", MethodName: "sanitize_sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "ActiveRecord SQL sanitization"},
		{ID: "ruby.activerecord.where.parameterized", Language: rules.LangRuby, Pattern: `\.where\s*\(\s*\w+\s*:\s*`, ObjectType: "ActiveRecord", MethodName: "where", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "ActiveRecord parameterized where clause"},

		// URL encoding
		{ID: "ruby.cgi.escape", Language: rules.LangRuby, Pattern: `CGI\.escape\s*\(`, ObjectType: "CGI", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput}, Description: "CGI escape (URL/HTML encoding)"},

		// Safe YAML
		{ID: "ruby.yaml.safe_load", Language: rules.LangRuby, Pattern: `YAML\.safe_load\s*\(`, ObjectType: "YAML", MethodName: "safe_load", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Safe YAML deserialization"},

		// Sequel parameterized queries
		{ID: "ruby.sequel.where.parameterized", Language: rules.LangRuby, Pattern: `\.where\s*\(\s*\w+\s*:\s*`, ObjectType: "Sequel::Dataset", MethodName: "where", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Sequel parameterized where clause"},
		{ID: "ruby.sequel.placeholder", Language: rules.LangRuby, Pattern: `\.where\s*\(\s*['"].*\?\s*['"]`, ObjectType: "Sequel::Dataset", MethodName: "where(?)", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Sequel placeholder-based where clause"},

		// TinyTds string escaping (FreeTDS / SQL Server)
		{ID: "ruby.tiny_tds.escape", Language: rules.LangRuby, Pattern: `\.escape\s*\(`, ObjectType: "TinyTds::Client", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "TinyTds::Client#escape — escapes a string for safe interpolation into a SQL Server query"},

		// Nokogiri safe parsing
		{ID: "ruby.nokogiri.nonet", Language: rules.LangRuby, Pattern: `Nokogiri::XML\s*\(.*NONET`, ObjectType: "Nokogiri::XML", MethodName: "XML(NONET)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkURLFetch}, Description: "Nokogiri XML parsing with NONET flag (prevents XXE)"},

		// ActiveStorage sanitize_filename
		{ID: "ruby.activestorage.sanitize_filename", Language: rules.LangRuby, Pattern: `ActiveStorage::Filename\.new\s*\(.*\.sanitized`, ObjectType: "ActiveStorage::Filename", MethodName: "sanitized", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "ActiveStorage filename sanitization"},

		// Rack::Utils.escape_html
		{ID: "ruby.rack.utils.escape_html", Language: rules.LangRuby, Pattern: `Rack::Utils\.escape_html\s*\(`, ObjectType: "Rack::Utils", MethodName: "escape_html", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Rack HTML escaping"},

		// escape_utils gem — fast C-extension HTML/JavaScript/URL output encoders (brianmario/escape_utils, used by html-pipeline)
		{ID: "ruby.escape_utils.escape_html", Language: rules.LangRuby, Pattern: `EscapeUtils\.escape_html\s*\(`, ObjectType: "EscapeUtils", MethodName: "escape_html", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "escape_utils gem HTML entity encoding"},
		{ID: "ruby.escape_utils.escape_javascript", Language: rules.LangRuby, Pattern: `EscapeUtils\.escape_javascript\s*\(`, ObjectType: "EscapeUtils", MethodName: "escape_javascript", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "escape_utils gem JavaScript-context string escaping"},
		{ID: "ruby.escape_utils.escape_url", Language: rules.LangRuby, Pattern: `EscapeUtils\.escape_url\s*\(`, ObjectType: "EscapeUtils", MethodName: "escape_url", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput}, Description: "escape_utils gem URL/query percent-encoding (CGI.escape equivalent)"},

		// URI.encode_www_form_component
		{ID: "ruby.uri.encode_www_form_component", Language: rules.LangRuby, Pattern: `URI\.encode_www_form_component\s*\(`, ObjectType: "URI", MethodName: "encode_www_form_component", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch}, Description: "URI component encoding"},

		// Loofah (used by Rails sanitize)
		{ID: "ruby.loofah.scrub", Language: rules.LangRuby, Pattern: `Loofah\.fragment\s*\(.*\.scrub`, ObjectType: "Loofah", MethodName: "scrub", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Loofah HTML scrubbing/sanitization"},

		// Crypto / Auth Sanitizers
		{ID: "ruby.crypto.bcrypt.create", Language: rules.LangRuby, Pattern: `BCrypt::Password\.create\s*\(`, ObjectType: "BCrypt::Password", MethodName: "create", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "BCrypt password hashing (safe password storage)"},
		{ID: "ruby.crypto.bcrypt.compare", Language: rules.LangRuby, Pattern: `BCrypt::Password\.new\s*\(.*==`, ObjectType: "BCrypt::Password", MethodName: "==", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "BCrypt password verification (constant-time comparison)"},
		{ID: "ruby.crypto.securerandom", Language: rules.LangRuby, Pattern: `SecureRandom\.\w+\s*\(`, ObjectType: "SecureRandom", MethodName: "SecureRandom.*", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random generation"},
		{ID: "ruby.crypto.openssl.hmac", Language: rules.LangRuby, Pattern: `OpenSSL::HMAC\.\w+\s*\(`, ObjectType: "OpenSSL::HMAC", MethodName: "HMAC", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "HMAC message authentication code"},
		{ID: "ruby.crypto.secure_compare", Language: rules.LangRuby, Pattern: `ActiveSupport::SecurityUtils\.secure_compare\s*\(|Rack::Utils\.secure_compare\s*\(`, ObjectType: "SecurityUtils", MethodName: "secure_compare", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Constant-time string comparison (prevents timing attacks)"},

		// --- Modern password hashing / KDF sanitizers (CWE-916, CWE-327) ---
		// argon2 gem (https://github.com/technion/ruby-argon2) — winner of the
		// Password Hashing Competition; Argon2id is the recommended algorithm.
		{
			ID:          "ruby.crypto.argon2.create",
			Language:    rules.LangRuby,
			Pattern:     `Argon2::Password\.create\s*\(`,
			ObjectType:  "Argon2::Password",
			MethodName:  "create",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2::Password.create(password) — memory-hard Argon2id password hashing (argon2 gem)",
		},
		{
			ID:          "ruby.crypto.argon2.verify_password",
			Language:    rules.LangRuby,
			Pattern:     `Argon2::Password\.verify_password\s*\(`,
			ObjectType:  "Argon2::Password",
			MethodName:  "verify_password",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2::Password.verify_password(plain, hash) — constant-time Argon2 hash verification (argon2 gem)",
		},
		// scrypt gem (https://github.com/pbhogan/scrypt) — memory-hard KDF.
		{
			ID:          "ruby.crypto.scrypt.create",
			Language:    rules.LangRuby,
			Pattern:     `SCrypt::Password\.create\s*\(`,
			ObjectType:  "SCrypt::Password",
			MethodName:  "create",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SCrypt::Password.create(password) — memory-hard scrypt password hashing (scrypt gem)",
		},
		// OpenSSL::KDF.pbkdf2_hmac — Ruby stdlib (Ruby 2.5+) PBKDF2 KDF.
		{
			ID:          "ruby.crypto.openssl.kdf.pbkdf2_hmac",
			Language:    rules.LangRuby,
			Pattern:     `OpenSSL::KDF\.pbkdf2_hmac\s*\(`,
			ObjectType:  "OpenSSL::KDF",
			MethodName:  "pbkdf2_hmac",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL::KDF.pbkdf2_hmac(password, salt:, iterations:, length:, hash:) — RFC 8018 PBKDF2 (Ruby stdlib 2.5+)",
		},
		// OpenSSL::PKCS5.pbkdf2_hmac — older PBKDF2 API (kept for legacy code).
		{
			ID:          "ruby.crypto.openssl.pkcs5.pbkdf2_hmac",
			Language:    rules.LangRuby,
			Pattern:     `OpenSSL::PKCS5\.pbkdf2_hmac\s*\(`,
			ObjectType:  "OpenSSL::PKCS5",
			MethodName:  "pbkdf2_hmac",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter, keylen, digest) — legacy PBKDF2 API (Ruby stdlib)",
		},
		// rbnacl gem (https://github.com/RubyCrypto/rbnacl) — libsodium binding.
		{
			ID:          "ruby.crypto.rbnacl.password_hash.argon2id",
			Language:    rules.LangRuby,
			Pattern:     `RbNaCl::PasswordHash\.argon2id\s*\(`,
			ObjectType:  "RbNaCl::PasswordHash",
			MethodName:  "argon2id",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "RbNaCl::PasswordHash.argon2id(password, ops, mem) — libsodium Argon2id password hashing (rbnacl gem)",
		},

		// Infrastructure / Network Sanitizers
		{ID: "ruby.ipaddr.validate", Language: rules.LangRuby, Pattern: `IPAddr\.new\s*\(|\.include\?\s*\(`, ObjectType: "IPAddr", MethodName: "IPAddr.new/include?", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address parsing and CIDR range validation (SSRF prevention)"},
		{ID: "ruby.uri.parse.host", Language: rules.LangRuby, Pattern: `URI\.parse\s*\(.*\.host`, ObjectType: "URI", MethodName: "URI.parse.host", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL hostname extraction for domain allowlist validation"},

		// LDAP sanitization
		{ID: "ruby.net_ldap.filter.escape", Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.escape\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Net::LDAP escape filter"},
		{ID: "ruby.net_ldap.dn.escape", Language: rules.LangRuby, Pattern: `Net::LDAP::DN\.escape\s*\(`, ObjectType: "Net::LDAP::DN", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Net::LDAP::DN.escape — escapes RFC 4514 DN component special characters"},

		// XPath sanitization
		{ID: "ruby.nokogiri.noblanks", Language: rules.LangRuby, Pattern: `Nokogiri::XML\s*\(.*NOBLANKS`, ObjectType: "Nokogiri::XML", MethodName: "XML(NOBLANKS)", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "Nokogiri NOBLANKS"},
		{ID: "ruby.rexml.entity_expansion_limit", Language: rules.LangRuby, Pattern: `REXML::Document\.entity_expansion_text_limit`, ObjectType: "REXML::Document", MethodName: "entity_expansion_text_limit", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "REXML safe"},

		// Template sanitization
		{ID: "ruby.liquid.auto_escape", Language: rules.LangRuby, Pattern: `Liquid::Template\.parse\s*\(.*\.render\s*\(`, ObjectType: "Liquid::Template", MethodName: "parse.render", Neutralizes: []taint.SinkCategory{taint.SnkTemplate}, Description: "Liquid safe"},

		// NOTE: Pathname#cleanpath, File.expand_path, and Pathname#realpath
		// are intentionally NOT registered as standalone CWE-22 sanitizers
		// (mirrors the filepath.Clean note in go_sanitizers.go and the
		// os.path.normpath/realpath note in python_sanitizers.go).
		// Canonicalization alone does not reject escapes:
		// Pathname.new("../../etc/passwd").cleanpath is still
		// "../../etc/passwd", and expand_path/realpath resolve "../" to a
		// real path OUTSIDE the safe base. A complete defence is canonicalize
		// + containment — that combo IS recognised below as
		// ruby.file.expand_path_guard (expand_path/cleanpath + start_with?).

		// --- Regex escaping ---
		{
			ID:          "ruby.regexp.escape",
			Language:    rules.LangRuby,
			Pattern:     `Regexp\.escape\s*\(|Regexp\.quote\s*\(`,
			ObjectType:  "Regexp",
			MethodName:  "escape/quote",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex metacharacter escaping (prevents ReDoS and injection)",
		},

		// --- ActiveRecord SQL sanitization ---
		{
			ID:          "ruby.activerecord.sanitize_sql_array",
			Language:    rules.LangRuby,
			Pattern:     `sanitize_sql_array\s*\(|sanitize_sql_for_conditions\s*\(`,
			ObjectType:  "ActiveRecord::Base",
			MethodName:  "sanitize_sql_array",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ActiveRecord SQL array sanitization for parameterized queries",
		},

		// NOTE: Pathname#realpath deliberately absent — canonicalize-only,
		// see the cleanpath/expand_path note above.

		// --- CGI HTML escaping (Ruby stdlib) ---
		{
			ID:          "ruby.cgi.escapehtml",
			Language:    rules.LangRuby,
			Pattern:     `CGI\.escapeHTML\s*\(|CGI\.escape_html\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "escapeHTML",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "CGI HTML entity escaping (Ruby stdlib)",
		},

		// --- Psych safe YAML loading (Ruby stdlib since 2.3) ---
		{
			ID:          "ruby.psych.safe_load",
			Language:    rules.LangRuby,
			Pattern:     `Psych\.safe_load\s*\(`,
			ObjectType:  "Psych",
			MethodName:  "safe_load",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Psych safe YAML deserialization (disables arbitrary object creation)",
		},

		// --- Oj safe mode (JSON gem) ---
		{
			ID:          "ruby.oj.safe_load",
			Language:    rules.LangRuby,
			Pattern:     `Oj\.safe_load\s*\(`,
			ObjectType:  "Oj",
			MethodName:  "safe_load",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Oj safe JSON loading (disables object mode deserialization)",
		},
		{
			ID:          "ruby.oj.strict_load",
			Language:    rules.LangRuby,
			Pattern:     `Oj\.strict_load\s*\(`,
			ObjectType:  "Oj",
			MethodName:  "strict_load",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Oj strict JSON loading (only basic JSON types, no object creation)",
		},

		// --- ActiveRecord connection.quote ---
		{
			ID:          "ruby.activerecord.connection.quote",
			Language:    rules.LangRuby,
			Pattern:     `connection\.quote\s*\(|\.connection\.quote\s*\(`,
			ObjectType:  "ActiveRecord::ConnectionAdapters",
			MethodName:  "quote",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ActiveRecord SQL value quoting",
		},

		// --- Sanitize gem (widely used HTML sanitizer) ---
		{
			ID:          "ruby.sanitize.fragment",
			Language:    rules.LangRuby,
			Pattern:     `Sanitize\.fragment\s*\(|Sanitize\.clean\s*\(`,
			ObjectType:  "Sanitize",
			MethodName:  "fragment/clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Sanitize gem HTML sanitization (whitelist-based)",
		},

		// --- Rails strip_tags helper ---
		// ObjectType "" (was "ActionView"): strip_tags is a bare ActionView helper
		// invoked WITHOUT a receiver (`strip_tags(input)`), so a receiver-typed
		// ObjectType never matched and the sanitizer was dead for both the inline
		// and two-step (`safe = strip_tags(x)`) forms — the HTML-output sink fired
		// through it. Empty ObjectType matches the any-receiver bare call (mirrors
		// the `sanitize`/`h` helpers above). The MethodName-keyed candidate lookup
		// still reaches the fully-qualified `…SanitizeHelper.strip_tags` form.
		{
			ID:          "ruby.rails.strip_tags",
			Language:    rules.LangRuby,
			Pattern:     `strip_tags\s*\(|ActionView::Helpers::SanitizeHelper\.strip_tags\s*\(`,
			ObjectType:  "",
			MethodName:  "strip_tags",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Rails strip_tags helper (removes all HTML tags)",
		},

		// --- ERB URL encoding ---
		{
			ID:          "ruby.erb.url_encode",
			Language:    rules.LangRuby,
			Pattern:     `ERB::Util\.url_encode\s*\(`,
			ObjectType:  "ERB::Util",
			MethodName:  "url_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "ERB URL encoding for safe URL parameter embedding",
		},

		// --- JSON serialization (prevents XSS in JSON contexts) ---
		{
			ID:          "ruby.json.generate",
			Language:    rules.LangRuby,
			Pattern:     `JSON\.generate\s*\(|\.to_json\b`,
			ObjectType:  "JSON",
			MethodName:  "generate/to_json",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "JSON serialization (HTML-safe output encoding)",
		},

		// --- Shellwords.join (shell-safe array joining) ---
		{
			ID:          "ruby.shellwords.join",
			Language:    rules.LangRuby,
			Pattern:     `Shellwords\.join\s*\(`,
			ObjectType:  "Shellwords",
			MethodName:  "join",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Shell-safe argument array joining (escapes each element)",
		},

		// --- Rails content_tag (auto-escapes values) ---
		{
			ID:          "ruby.rails.content_tag",
			Language:    rules.LangRuby,
			Pattern:     `\bcontent_tag\s*\(`,
			ObjectType:  "ActionView",
			MethodName:  "content_tag",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Rails content_tag helper (auto-escapes content)",
		},

		// --- ActiveRecord parameterized .where with placeholder ---
		{
			ID:          "ruby.activerecord.where.placeholder",
			Language:    rules.LangRuby,
			Pattern:     `\.where\s*\(\s*['"].*\?\s*['"]`,
			ObjectType:  "ActiveRecord",
			MethodName:  "where(?)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ActiveRecord placeholder-based where clause (parameterized)",
		},

		// --- Rack::Utils.escape_path ---
		{
			ID:          "ruby.rack.utils.escape_path",
			Language:    rules.LangRuby,
			Pattern:     `Rack::Utils\.escape_path\s*\(`,
			ObjectType:  "Rack::Utils",
			MethodName:  "escape_path",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead, taint.SnkRedirect},
			Description: "Rack path component escaping",
		},

		// --- Addressable::URI (URL validation/parsing gem) ---
		{
			ID:          "ruby.addressable.uri.parse",
			Language:    rules.LangRuby,
			Pattern:     `Addressable::URI\.parse\s*\(.*\.host|Addressable::URI\.parse\s*\(.*\.hostname`,
			ObjectType:  "Addressable::URI",
			MethodName:  "parse.host",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Addressable URI hostname extraction for allowlist validation",
		},

		// --- ActiveRecord LIKE sanitization ---
		{
			ID:          "ruby.activerecord.sanitize_sql_like",
			Language:    rules.LangRuby,
			Pattern:     `sanitize_sql_like\s*\(`,
			ObjectType:  "ActiveRecord::Base",
			MethodName:  "sanitize_sql_like",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ActiveRecord LIKE clause sanitization (escapes %, _, \\)",
		},

		// --- URI.encode_www_form (hash/array to query string) ---
		{
			ID:          "ruby.uri.encode_www_form",
			Language:    rules.LangRuby,
			Pattern:     `URI\.encode_www_form\s*\(`,
			ObjectType:  "URI",
			MethodName:  "encode_www_form",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI query string encoding for safe URL parameter construction",
		},

		// --- Addressable URI normalization (redirect/SSRF prevention) ---
		{
			ID:          "ruby.addressable.uri.normalize",
			Language:    rules.LangRuby,
			Pattern:     `Addressable::URI\.parse\s*\(.*\.host|Addressable::URI\.parse\s*\(.*\.normalized_host`,
			ObjectType:  "Addressable::URI",
			MethodName:  "parse.host/normalized_host",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Addressable URI hostname extraction for domain allowlist validation",
		},

		// --- Rails url_for with only_path (prevents open redirect) ---
		{
			ID:          "ruby.rails.url_for.only_path",
			Language:    rules.LangRuby,
			Pattern:     `url_for\s*\(.*only_path\s*:\s*true`,
			ObjectType:  "ActionController",
			MethodName:  "url_for(only_path: true)",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Rails url_for with only_path: true strips host (prevents open redirect)",
		},

		// (The former second `ruby.rails.strip_tags` entry here — a same-file
		// duplicate ID with an identical Neutralizes list — was folded into the
		// any-receiver entry above when its ObjectType was corrected to "".)

		// --- CRLF stripping (prevents header + log injection) ---
		{
			ID:          "ruby.string.delete.crlf",
			Language:    rules.LangRuby,
			Pattern:     `\.delete\s*\(\s*["']\\[rn]`,
			ObjectType:  "",
			MethodName:  "delete",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "String#delete removing CR/LF characters (prevents header/log injection)",
		},
		{
			ID:          "ruby.string.gsub.crlf",
			Language:    rules.LangRuby,
			Pattern:     `\.gsub\s*\(\s*/\[?\\[rn]`,
			ObjectType:  "",
			MethodName:  "gsub",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Regex gsub replacing CR/LF characters (prevents header/log injection)",
		},
		{
			ID:          "ruby.string.tr.crlf",
			Language:    rules.LangRuby,
			Pattern:     `\.tr\s*\(\s*["']\\[rn]`,
			ObjectType:  "",
			MethodName:  "tr",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "String#tr transliterating CR/LF characters (prevents header/log injection)",
		},

		// --- Email address validation (prevents header injection in email) ---
		{
			ID:          "ruby.mail.address.new",
			Language:    rules.LangRuby,
			Pattern:     `Mail::Address\.new\s*\(`,
			ObjectType:  "Mail::Address",
			MethodName:  "new",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Mail gem address parsing validates RFC 2822 compliance (prevents email header injection)",
		},

		// --- Trust boundary sanitizers (CWE-501) ---
		{
			ID:          "ruby.activesupport.message_verifier",
			Language:    rules.LangRuby,
			Pattern:     `MessageVerifier.*\.verify\s*\(|message_verifier.*\.verify\s*\(`,
			ObjectType:  "ActiveSupport::MessageVerifier",
			MethodName:  "verify",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize},
			Description: "ActiveSupport::MessageVerifier cryptographic signature verification",
		},
		{
			ID:          "ruby.rails.signed_cookies",
			Language:    rules.LangRuby,
			Pattern:     `cookies\.signed\s*\[|cookies\.encrypted\s*\[`,
			ObjectType:  "ActionDispatch::Cookies",
			MethodName:  "signed[]/encrypted[]",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Rails signed/encrypted cookie reader verifies integrity before use",
		},

		// --- Discourse / Rails DB parameterization (from Discourse audit 2026-04-09) ---
		{
			ID:          "ruby.discourse.db_sql_fragment",
			Language:    rules.LangRuby,
			Pattern:     `DB\.sql_fragment\s*\(`,
			ObjectType:  "DB",
			MethodName:  "sql_fragment",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Discourse DB.sql_fragment parameterized SQL builder (bind variables via named/positional params)",
		},
		{
			ID:          "ruby.rails.sanitize_sql",
			Language:    rules.LangRuby,
			Pattern:     `sanitize_sql\s*\(|sanitize_sql_array\s*\(|sanitize_sql_for_conditions\s*\(`,
			ObjectType:  "ActiveRecord",
			MethodName:  "sanitize_sql",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ActiveRecord sanitize_sql family — parameterizes SQL fragments",
		},
		{
			ID:          "ruby.rails.quote",
			Language:    rules.LangRuby,
			Pattern:     `connection\.quote\s*\(|ActiveRecord::Base\.connection\.quote\s*\(`,
			ObjectType:  "ActiveRecord::ConnectionAdapters",
			MethodName:  "quote",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ActiveRecord connection.quote — escapes values for SQL interpolation",
		},

		// --- Dynamic dispatch guards ---
		{
			ID:          "ruby.respond_to_guard",
			Language:    rules.LangRuby,
			Pattern:     `\brespond_to\?\s*\(`,
			ObjectType:  "",
			MethodName:  "respond_to?",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "respond_to? guard before send/public_send — constrains dynamic dispatch to existing methods",
		},

		// --- Path sanitizers ---
		{
			ID:          "ruby.file.basename",
			Language:    rules.LangRuby,
			Pattern:     `File\.basename\s*\(`,
			ObjectType:  "File",
			MethodName:  "basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "File.basename strips directory components (prevents path traversal)",
		},
		{
			ID:          "ruby.file.expand_path_guard",
			Language:    rules.LangRuby,
			Pattern:     `File\.expand_path\s*\(.*\)\.start_with\?\s*\(|Pathname\.new\s*\(.*\)\.cleanpath.*\.start_with\?`,
			ObjectType:  "File",
			MethodName:  "expand_path+start_with?",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Path canonicalization + prefix check (standard path traversal prevention pattern)",
		},
		{
			ID:          "ruby.rails.send_from_directory",
			Language:    rules.LangRuby,
			Pattern:     `send_file\s+Rails\.root\.join\s*\(|send_file\s+File\.join\s*\(\s*[A-Z_]`,
			ObjectType:  "ActionController",
			MethodName:  "send_file with safe base",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead},
			Description: "send_file with Rails.root.join or constant base directory (safe path construction)",
		},

		// --- Log injection ---
		{
			ID:          "ruby.log.crlf_gsub",
			Language:    rules.LangRuby,
			Pattern:     `\.gsub\s*\(\s*/\\[rn]/|\.gsub\s*\(\s*['"]\\[rn]['"]|\.delete\s*\(\s*['"]\r\n['"]`,
			ObjectType:  "",
			MethodName:  "gsub/delete CRLF",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "CRLF stripping before logging (prevents log injection/forging)",
		},
		{
			ID:          "ruby.json_generate",
			Language:    rules.LangRuby,
			Pattern:     `JSON\.generate\s*\(|\.to_json\b`,
			ObjectType:  "JSON",
			MethodName:  "generate/to_json",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "JSON serialization escapes control characters (safe for structured log output)",
		},

		// --- Open redirect ---
		{
			ID:          "ruby.uri.host_allowlist",
			Language:    rules.LangRuby,
			Pattern:     `URI\.parse\s*\([^)]*\)\.host\s*==|URI\s*\([^)]*\)\.host\s+in\s|allowed_redirect_host`,
			ObjectType:  "URI",
			MethodName:  "URI.parse().host check",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "URI host validation before redirect (prevents open redirect)",
		},

		// --- SSRF sanitizers (CWE-918 prevention) ---

		// SsrfFilter gem — wraps HTTP requests with DNS resolution validation,
		// private IP blocking, and redirect-following safety. The response result
		// is sanitized for SSRF (the request was made safely).
		// Gem: github.com/arkadiyt/ssrf_filter (7M+ downloads)
		{
			ID:          "ruby.ssrf_filter.request",
			Language:    rules.LangRuby,
			Pattern:     `SsrfFilter\.(?:get|post|put|patch|delete|head)\s*\(`,
			ObjectType:  "SsrfFilter",
			MethodName:  "get/post/put/patch/delete/head",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "SsrfFilter gem — validates URL against private IP ranges and DNS rebinding before HTTP request",
		},

		// URI scheme extraction — when a developer extracts .scheme from a tainted
		// URL, the result (a protocol string like "http"/"https") is safe for SSRF.
		// Common pattern: scheme = URI.parse(url).scheme; raise unless scheme.in?(%w[http https])
		{
			ID:          "ruby.uri.parse.scheme",
			Language:    rules.LangRuby,
			Pattern:     `URI\.parse\s*\(.*\.scheme`,
			ObjectType:  "URI",
			MethodName:  "scheme",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI scheme extraction for protocol validation (restricts to http/https)",
		},

		// Addressable::URI scheme extraction — same pattern as URI.parse but for
		// the Addressable gem (150M+ downloads), which handles edge-case URIs better.
		{
			ID:          "ruby.addressable.uri.scheme",
			Language:    rules.LangRuby,
			Pattern:     `Addressable::URI\.parse\s*\(.*\.scheme`,
			ObjectType:  "Addressable::URI",
			MethodName:  "scheme",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Addressable URI scheme extraction for protocol allowlist validation",
		},

		// private_address_check gem — resolves hostname and checks if the IP is in
		// a private/internal range (RFC 1918, loopback, link-local).
		// Gem: github.com/jtdowney/private_address_check (used by GitLab)
		{
			ID:          "ruby.private_address_check.resolves",
			Language:    rules.LangRuby,
			Pattern:     `PrivateAddressCheck\.resolves_to_private_address\?\s*\(`,
			ObjectType:  "PrivateAddressCheck",
			MethodName:  "resolves_to_private_address?",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "private_address_check gem — validates hostname doesn't resolve to private/internal IP ranges",
		},

		// URI port extraction — isolates port number from a tainted URL.
		// Used in SSRF prevention to validate that the target port is allowed
		// (e.g., only 80/443, not internal service ports like 6379, 9200).
		{
			ID:          "ruby.uri.parse.port",
			Language:    rules.LangRuby,
			Pattern:     `URI\.parse\s*\(.*\.port`,
			ObjectType:  "URI",
			MethodName:  "port",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URI port extraction for port validation (prevents internal service access on non-standard ports)",
		},

		// --- Command injection: String#shellescape instance method (CWE-78) ---
		{
			ID:          "ruby.string.shellescape",
			Language:    rules.LangRuby,
			Pattern:     `\.shellescape\b`,
			ObjectType:  "",
			MethodName:  "shellescape",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "String#shellescape instance method — escapes shell metacharacters (same as Shellwords.shellescape)",
		},

		// --- Template injection sanitizers: auto-escaping template engines (CWE-1336) ---
		// ObjectType "@argpattern" (was "Haml::Engine"): the sanitizer call is the
		// CHAINED `Haml::Engine.new(tmpl).render(...)`, whose receiver is
		// `Haml::Engine.new(...)` — a receiver-typed ObjectType match against the
		// bare type "Haml::Engine" missed it on a two-step assignment
		// (`out = Haml::Engine.new(...).render(...)`), so `out` stayed HTML-unsafe.
		// "@argpattern" re-validates the call TEXT against the Pattern (which is
		// anchored to the full `Haml::Engine.new(...).render(` chain), matching both
		// the inline and two-step forms precisely.
		{
			ID:          "ruby.haml.engine_render",
			Language:    rules.LangRuby,
			Pattern:     `Haml::Engine\.new\s*\(.*\.render\s*\(`,
			ObjectType:  "@argpattern",
			MethodName:  "new.render",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Haml template engine auto-escapes HTML entities by default in output tags",
		},
		{
			ID:          "ruby.mustache.render",
			Language:    rules.LangRuby,
			Pattern:     `Mustache\.render\s*\(`,
			ObjectType:  "Mustache",
			MethodName:  "render",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Mustache auto-escapes HTML entities in {{}} tags (triple-stache {{{raw}}} for unescaped)",
		},
		// ObjectType "@argpattern" (was "Slim::Template"): same chained-receiver
		// rationale as Haml above — `Slim::Template.new(...).render(...)` only
		// matches when the call TEXT is validated against the chain-anchored Pattern.
		{
			ID:          "ruby.slim.template_render",
			Language:    rules.LangRuby,
			Pattern:     `Slim::Template\.new\s*\(.*\.render\s*\(`,
			ObjectType:  "@argpattern",
			MethodName:  "new.render",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Slim template engine auto-escapes HTML by default (use == for raw output)",
		},

		// --- Log injection: JSON serialization sanitizers (CWE-117) ---
		{
			ID:          "ruby.oj.dump",
			Language:    rules.LangRuby,
			Pattern:     `Oj\.dump\s*\(`,
			ObjectType:  "Oj",
			MethodName:  "dump",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Oj JSON serialization escapes control characters (safe for structured log output)",
		},
		{
			ID:          "ruby.multi_json.dump",
			Language:    rules.LangRuby,
			Pattern:     `MultiJson\.dump\s*\(|MultiJson\.encode\s*\(`,
			ObjectType:  "MultiJson",
			MethodName:  "dump/encode",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "MultiJson serialization escapes control characters (safe for structured log output)",
		},

		// --- Eval sanitizers: dynamic dispatch / class resolution guards (CWE-94, CWE-470) ---
		{
			ID:          "ruby.safe_constantize",
			Language:    rules.LangRuby,
			Pattern:     `\.safe_constantize\b`,
			ObjectType:  "",
			MethodName:  "safe_constantize",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Rails safe_constantize returns nil for unknown constants (prevents arbitrary class instantiation via CWE-470)",
		},
		{
			ID:          "ruby.const_defined",
			Language:    rules.LangRuby,
			Pattern:     `\.const_defined\?\s*\(`,
			ObjectType:  "",
			MethodName:  "const_defined?",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Module.const_defined? validates constant exists before const_get/constantize (CWE-470 guard)",
		},
		{
			ID:          "ruby.method_defined",
			Language:    rules.LangRuby,
			Pattern:     `\.method_defined\?\s*\(|\.private_method_defined\?\s*\(`,
			ObjectType:  "",
			MethodName:  "method_defined?/private_method_defined?",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Module.method_defined? validates method exists before send/public_send (CWE-94 guard)",
		},

		// --- Strict type conversion sanitizers (CWE-78, CWE-89, CWE-94) ---
		{
			ID:          "ruby.integer_strict",
			Language:    rules.LangRuby,
			Pattern:     `\bInteger\s*\(`,
			ObjectType:  "",
			MethodName:  "Integer",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkEval},
			Description: "Kernel#Integer() strict conversion — raises ArgumentError on non-numeric input (stricter than .to_i)",
		},
		{
			ID:          "ruby.float_strict",
			Language:    rules.LangRuby,
			Pattern:     `\bFloat\s*\(`,
			ObjectType:  "",
			MethodName:  "Float",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkEval},
			Description: "Kernel#Float() strict conversion — raises ArgumentError on non-numeric input (stricter than .to_f)",
		},

		// --- JWT signature verification / signing (CWE-345 / CWE-347) ---
		//
		// These calls either (a) validate a JWT's signature against a
		// key/algorithm list (returning verified claims) or (b) produce a
		// server-signed token whose payload is integrity-protected. A
		// tainted token that has passed through one of these calls is no
		// longer attacker-controlled for Crypto / Deserialize / Trust-
		// Boundary purposes. These are the paired sanitizers for the JWT
		// sinks added in ruby_sinks.go.
		{
			ID:          "ruby.jose.jwt.verify",
			Language:    rules.LangRuby,
			Pattern:     `JOSE::JWT\.verify\s*\(`,
			ObjectType:  "JOSE::JWT",
			MethodName:  "verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "jose-ruby JOSE::JWT.verify(key, signed) validates the JWT signature against the supplied key before exposing claims",
		},
		{
			ID:          "ruby.jose.jwt.verify_strict",
			Language:    rules.LangRuby,
			Pattern:     `JOSE::JWT\.verify_strict\s*\(`,
			ObjectType:  "JOSE::JWT",
			MethodName:  "verify_strict",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "jose-ruby JOSE::JWT.verify_strict(key, algorithms, signed) validates signature AND restricts to the allowed algorithms (prevents alg-confusion)",
		},
		{
			ID:          "ruby.jwt.encode",
			Language:    rules.LangRuby,
			Pattern:     `JWT\.encode\s*\(`,
			ObjectType:  "JWT",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "ruby-jwt JWT.encode(payload, key, alg) signs the payload server-side; the emitted token is integrity-protected for downstream verifiers",
		},
		{
			ID:          "ruby.jwt.token.sign",
			Language:    rules.LangRuby,
			Pattern:     `\.sign!\s*\(\s*algorithm\s*:`,
			ObjectType:  "JWT::Token",
			MethodName:  "sign!",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "ruby-jwt JWT::Token#sign!(algorithm:, key:) produces a signed JWT (v3 API); the output token.jwt is integrity-protected",
		},
		{
			ID:          "ruby.jwt.encoded_token.verify_signature",
			Language:    rules.LangRuby,
			Pattern:     `\.verify_signature!\s*\(`,
			ObjectType:  "JWT::EncodedToken",
			MethodName:  "verify_signature!",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "ruby-jwt JWT::EncodedToken#verify_signature!(signature: {...}) validates the signature before claims can be trusted (v3 API)",
		},

		// --- Temporal-parse return-value sanitizers (Date / DateTime / Time stdlib) ---
		// Each of these stdlib class methods accepts a user-controlled string and
		// returns a strongly-typed Date / DateTime / Time value. The returned
		// object's #to_s output is a constrained format (digits, dashes, colons,
		// 'T', 'Z', '+', spaces — no quotes, no shell metacharacters, no angle
		// brackets, no path-traversal sequences, no CRLF), so downstream
		// interpolation into SQL / command / HTML / log / file-path / redirect
		// sinks is safe. SnkURLFetch is intentionally NOT neutralized — a parsed
		// timestamp concatenated onto a URL hostname or path can still drive SSRF
		// against internal scheduling endpoints. Same model as the Kotlin
		// java.time.* parsers (PR #600), Rust chrono/time (PR #688), and JS
		// date-fns/dayjs/luxon/moment (PR #691) sanitizer cycles.
		{
			ID:          "ruby.date.parse",
			Language:    rules.LangRuby,
			Pattern:     `\bDate\.parse\s*\(`,
			ObjectType:  "Date",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Date.parse(str) — heuristic parser returning a Date (raises ArgumentError on unrecognised input)",
		},
		{
			ID:          "ruby.date.iso8601",
			Language:    rules.LangRuby,
			Pattern:     `\bDate\.iso8601\s*\(`,
			ObjectType:  "Date",
			MethodName:  "iso8601",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Date.iso8601(str) — strict ISO-8601 parser returning a Date",
		},
		{
			ID:          "ruby.date.rfc3339",
			Language:    rules.LangRuby,
			Pattern:     `\bDate\.rfc3339\s*\(`,
			ObjectType:  "Date",
			MethodName:  "rfc3339",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Date.rfc3339(str) — strict RFC-3339 parser returning a Date",
		},
		{
			ID:          "ruby.date.strptime",
			Language:    rules.LangRuby,
			Pattern:     `\bDate\.strptime\s*\(`,
			ObjectType:  "Date",
			MethodName:  "strptime",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Date.strptime(str, fmt) — format-bounded parser returning a Date",
		},
		{
			ID:          "ruby.datetime.parse",
			Language:    rules.LangRuby,
			Pattern:     `\bDateTime\.parse\s*\(`,
			ObjectType:  "DateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTime.parse(str) — heuristic parser returning a DateTime",
		},
		{
			ID:          "ruby.datetime.iso8601",
			Language:    rules.LangRuby,
			Pattern:     `\bDateTime\.iso8601\s*\(`,
			ObjectType:  "DateTime",
			MethodName:  "iso8601",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTime.iso8601(str) — strict ISO-8601 parser returning a DateTime",
		},
		{
			ID:          "ruby.datetime.rfc3339",
			Language:    rules.LangRuby,
			Pattern:     `\bDateTime\.rfc3339\s*\(`,
			ObjectType:  "DateTime",
			MethodName:  "rfc3339",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTime.rfc3339(str) — strict RFC-3339 parser returning a DateTime",
		},
		{
			ID:          "ruby.datetime.rfc2822",
			Language:    rules.LangRuby,
			Pattern:     `\bDateTime\.rfc2822\s*\(`,
			ObjectType:  "DateTime",
			MethodName:  "rfc2822",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTime.rfc2822(str) — strict RFC-2822 mail-date parser returning a DateTime",
		},
		{
			ID:          "ruby.datetime.strptime",
			Language:    rules.LangRuby,
			Pattern:     `\bDateTime\.strptime\s*\(`,
			ObjectType:  "DateTime",
			MethodName:  "strptime",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTime.strptime(str, fmt) — format-bounded parser returning a DateTime",
		},
		{
			ID:          "ruby.time.parse",
			Language:    rules.LangRuby,
			Pattern:     `\bTime\.parse\s*\(`,
			ObjectType:  "Time",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Time.parse(str) — heuristic parser returning a Time (require 'time'; also matches Time.zone.parse via receiver-chain heuristic)",
		},
		{
			ID:          "ruby.time.iso8601",
			Language:    rules.LangRuby,
			Pattern:     `\bTime\.iso8601\s*\(`,
			ObjectType:  "Time",
			MethodName:  "iso8601",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Time.iso8601(str) — strict ISO-8601 parser returning a Time (require 'time')",
		},
		{
			ID:          "ruby.time.xmlschema",
			Language:    rules.LangRuby,
			Pattern:     `\bTime\.xmlschema\s*\(`,
			ObjectType:  "Time",
			MethodName:  "xmlschema",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Time.xmlschema(str) — strict ISO-8601 parser returning a Time (alias of Time.iso8601, require 'time')",
		},
		{
			ID:          "ruby.time.rfc2822",
			Language:    rules.LangRuby,
			Pattern:     `\bTime\.rfc2822\s*\(`,
			ObjectType:  "Time",
			MethodName:  "rfc2822",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Time.rfc2822(str) — strict RFC-2822 mail-date parser returning a Time (require 'time')",
		},
		{
			ID:          "ruby.time.httpdate",
			Language:    rules.LangRuby,
			Pattern:     `\bTime\.httpdate\s*\(`,
			ObjectType:  "Time",
			MethodName:  "httpdate",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Time.httpdate(str) — strict RFC-1123 HTTP-date parser returning a Time (require 'time')",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "ruby.bson.objectid.from_string",
			Language:    rules.LangRuby,
			Pattern:     `BSON::ObjectId\.from_string\s*\(|BSON::ObjectId\.legal\?\s*\(`,
			ObjectType:  "BSON::ObjectId",
			MethodName:  "from_string/legal?",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "BSON::ObjectId.from_string / .legal? — validates and converts to a 24-hex-char ObjectId; rejects operator-injection payloads (CWE-943)",
		},
		{
			ID:          "ruby.mongo.to_bson",
			Language:    rules.LangRuby,
			Pattern:     `\.to_bson\s*\(`,
			ObjectType:  "BSON::Document",
			MethodName:  "to_bson",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "Ruby driver .to_bson serialises the receiver to a typed BSON byte sequence (values bound as typed BSON entries, not concatenated)",
		},
		{
			ID:          "ruby.mongo.bson_string",
			Language:    rules.LangRuby,
			Pattern:     `BSON::String\.new\s*\(`,
			ObjectType:  "BSON::String",
			MethodName:  "BSON::String.new",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "BSON::String.new wraps a Ruby string as a typed BSON string value (forces string typing, so a Hash payload cannot smuggle a $where clause)",
		},

		// --- Header injection (CWE-93 CRLF) — strip + typed-container ---
		{
			ID:          "ruby.header.gsub_crlf",
			Language:    rules.LangRuby,
			Pattern:     `\.gsub\s*\(\s*\/[\\r\\n]+\/[a-z]*\s*,|\.tr\s*\(\s*['"][\\r\\n]+['"]`,
			ObjectType:  "String",
			MethodName:  "String#gsub(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Manual CR/LF stripping (gsub(/[\\r\\n]+/, '') / tr('\\r\\n','')) — defends header / log injection (CWE-93)",
		},
		{
			ID:          "ruby.rack.headers_hash",
			Language:    rules.LangRuby,
			Pattern:     `Rack::Headers\.new\s*\(|Rack::Utils::HeaderHash\b`,
			ObjectType:  "Rack::Headers",
			MethodName:  "Rack::Headers/HeaderHash",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Rack::Headers / Rack::Utils::HeaderHash — typed multi-map header container; rejects CR/LF in values per Rack 3 spec",
		},
		{
			ID:          "ruby.actiondispatch.response_headers",
			Language:    rules.LangRuby,
			Pattern:     `response\.headers\.merge\s*\(|ActionDispatch::Http::Headers\b`,
			ObjectType:  "ActionDispatch::Http::Headers",
			MethodName:  "ActionDispatch::Http::Headers",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "ActionDispatch::Http::Headers — Rails typed header container; rejects newline characters in values (since Rails 5.0)",
		},

		// --- Eval sanitizers ---
		{
			ID:          "ruby.json.parse",
			Language:    rules.LangRuby,
			Pattern:     `JSON\.parse\s*\(`,
			ObjectType:  "JSON",
			MethodName:  "JSON.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "JSON.parse — strict JSON parser (no script execution); safe alternative to eval on JSON inputs",
		},
		{
			ID:          "ruby.dentaku.calculator",
			Language:    rules.LangRuby,
			Pattern:     `Dentaku::Calculator\.new\s*\(|Dentaku\(`,
			ObjectType:  "Dentaku::Calculator",
			MethodName:  "Dentaku",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Dentaku Calculator — math-expression-only evaluator (no Ruby builtin access); safe replacement for eval on user-supplied formulas",
		},

		// --- ReDoS sanitizer (CWE-1333) — escape regex metacharacters ---
		// Closes the gap left by the SnkRegexDoS sinks (ruby.regexp.new,
		// ruby.regexp.dynamic_match): once a tainted string is escaped it can
		// only ever match itself literally, so no operator/quantifier the
		// attacker supplies survives and catastrophic backtracking is
		// impossible. Regexp.escape and its alias Regexp.quote both produce a
		// metacharacter-neutralised literal. (The existing ruby.regexp.escape
		// entry only declares SnkEval/SnkSQLQuery — SnkRegexDoS was not
		// covered.)
		{
			ID:          "ruby.regexp.escape.redos",
			Language:    rules.LangRuby,
			Pattern:     `Regexp\.escape\s*\(|Regexp\.quote\s*\(`,
			ObjectType:  "Regexp",
			MethodName:  "escape/quote",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Regexp.escape / Regexp.quote — escapes every regex metacharacter so the tainted input matches only literally (prevents ReDoS via attacker-injected quantifiers)",
		},

		// --- CSV / spreadsheet formula-injection sanitizer (CWE-1236) ---
		// Closes the gap for the SnkCSV sink (ruby.csv.addrow). The canonical
		// fix is to neutralise cells that begin with a formula trigger
		// character (=, +, -, @, and tab/CR) before writing them, e.g.
		//   value.gsub(/^[=+\-@\t\r]/, "'\\0")
		// which prefixes a quote so spreadsheet apps treat the cell as text.
		// Pattern requires the gsub/sub regex to begin with an (optionally
		// anchored) formula-trigger class so an unrelated gsub does not match.
		{
			ID:          "ruby.csv.formula_prefix",
			Language:    rules.LangRuby,
			Pattern:     `\.g?sub\s*\(\s*/\^?\[?[=+@-]`,
			ObjectType:  "String",
			MethodName:  "gsub/sub(formula-trigger)",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "String#gsub/sub stripping or quoting leading formula-trigger characters (=, +, -, @) — neutralises CSV/spreadsheet formula injection before the value is written to a CSV cell (CWE-1236)",
		},

		// --- Unrestricted-upload sanitizer (CWE-434) — content-based MIME sniff ---
		// Closes the gap for the SnkUpload sinks (ruby.carrierwave.store,
		// ruby.shrine.upload). Marcel is the magic-byte MIME detector bundled
		// with ActiveStorage / Shrine: Marcel::MimeType.for(io) inspects the
		// file contents (not the attacker-supplied filename or Content-Type
		// header) so the resulting type can be checked against an allowlist
		// before the upload is persisted. This is the recommended, content-
		// based validation that defeats extension/MIME spoofing.
		{
			ID:          "ruby.marcel.mimetype.for",
			Language:    rules.LangRuby,
			Pattern:     `Marcel::MimeType\.for\s*\(`,
			ObjectType:  "Marcel::MimeType",
			MethodName:  "for",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Marcel::MimeType.for(io) — content/magic-byte MIME detection (ignores spoofable filename and Content-Type) for allowlisting uploads before persistence (CWE-434)",
		},

		// --- Padrino-helpers output escaping (CWE-79) ---
		// padrino-helpers ships escape_html (aliased h / h!) backed by
		// Rack::Utils.escape_html — the canonical HTML-entity encoder used in
		// Padrino views before emitting user data into markup.
		{
			ID:          "ruby.padrino.escape_html",
			Language:    rules.LangRuby,
			Pattern:     `\bescape_html\s*\(`,
			ObjectType:  "",
			MethodName:  "escape_html",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Padrino-helpers escape_html — HTML-entity encodes user data for safe output in views (CWE-79)",
		},
		{
			ID:          "ruby.padrino.h",
			Language:    rules.LangRuby,
			Pattern:     `\bh!?\s*\(`,
			ObjectType:  "",
			MethodName:  "h/h!",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Padrino-helpers h / h! — escape_html alias that HTML-escapes user data before output (CWE-79)",
		},
		{
			ID:          "ruby.padrino.rack.escape_html",
			Language:    rules.LangRuby,
			Pattern:     `Rack::Utils\.escape_html\s*\(`,
			ObjectType:  "Rack::Utils",
			MethodName:  "escape_html",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Rack::Utils.escape_html — HTML-entity encoder underlying Padrino/Sinatra escape helpers (CWE-79)",
		},

		// pg gem (ruby-pg) — libpq-backed SQL escaping. The canonical way to
		// safely interpolate dynamic values/identifiers into a SQL string when
		// PQexec-style parameter binding ($1) cannot be used (e.g. dynamic
		// table/column names). Each returns a libpq-escaped string, so the
		// LHS of `safe = conn.escape_*(user_input)` is no longer SQL-tainted.
		{
			ID:          "ruby.pg.escape_string",
			Language:    rules.LangRuby,
			Pattern:     `\.escape_string\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "escape_string",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PG::Connection#escape_string — libpq PQescapeStringConn; escapes a value for safe inclusion inside an SQL string literal (CWE-89)",
		},
		{
			ID:          "ruby.pg.escape_literal",
			Language:    rules.LangRuby,
			Pattern:     `\.escape_literal\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "escape_literal",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PG::Connection#escape_literal — libpq PQescapeLiteral; escapes and quotes a value as a complete SQL string literal (CWE-89)",
		},
		{
			ID:          "ruby.pg.escape_identifier",
			Language:    rules.LangRuby,
			Pattern:     `\.escape_identifier\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "escape_identifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PG::Connection#escape_identifier — libpq PQescapeIdentifier; escapes and quotes a value as a SQL identifier (dynamic table/column name) (CWE-89)",
		},
		{
			ID:          "ruby.pg.quote_ident",
			Language:    rules.LangRuby,
			Pattern:     `\.quote_ident\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "quote_ident",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PG::Connection#quote_ident — quotes a string as a SQL identifier, doubling embedded quotes (CWE-89)",
		},

		// ─────────────────────────────────────────────────────────────────
		// ECL wave-2 (ecl2/ruby): paired sanitizer for the new SnkDeserialize
		// (JSON.load) sink.
		// ─────────────────────────────────────────────────────────────────

		// JSON.parse is the safe alternative to JSON.load for deserialization:
		// it produces only the primitive JSON types (Hash/Array/String/Number/
		// true/false/nil) and never instantiates application objects, so a value
		// that has passed through it can no longer trigger the create_additions
		// /json_class object-injection vector. Complements the existing
		// ruby.json.parse entry which only neutralised SnkEval.
		{
			ID:          "ruby.json.parse.deserialize",
			Language:    rules.LangRuby,
			Pattern:     `JSON\.parse\s*\(`,
			ObjectType:  "JSON",
			MethodName:  "JSON.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JSON.parse — strict JSON parser that yields only primitive JSON types and never instantiates Ruby objects; safe alternative to JSON.load on untrusted input (CWE-502)",
		},
	}
}
