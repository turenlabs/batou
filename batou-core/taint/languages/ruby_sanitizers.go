package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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

		// Nokogiri safe parsing
		{ID: "ruby.nokogiri.nonet", Language: rules.LangRuby, Pattern: `Nokogiri::XML\s*\(.*NONET`, ObjectType: "Nokogiri::XML", MethodName: "XML(NONET)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkURLFetch}, Description: "Nokogiri XML parsing with NONET flag (prevents XXE)"},

		// ActiveStorage sanitize_filename
		{ID: "ruby.activestorage.sanitize_filename", Language: rules.LangRuby, Pattern: `ActiveStorage::Filename\.new\s*\(.*\.sanitized`, ObjectType: "ActiveStorage::Filename", MethodName: "sanitized", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "ActiveStorage filename sanitization"},

		// Rack::Utils.escape_html
		{ID: "ruby.rack.utils.escape_html", Language: rules.LangRuby, Pattern: `Rack::Utils\.escape_html\s*\(`, ObjectType: "Rack::Utils", MethodName: "escape_html", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Rack HTML escaping"},

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

		// Infrastructure / Network Sanitizers
		{ID: "ruby.ipaddr.validate", Language: rules.LangRuby, Pattern: `IPAddr\.new\s*\(|\.include\?\s*\(`, ObjectType: "IPAddr", MethodName: "IPAddr.new/include?", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address parsing and CIDR range validation (SSRF prevention)"},
		{ID: "ruby.uri.parse.host", Language: rules.LangRuby, Pattern: `URI\.parse\s*\(.*\.host`, ObjectType: "URI", MethodName: "URI.parse.host", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL hostname extraction for domain allowlist validation"},

		// LDAP sanitization
		{ID: "ruby.net_ldap.filter.escape", Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.escape\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Net::LDAP escape filter"},

		// XPath sanitization
		{ID: "ruby.nokogiri.noblanks", Language: rules.LangRuby, Pattern: `Nokogiri::XML\s*\(.*NOBLANKS`, ObjectType: "Nokogiri::XML", MethodName: "XML(NOBLANKS)", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "Nokogiri NOBLANKS"},
		{ID: "ruby.rexml.entity_expansion_limit", Language: rules.LangRuby, Pattern: `REXML::Document\.entity_expansion_text_limit`, ObjectType: "REXML::Document", MethodName: "entity_expansion_text_limit", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "REXML safe"},

		// Template sanitization
		{ID: "ruby.liquid.auto_escape", Language: rules.LangRuby, Pattern: `Liquid::Template\.parse\s*\(.*\.render\s*\(`, ObjectType: "Liquid::Template", MethodName: "parse.render", Neutralizes: []taint.SinkCategory{taint.SnkTemplate}, Description: "Liquid safe"},

		// Path sanitization
		{ID: "ruby.pathname.cleanpath", Language: rules.LangRuby, Pattern: `Pathname\.new\s*\(.*\.cleanpath`, ObjectType: "Pathname", MethodName: "cleanpath", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "Pathname cleanpath (collapses .. components)"},
		{ID: "ruby.file.expand_path", Language: rules.LangRuby, Pattern: `File\.expand_path\s*\(`, ObjectType: "File", MethodName: "expand_path", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "File.expand_path (resolves relative paths)"},

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

		// --- Pathname sanitization ---
		{
			ID:          "ruby.pathname.realpath",
			Language:    rules.LangRuby,
			Pattern:     `Pathname\.new\(.*\)\.realpath|\.realpath\b`,
			ObjectType:  "Pathname",
			MethodName:  "realpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Pathname realpath resolution (resolves symlinks and .. components)",
		},

		// --- Rails ActionController parameter filtering ---
		{
			ID:          "ruby.rails.strong_params",
			Language:    rules.LangRuby,
			Pattern:     `\.permit\s*\(`,
			ObjectType:  "ActionController::Parameters",
			MethodName:  "permit",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Rails strong parameters permit (allowlist filtering)",
		},

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
		{
			ID:          "ruby.rails.strip_tags",
			Language:    rules.LangRuby,
			Pattern:     `strip_tags\s*\(|ActionView::Helpers::SanitizeHelper\.strip_tags\s*\(`,
			ObjectType:  "ActionView",
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
			Pattern:     `content_tag\s*\(`,
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
	}
}
