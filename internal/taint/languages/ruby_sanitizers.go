package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
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
		{ID: "ruby.file.basename", Language: rules.LangRuby, Pattern: `File\.basename\s*\(`, ObjectType: "File", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Filename extraction"},

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
		{ID: "ruby.activestorage.sanitize_filename", Language: rules.LangRuby, Pattern: `ActiveStorage::Filename\.new\s*\(.*\.sanitized`, ObjectType: "ActiveStorage::Filename", MethodName: "sanitized", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "ActiveStorage filename sanitization"},

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
		{ID: "ruby.pathname.cleanpath", Language: rules.LangRuby, Pattern: `Pathname\.new\s*\(.*\.cleanpath`, ObjectType: "Pathname", MethodName: "cleanpath", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Pathname cleanpath"},
		{ID: "ruby.file.expand_path", Language: rules.LangRuby, Pattern: `File\.expand_path\s*\(`, ObjectType: "File", MethodName: "expand_path", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "File.expand_path"},

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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
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
	}
}
