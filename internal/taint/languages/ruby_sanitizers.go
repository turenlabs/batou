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
		}
}
