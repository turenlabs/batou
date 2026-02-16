package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (phpCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// HTML encoding
		{ID: "php.htmlspecialchars", Language: rules.LangPHP, Pattern: `\bhtmlspecialchars\s*\(`, MethodName: "htmlspecialchars", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML special characters encoding"},
		{ID: "php.htmlentities", Language: rules.LangPHP, Pattern: `\bhtmlentities\s*\(`, MethodName: "htmlentities", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML entities encoding"},
		{ID: "php.strip_tags", Language: rules.LangPHP, Pattern: `\bstrip_tags\s*\(`, MethodName: "strip_tags", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML tag stripping"},

		// Command escaping
		{ID: "php.escapeshellarg", Language: rules.LangPHP, Pattern: `\bescapeshellarg\s*\(`, MethodName: "escapeshellarg", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Shell argument escaping"},
		{ID: "php.escapeshellcmd", Language: rules.LangPHP, Pattern: `\bescapeshellcmd\s*\(`, MethodName: "escapeshellcmd", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Shell command escaping"},

		// Type coercion
		{ID: "php.intval", Language: rules.LangPHP, Pattern: `\bintval\s*\(`, MethodName: "intval", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer conversion"},
		{ID: "php.int.cast", Language: rules.LangPHP, Pattern: `\(int\)`, MethodName: "(int)", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer type cast"},

		// Path sanitization
		{ID: "php.basename", Language: rules.LangPHP, Pattern: `\bbasename\s*\(`, MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Basename extraction"},
	
		// SQL escaping
		{ID: "php.mysqli_real_escape_string", Language: rules.LangPHP, Pattern: `\bmysqli_real_escape_string\s*\(`, MethodName: "mysqli_real_escape_string", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL string escaping"},
		{ID: "php.pdo.quote", Language: rules.LangPHP, Pattern: `->quote\s*\(`, ObjectType: "PDO", MethodName: "quote", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "PDO string quoting"},
		{ID: "php.prepared.statement", Language: rules.LangPHP, Pattern: `->prepare\s*\(`, ObjectType: "PDO", MethodName: "prepare", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Prepared statement (parameterized query)"},

		// URL encoding
		{ID: "php.urlencode", Language: rules.LangPHP, Pattern: `\burlencode\s*\(`, MethodName: "urlencode", Neutralizes: []taint.SinkCategory{taint.SnkRedirect}, Description: "URL encoding"},

		// WordPress sanitizers
		{ID: "php.wordpress.wp_kses", Language: rules.LangPHP, Pattern: `\bwp_kses\s*\(`, MethodName: "wp_kses", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress HTML filtering via wp_kses()"},
		{ID: "php.wordpress.wp_kses_post", Language: rules.LangPHP, Pattern: `\bwp_kses_post\s*\(`, MethodName: "wp_kses_post", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress post HTML filtering via wp_kses_post()"},
		{ID: "php.wordpress.esc_html", Language: rules.LangPHP, Pattern: `\besc_html\s*\(`, MethodName: "esc_html", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress HTML escaping via esc_html()"},
		{ID: "php.wordpress.esc_attr", Language: rules.LangPHP, Pattern: `\besc_attr\s*\(`, MethodName: "esc_attr", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress attribute escaping via esc_attr()"},
		{ID: "php.wordpress.esc_url", Language: rules.LangPHP, Pattern: `\besc_url\s*\(`, MethodName: "esc_url", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch}, Description: "WordPress URL escaping via esc_url()"},
		{ID: "php.wordpress.esc_sql", Language: rules.LangPHP, Pattern: `\besc_sql\s*\(`, MethodName: "esc_sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "WordPress SQL escaping via esc_sql()"},
		{ID: "php.wordpress.wpdb.prepare", Language: rules.LangPHP, Pattern: `\$wpdb->prepare\s*\(`, ObjectType: "wpdb", MethodName: "prepare", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "WordPress prepared statement via wpdb->prepare()"},
		{ID: "php.wordpress.sanitize_text_field", Language: rules.LangPHP, Pattern: `\bsanitize_text_field\s*\(`, MethodName: "sanitize_text_field", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery}, Description: "WordPress text field sanitization"},
		{ID: "php.wordpress.absint", Language: rules.LangPHP, Pattern: `\babsint\s*\(`, MethodName: "absint", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "WordPress absolute integer cast via absint()"},

		// Laravel sanitizers
		{ID: "php.laravel.e", Language: rules.LangPHP, Pattern: `\be\s*\(`, MethodName: "e", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Laravel e() HTML entity encoding helper"},
		{ID: "php.laravel.blade.escaped", Language: rules.LangPHP, Pattern: `\{\{\s*.*\s*\}\}`, MethodName: "{{ }}", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Laravel Blade escaped output {{ }}"},

		// XXE prevention
		{ID: "php.libxml_disable_entity_loader", Language: rules.LangPHP, Pattern: `\blibxml_disable_entity_loader\s*\(\s*true\s*\)`, MethodName: "libxml_disable_entity_loader", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Disable XML external entity loading"},

		// PDO prepared statements (MySQLi)
		{ID: "php.mysqli.prepare", Language: rules.LangPHP, Pattern: `->prepare\s*\(`, ObjectType: "mysqli", MethodName: "prepare", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQLi prepared statement (parameterized query)"},

		// Filter functions
		{ID: "php.filter_input", Language: rules.LangPHP, Pattern: `\bfilter_input\s*\(`, MethodName: "filter_input", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkCommand}, Description: "Input filtering via filter_input()"},
		{ID: "php.filter_var", Language: rules.LangPHP, Pattern: `\bfilter_var\s*\(`, MethodName: "filter_var", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkCommand}, Description: "Variable filtering via filter_var()"},

		// Crypto / Auth Sanitizers
		{ID: "php.crypto.password_hash", Language: rules.LangPHP, Pattern: `\bpassword_hash\s*\(`, MethodName: "password_hash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "PHP password_hash (bcrypt/argon2 safe password storage)"},
		{ID: "php.crypto.password_verify", Language: rules.LangPHP, Pattern: `\bpassword_verify\s*\(`, MethodName: "password_verify", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "PHP password_verify (constant-time password verification)"},
		{ID: "php.crypto.hash_equals", Language: rules.LangPHP, Pattern: `\bhash_equals\s*\(`, MethodName: "hash_equals", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Constant-time string comparison (prevents timing attacks)"},
		{ID: "php.crypto.random_bytes", Language: rules.LangPHP, Pattern: `\brandom_bytes\s*\(|\brandom_int\s*\(`, MethodName: "random_bytes/random_int", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random generation"},
		{ID: "php.laravel.csrf_middleware", Language: rules.LangPHP, Pattern: `VerifyCsrfToken|csrf_field\s*\(|@csrf`, MethodName: "VerifyCsrfToken", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Laravel CSRF protection middleware/token"},

		// Infrastructure / Network Sanitizers
		{ID: "php.filter_var.validate_url", Language: rules.LangPHP, Pattern: `filter_var\s*\(.*FILTER_VALIDATE_URL`, MethodName: "filter_var(FILTER_VALIDATE_URL)", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL validation via filter_var FILTER_VALIDATE_URL"},
		{ID: "php.filter_var.validate_ip", Language: rules.LangPHP, Pattern: `filter_var\s*\(.*FILTER_VALIDATE_IP`, MethodName: "filter_var(FILTER_VALIDATE_IP)", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address validation via filter_var FILTER_VALIDATE_IP (SSRF prevention)"},

		// --- Path resolution ---
		{
			ID:          "php.realpath",
			Language:    rules.LangPHP,
			Pattern:     `\brealpath\s*\(`,
			ObjectType:  "",
			MethodName:  "realpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Resolve symlinks and return canonical path (path traversal prevention)",
		},

		// --- Type checking ---
		{
			ID:          "php.ctype",
			Language:    rules.LangPHP,
			Pattern:     `ctype_alpha\s*\(|ctype_alnum\s*\(|ctype_digit\s*\(`,
			ObjectType:  "",
			MethodName:  "ctype_*",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Character type checking functions (restrict to safe character sets)",
		},

		// --- Regex escaping ---
		{
			ID:          "php.preg_quote",
			Language:    rules.LangPHP,
			Pattern:     `preg_quote\s*\(`,
			ObjectType:  "",
			MethodName:  "preg_quote",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex metacharacter escaping (prevents ReDoS and injection in patterns)",
		},

		// --- Laravel sanitization ---
		{
			ID:          "php.laravel.validator",
			Language:    rules.LangPHP,
			Pattern:     `Validator::make\s*\(|\$request->validate\s*\(`,
			ObjectType:  "Illuminate\\Validation\\Validator",
			MethodName:  "Validator::make/validate",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "Laravel validation for input sanitization",
		},

		// --- filter_var FILTER_SANITIZE_* ---
		{
			ID:          "php.filter_var.sanitize_string",
			Language:    rules.LangPHP,
			Pattern:     `filter_var\s*\(.*FILTER_SANITIZE_`,
			ObjectType:  "",
			MethodName:  "filter_var(FILTER_SANITIZE_*)",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Variable sanitization via filter_var with FILTER_SANITIZE_* flag",
		},

		// --- addslashes ---
		{
			ID:          "php.addslashes",
			Language:    rules.LangPHP,
			Pattern:     `\baddslashes\s*\(`,
			ObjectType:  "",
			MethodName:  "addslashes",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Backslash escaping for quotes (use prepared statements instead)",
		},

		// --- PDO::prepare ---
		{
			ID:          "php.pdo.prepare",
			Language:    rules.LangPHP,
			Pattern:     `->prepare\s*\(`,
			ObjectType:  "PDO",
			MethodName:  "prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PDO prepared statement (parameterized query)",
		},

		// --- floatval ---
		{
			ID:          "php.floatval",
			Language:    rules.LangPHP,
			Pattern:     `\bfloatval\s*\(|\(float\)`,
			ObjectType:  "",
			MethodName:  "floatval/(float)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Float conversion (restricts to numeric values)",
		},
		}
}
