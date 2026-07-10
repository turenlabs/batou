package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// phpNumericNeutralizes is the set of injection sink categories that an
// integer/float coercion (intval, (int), absint, floatval, …) makes safe. A
// numeric value cannot carry SQL/shell/HTML/path/header/etc. injection
// payloads in ANY string context, so the coercion neutralizes every
// string-injection sink — not just the few that were historically listed.
// (Used cross-statement: `$id = intval($_GET['id']); echo $id;` must be clean.)
var phpNumericNeutralizes = []taint.SinkCategory{
	taint.SnkSQLQuery, taint.SnkCommand, taint.SnkXPath, taint.SnkEval,
	taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkFileRead,
	taint.SnkFileWrite, taint.SnkLDAP, taint.SnkHeader, taint.SnkNoSQL,
	taint.SnkTemplate, taint.SnkDeserialize, taint.SnkUpload, taint.SnkCSV, taint.SnkLog,
}

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
		{ID: "php.intval", Language: rules.LangPHP, Pattern: `\bintval\s*\(`, MethodName: "intval", Neutralizes: phpNumericNeutralizes, Description: "Integer conversion"},
		{ID: "php.int.cast", Language: rules.LangPHP, Pattern: `\(int\)`, MethodName: "(int)", Neutralizes: phpNumericNeutralizes, Description: "Integer type cast"},

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
		{ID: "php.wordpress.esc_url", Language: rules.LangPHP, Pattern: `\besc_url\s*\(`, MethodName: "esc_url", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHTMLOutput}, Description: "WordPress URL escaping via esc_url() — strips/encodes dangerous chars, safe for HTML attribute output too"},
		{ID: "php.wordpress.esc_sql", Language: rules.LangPHP, Pattern: `\besc_sql\s*\(`, MethodName: "esc_sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "WordPress SQL escaping via esc_sql()"},
		{ID: "php.wordpress.wpdb.prepare", Language: rules.LangPHP, Pattern: `\$wpdb->prepare\s*\(`, ObjectType: "wpdb", MethodName: "prepare", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "WordPress prepared statement via wpdb->prepare()"},
		{ID: "php.wordpress.sanitize_text_field", Language: rules.LangPHP, Pattern: `\bsanitize_text_field\s*\(`, MethodName: "sanitize_text_field", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery}, Description: "WordPress text field sanitization"},
		{ID: "php.wordpress.absint", Language: rules.LangPHP, Pattern: `\babsint\s*\(`, MethodName: "absint", Neutralizes: phpNumericNeutralizes, Description: "WordPress absolute integer cast via absint()"},
		{ID: "php.wordpress.esc_js", Language: rules.LangPHP, Pattern: `\besc_js\s*\(`, MethodName: "esc_js", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress esc_js() — escapes text for inline JavaScript string literals"},
		{ID: "php.wordpress.wp_json_encode", Language: rules.LangPHP, Pattern: `\bwp_json_encode\s*\(`, MethodName: "wp_json_encode", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress wp_json_encode() — JSON-encodes (escapes <, >, &, quotes), safe to echo into an HTML <script> context"},
		{ID: "php.wordpress.esc_textarea", Language: rules.LangPHP, Pattern: `\besc_textarea\s*\(`, MethodName: "esc_textarea", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress esc_textarea() — HTML-encodes text for safe use inside <textarea>"},
		{ID: "php.wordpress.sanitize_email", Language: rules.LangPHP, Pattern: `\bsanitize_email\s*\(`, MethodName: "sanitize_email", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader}, Description: "WordPress sanitize_email() — strips chars that are not valid in an email address (also blocks CRLF for header injection)"},
		{ID: "php.wordpress.sanitize_title", Language: rules.LangPHP, Pattern: `\bsanitize_title\s*\(`, MethodName: "sanitize_title", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "WordPress sanitize_title() — strips tags and non-URL-safe characters (used for slugs)"},
		{ID: "php.wordpress.sanitize_user", Language: rules.LangPHP, Pattern: `\bsanitize_user\s*\(`, MethodName: "sanitize_user", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery}, Description: "WordPress sanitize_user() — strips tags, octets, and unsafe chars from a username"},
		{ID: "php.wordpress.sanitize_key", Language: rules.LangPHP, Pattern: `\bsanitize_key\s*\(`, MethodName: "sanitize_key", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery, taint.SnkHeader}, Description: "WordPress sanitize_key() — lowercases and restricts to [a-z0-9_-] (safe for SQL identifiers, option keys, etc.)"},
		{ID: "php.wordpress.tag_escape", Language: rules.LangPHP, Pattern: `\btag_escape\s*\(`, MethodName: "tag_escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "WordPress tag_escape() — escapes HTML/SQL table and tag identifiers"},
		{ID: "php.wordpress.wpdb.esc_like", Language: rules.LangPHP, Pattern: `\$wpdb->esc_like\s*\(`, ObjectType: "wpdb", MethodName: "esc_like", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "WordPress wpdb->esc_like() — escapes %_ wildcards for safe use inside LIKE clauses (combine with wpdb->prepare)"},

		// Laravel sanitizers
		{ID: "php.laravel.e", Language: rules.LangPHP, Pattern: `(?:^|[^\w$>])e\s*\(`, MethodName: "e", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Laravel e() HTML entity encoding helper"},
		{ID: "php.laravel.blade.escaped", Language: rules.LangPHP, Pattern: `\{\{\s*.*\s*\}\}`, MethodName: "{{ }}", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Laravel Blade escaped output {{ }}"},

		// XXE prevention
		{ID: "php.libxml_disable_entity_loader", Language: rules.LangPHP, Pattern: `\blibxml_disable_entity_loader\s*\(\s*true\s*\)`, MethodName: "libxml_disable_entity_loader", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Disable XML external entity loading"},

		// PDO prepared statements (MySQLi)
		{ID: "php.mysqli.prepare", Language: rules.LangPHP, Pattern: `->prepare\s*\(`, ObjectType: "mysqli", MethodName: "prepare", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQLi prepared statement (parameterized query)"},

		// Filter functions — generic filter_var/filter_input cannot escape SQL,
		// HTML, or shell metacharacters without a specific flag. Without flag
		// context, we only claim TrustBoundary (developer intent to validate).
		// Flag-aware entries below extend the claim for specific flags —
		// these only apply in the regex engine (tsflow matches by method name,
		// not Pattern, so flag-aware claims are best-effort in regex only).
		{ID: "php.filter_input", Language: rules.LangPHP, Pattern: `\bfilter_input\s*\(`, MethodName: "filter_input", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "filter_input (generic — TrustBoundary only; does not defend SQL/Command/HTML without a SANITIZE flag)"},
		{ID: "php.filter_var", Language: rules.LangPHP, Pattern: `\bfilter_var\s*\(`, MethodName: "filter_var", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "filter_var (generic — TrustBoundary only; does not defend SQL/Command/HTML without a SANITIZE flag)"},
		// Flag-aware extensions (regex engine only).
		{ID: "php.filter_input.sanitize", Language: rules.LangPHP, Pattern: `\bfilter_input\s*\([^)]*FILTER_SANITIZE_`, MethodName: "filter_input_sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "filter_input with FILTER_SANITIZE_* flag (HTML escape)"},
		{ID: "php.filter_input.validate_int", Language: rules.LangPHP, Pattern: `\bfilter_input\s*\([^)]*FILTER_VALIDATE_(INT|FLOAT|BOOLEAN)`, MethodName: "filter_input_validate_int", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "filter_input numeric validation (restricts to digits/float)"},
		{ID: "php.filter_var.sanitize", Language: rules.LangPHP, Pattern: `\bfilter_var\s*\([^)]*FILTER_SANITIZE_`, MethodName: "filter_var_sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "filter_var with FILTER_SANITIZE_* flag (HTML escape)"},
		{ID: "php.filter_var.validate_int", Language: rules.LangPHP, Pattern: `\bfilter_var\s*\([^)]*FILTER_VALIDATE_(INT|FLOAT|BOOLEAN)`, MethodName: "filter_var_validate_int", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "filter_var numeric validation (restricts to digits/float)"},

		// Crypto / Auth Sanitizers
		{ID: "php.crypto.password_hash", Language: rules.LangPHP, Pattern: `\bpassword_hash\s*\(`, MethodName: "password_hash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "PHP password_hash (bcrypt/argon2 safe password storage)"},
		{ID: "php.crypto.password_verify", Language: rules.LangPHP, Pattern: `\bpassword_verify\s*\(`, MethodName: "password_verify", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "PHP password_verify (constant-time password verification)"},
		{ID: "php.crypto.hash_equals", Language: rules.LangPHP, Pattern: `\bhash_equals\s*\(`, MethodName: "hash_equals", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Constant-time string comparison (prevents timing attacks)"},
		{ID: "php.crypto.random_bytes", Language: rules.LangPHP, Pattern: `\brandom_bytes\s*\(|\brandom_int\s*\(`, MethodName: "random_bytes/random_int", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random generation"},
		{ID: "php.laravel.csrf_middleware", Language: rules.LangPHP, Pattern: `VerifyCsrfToken|csrf_field\s*\(|@csrf`, MethodName: "VerifyCsrfToken", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Laravel CSRF protection middleware/token"},

		// Infrastructure / Network Sanitizers
		{ID: "php.filter_var.validate_url", Language: rules.LangPHP, Pattern: `filter_var\s*\(.*FILTER_VALIDATE_URL`, MethodName: "filter_var(FILTER_VALIDATE_URL)", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL validation via filter_var FILTER_VALIDATE_URL"},
		{ID: "php.filter_var.validate_ip", Language: rules.LangPHP, Pattern: `filter_var\s*\(.*FILTER_VALIDATE_IP`, MethodName: "filter_var(FILTER_VALIDATE_IP)", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address validation via filter_var FILTER_VALIDATE_IP (SSRF prevention)"},

		// NOTE: realpath(), SplFileInfo::getRealPath(), and WordPress's
		// wp_normalize_path() are intentionally NOT registered as standalone
		// CWE-22 sanitizers (mirrors the filepath.Clean note in
		// go_sanitizers.go and the os.path.normpath/realpath note in
		// python_sanitizers.go). Canonicalization alone does not reject
		// escapes: realpath("../../etc/passwd") resolves to "/etc/passwd" —
		// a real path OUTSIDE the safe base — and wp_normalize_path() only
		// normalizes separators, leaving "../" intact. A complete defence is
		// canonicalize + containment (e.g. strpos(realpath($p), $base) === 0,
		// the jail pattern recognised by the scanner's PHP FP filter); the
		// canonicalize step by itself must not kill the taint flow.

		// --- Regex escaping ---
		{
			ID:          "php.preg_quote",
			Language:    rules.LangPHP,
			Pattern:     `preg_quote\s*\(`,
			ObjectType:  "",
			MethodName:  "preg_quote",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery, taint.SnkRegexDoS},
			Description: "Regex metacharacter escaping (prevents ReDoS and injection in patterns)",
		},

		// --- Laravel sanitization ---
		{
			ID:          "php.laravel.validator",
			Language:    rules.LangPHP,
			Pattern:     `Validator::make\s*\(|\$request->validate\s*\(`,
			ObjectType:  "Illuminate\\Validation\\Validator",
			MethodName:  "Validator::make/validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Laravel validation for input sanitization",
		},

		// --- filter_var FILTER_SANITIZE_* ---
		{
			ID:          "php.filter_var.sanitize_string",
			Language:    rules.LangPHP,
			Pattern:     `filter_var\s*\(.*FILTER_SANITIZE_`,
			ObjectType:  "",
			MethodName:  "filter_var(FILTER_SANITIZE_*)",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Variable sanitization via filter_var with FILTER_SANITIZE_* flag",
		},

		// --- addslashes ---
		{
			ID:          "php.addslashes",
			Language:    rules.LangPHP,
			Pattern:     `\baddslashes\s*\(`,
			ObjectType:  "",
			MethodName:  "addslashes",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
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
			Neutralizes: phpNumericNeutralizes,
			Description: "Float conversion (restricts to numeric values)",
		},

		// --- Symfony / Twig sanitizers ---
		{
			ID:          "php.twig.autoescape",
			Language:    rules.LangPHP,
			Pattern:     `\{\{.*\}\}|->render\s*\(.*\.html\.twig`,
			ObjectType:  "Twig",
			MethodName:  "{{ }} auto-escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Twig auto-escaping in templates (enabled by default)",
		},
		{
			ID:          "php.twig.escape.filter",
			Language:    rules.LangPHP,
			Pattern:     `\|\s*e\b|\|\s*escape\b`,
			ObjectType:  "Twig",
			MethodName:  "|e / |escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Twig explicit escape filter",
		},
		{
			ID:          "php.symfony.htmlspecialchars",
			Language:    rules.LangPHP,
			Pattern:     `\bhtmlspecialchars\s*\(.*ENT_QUOTES`,
			ObjectType:  "Symfony",
			MethodName:  "htmlspecialchars(ENT_QUOTES)",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Symfony-style htmlspecialchars with ENT_QUOTES flag",
		},

		// Doctrine sanitizers
		{
			ID:          "php.doctrine.setparameter",
			Language:    rules.LangPHP,
			Pattern:     `->setParameter\(`,
			ObjectType:  "Query",
			MethodName:  "setParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Doctrine setParameter() parameterized query binding",
		},
		{
			ID:          "php.doctrine.querybuilder",
			Language:    rules.LangPHP,
			Pattern:     `->createQueryBuilder\(\)`,
			ObjectType:  "EntityManager",
			MethodName:  "createQueryBuilder",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Doctrine createQueryBuilder() type-safe query builder",
		},

		// Eloquent sanitizers
		{
			ID:          "php.eloquent.parameterized",
			Language:    rules.LangPHP,
			Pattern:     `->whereRaw\([^,]+,\s*\[`,
			ObjectType:  "Eloquent",
			MethodName:  "whereRaw",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Eloquent whereRaw() with bindings array (parameterized)",
		},
		{
			ID:          "php.eloquent.querybuilder",
			Language:    rules.LangPHP,
			Pattern:     `->(where|select|orderBy)\(`,
			ObjectType:  "Eloquent",
			MethodName:  "where/select/orderBy",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Eloquent query builder methods (parameterized)",
		},

		// --- SnkFileRead sanitizers (path traversal prevention) ---
		// NOTE: realpath() for SnkFileRead deliberately absent —
		// canonicalize-only, see the realpath note above.
		{
			ID:          "php.basename.fileread",
			Language:    rules.LangPHP,
			Pattern:     `\bbasename\s*\(`,
			MethodName:  "basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead},
			Description: "Basename extraction prevents directory traversal on reads",
		},
		{
			ID:          "php.symfony.filesystem.exists",
			Language:    rules.LangPHP,
			Pattern:     `\$filesystem->exists\s*\(`,
			ObjectType:  "Symfony\\Filesystem",
			MethodName:  "exists",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Symfony Filesystem existence check before file operations",
		},

		// --- SnkLog sanitizers (log injection prevention) ---
		{
			ID:          "php.str_replace.newlines",
			Language:    rules.LangPHP,
			Pattern:     `\bstr_replace\s*\(\s*(?:array\s*\()?\s*['"]\\[rn]`,
			MethodName:  "str_replace",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Newline character replacement prevents log and header injection",
		},
		{
			ID:          "php.preg_replace.control_chars",
			Language:    rules.LangPHP,
			Pattern:     `\bpreg_replace\s*\(\s*['"]/\[\\\\rn\]`,
			MethodName:  "preg_replace",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Regex-based control character stripping prevents log/header injection",
		},
		{
			ID:          "php.monolog.structured",
			Language:    rules.LangPHP,
			Pattern:     `\$\w+->(?:info|warning|error|debug|critical|alert|emergency|notice)\s*\(\s*['"][^'"]*['"]\s*,\s*\[`,
			ObjectType:  "Monolog\\Logger",
			MethodName:  "info/warning/error/...",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Monolog structured logging with context array (key-value prevents injection)",
		},

		// --- SnkTemplate sanitizers (SSTI prevention) ---
		{
			ID:          "php.twig.escape.js",
			Language:    rules.LangPHP,
			Pattern:     `\|\s*e\s*\(\s*['"]js['"]|escape\s*\(\s*['"]js['"]`,
			ObjectType:  "Twig",
			MethodName:  "|e('js')",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate},
			Description: "Twig JavaScript-context escaping filter",
		},
		{
			ID:          "php.blade.sanitize",
			Language:    rules.LangPHP,
			Pattern:     `\bBlade::render\s*\(`,
			ObjectType:  "Blade",
			MethodName:  "Blade::render",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Laravel Blade render with auto-escaping ({{ }} escapes by default)",
		},
		{
			ID:          "php.htmlpurifier",
			Language:    rules.LangPHP,
			Pattern:     `HTMLPurifier.*->purify\s*\(|\$purifier->purify\s*\(`,
			ObjectType:  "HTMLPurifier",
			MethodName:  "purify",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "HTMLPurifier library for safe HTML filtering",
		},

		// --- SnkHeader sanitizers (HTTP header injection prevention) ---
		{
			ID:          "php.header.remove.crlf",
			Language:    rules.LangPHP,
			Pattern:     `\bstr_replace\s*\(\s*(?:array\s*\()?\s*['"]\\r\\n`,
			MethodName:  "str_replace(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "CRLF removal prevents HTTP header injection (response splitting)",
		},
		{
			ID:          "php.symfony.response.headers.set",
			Language:    rules.LangPHP,
			Pattern:     `\$response->headers->set\s*\(`,
			ObjectType:  "Symfony\\HttpFoundation\\Response",
			MethodName:  "headers->set",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Symfony Response header setter (validates header values)",
		},

		// --- SnkLDAP sanitizers (LDAP injection prevention) ---
		{
			ID:          "php.ldap_escape",
			Language:    rules.LangPHP,
			Pattern:     `\bldap_escape\s*\(`,
			MethodName:  "ldap_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "PHP built-in LDAP string escaping (filter and DN modes)",
		},
		{
			ID:          "php.symfony.ldap.escape",
			Language:    rules.LangPHP,
			Pattern:     `LdapUtils::escape\s*\(|Ldap::escape\s*\(`,
			ObjectType:  "Symfony\\Ldap",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Symfony LDAP component escape for filter and DN values",
		},
		{
			ID:          "php.laminas.ldap.escapevalue",
			Language:    rules.LangPHP,
			Pattern:     `AbstractFilter::escapeValue\s*\(|Dn::escapeValue\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeValue",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Laminas/Zend LDAP filter and DN value escaping (AbstractFilter::escapeValue or Dn::escapeValue)",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "php.mongodb.bson.objectid",
			Language:    rules.LangPHP,
			Pattern:     `new\s+(?:MongoDB\\\\BSON\\\\)?ObjectId\s*\(`,
			ObjectType:  "",
			MethodName:  "ObjectId",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "BSON ObjectId conversion (validates and converts to safe ObjectId type, preventing NoSQL operator injection)",
		},
		{
			ID:          "php.mongodb.intval.nosql",
			Language:    rules.LangPHP,
			Pattern:     `\bintval\s*\(`,
			MethodName:  "intval",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Integer conversion neutralizes NoSQL operator injection (restricts to numeric value)",
		},

		{
			ID:          "php.symfony.validator",
			Language:    rules.LangPHP,
			Pattern:     `\$validator->validate\s*\(`,
			ObjectType:  "Symfony\\Validator",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Symfony Validator component for input validation before trust boundary",
		},

		// --- Path traversal sanitizers (SnkFileRead/SnkFileWrite) ---
		// NOTE: SplFileInfo::getRealPath() deliberately absent —
		// canonicalize-only, see the realpath note above.
		{
			ID:          "php.pathinfo.basename",
			Language:    rules.LangPHP,
			Pattern:     `\bpathinfo\s*\(.*PATHINFO_BASENAME`,
			ObjectType:  "",
			MethodName:  "pathinfo(PATHINFO_BASENAME)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "pathinfo() with PATHINFO_BASENAME extracts filename without directory (equivalent to basename())",
		},
		{
			ID:          "php.wordpress.sanitize_file_name",
			Language:    rules.LangPHP,
			Pattern:     `\bsanitize_file_name\s*\(`,
			ObjectType:  "",
			MethodName:  "sanitize_file_name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "WordPress sanitize_file_name() removes path separators, special chars, and .. sequences",
		},
		// NOTE: wp_normalize_path() deliberately absent — it only converts
		// backslashes to forward slashes and collapses duplicate separators;
		// "../" traversal sequences pass through untouched. See the realpath
		// note above.

		// --- Eval sanitizers (SnkEval) ---
		{
			ID:          "php.settype",
			Language:    rules.LangPHP,
			Pattern:     `\bsettype\s*\(`,
			ObjectType:  "",
			MethodName:  "settype",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Type coercion via settype() forces safe type conversion (int, float, bool, string)",
		},

		// --- Deserialization sanitizers (SnkDeserialize) ---
		{
			ID:          "php.unserialize.allowed_classes",
			Language:    rules.LangPHP,
			Pattern:     `\bunserialize\s*\([^)]*allowed_classes`,
			ObjectType:  "",
			MethodName:  "unserialize(allowed_classes)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "PHP 7+ unserialize() with allowed_classes restriction prevents gadget chain exploitation",
		},
		{
			ID:          "php.libxml.nonet",
			Language:    rules.LangPHP,
			Pattern:     `LIBXML_NONET`,
			ObjectType:  "",
			MethodName:  "LIBXML_NONET",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "LIBXML_NONET flag prevents network access during XML parsing (XXE/SSRF prevention)",
		},
		{
			ID:          "php.xmlreader.no_loaddtd",
			Language:    rules.LangPHP,
			Pattern:     `setParserProperty\s*\(\s*XMLReader::LOADDTD\s*,\s*false`,
			ObjectType:  "XMLReader",
			MethodName:  "setParserProperty(LOADDTD, false)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XMLReader DTD loading disabled prevents XXE via external DTD references (CWE-611)",
		},
		{
			ID:          "php.xmlreader.no_subst_entities",
			Language:    rules.LangPHP,
			Pattern:     `setParserProperty\s*\(\s*XMLReader::SUBST_ENTITIES\s*,\s*false`,
			ObjectType:  "XMLReader",
			MethodName:  "setParserProperty(SUBST_ENTITIES, false)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XMLReader entity substitution disabled prevents XXE expansion (CWE-611)",
		},

		// --- SSRF sanitizers (SnkURLFetch) ---
		{
			ID:          "php.filter_var.no_priv_range",
			Language:    rules.LangPHP,
			Pattern:     `filter_var\s*\(.*FILTER_FLAG_NO_PRIV_RANGE`,
			ObjectType:  "",
			MethodName:  "filter_var(FILTER_FLAG_NO_PRIV_RANGE)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP validation rejecting private ranges (10.x, 172.16.x, 192.168.x) for SSRF prevention",
		},
		{
			ID:          "php.filter_var.no_res_range",
			Language:    rules.LangPHP,
			Pattern:     `filter_var\s*\(.*FILTER_FLAG_NO_RES_RANGE`,
			ObjectType:  "",
			MethodName:  "filter_var(FILTER_FLAG_NO_RES_RANGE)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP validation rejecting reserved ranges (127.x, 0.x, 169.254.x) for SSRF prevention",
		},
		{
			ID:          "php.wordpress.wp_safe_remote_get",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_safe_remote_get\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_safe_remote_get",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "WordPress safe HTTP GET with built-in SSRF protections (blocks private IP ranges)",
		},
		{
			ID:          "php.wordpress.wp_safe_remote_post",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_safe_remote_post\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_safe_remote_post",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "WordPress safe HTTP POST with built-in SSRF protections (blocks private IP ranges)",
		},
		{
			ID:          "php.wordpress.wp_safe_remote_request",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_safe_remote_request\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_safe_remote_request",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "WordPress safe HTTP request with built-in SSRF protections (blocks private IP ranges via wp_http_validate_url)",
		},
		{
			ID:          "php.wordpress.wp_safe_remote_head",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_safe_remote_head\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_safe_remote_head",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "WordPress safe HTTP HEAD with built-in SSRF protections (blocks private IP ranges)",
		},
		{
			ID:          "php.ip2long",
			Language:    rules.LangPHP,
			Pattern:     `\bip2long\s*\(`,
			ObjectType:  "",
			MethodName:  "ip2long",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP to integer conversion for range validation (part of SSRF defense chain)",
		},
		{
			ID:          "php.inet_pton",
			Language:    rules.LangPHP,
			Pattern:     `\binet_pton\s*\(`,
			ObjectType:  "",
			MethodName:  "inet_pton",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IPv4/IPv6 to binary conversion for range validation (SSRF defense chain)",
		},

		// --- SnkLog sanitizers (log injection prevention) — additional ---
		{
			ID:          "php.laravel.log.structured",
			Language:    rules.LangPHP,
			Pattern:     `Log::(?:info|warning|error|debug|critical|alert|emergency|notice)\s*\([^,]+,\s*\[`,
			ObjectType:  "Illuminate\\Support\\Facades\\Log",
			MethodName:  "Log::info/warning/error/...",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Laravel Log facade structured logging with context array (key-value prevents injection)",
		},

		// --- SnkTrustBoundary sanitizers (trust boundary validation) — additional ---
		{
			ID:          "php.symfony.form.isvalid",
			Language:    rules.LangPHP,
			Pattern:     `\$form->isValid\s*\(\s*\)`,
			ObjectType:  "Symfony\\Form",
			MethodName:  "isValid",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Symfony Form validation check before storing user data across trust boundary",
		},
		{
			ID:          "php.laravel.request.validated",
			Language:    rules.LangPHP,
			Pattern:     `\$request->validated\s*\(\s*\)|\$request->safe\s*\(\s*\)`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "validated/safe",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Laravel request validated()/safe() returns only validated fields (prevents untrusted data in session/env)",
		},

		// --- SnkRedirect sanitizers (open redirect prevention) ---
		{
			ID:          "php.parse_url",
			Language:    rules.LangPHP,
			Pattern:     `\bparse_url\s*\(`,
			MethodName:  "parse_url",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "URL component extraction for scheme/host validation before redirect",
		},
		{
			ID:          "php.rawurlencode",
			Language:    rules.LangPHP,
			Pattern:     `\brawurlencode\s*\(`,
			MethodName:  "rawurlencode",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHeader},
			Description: "RFC 3986 URL encoding prevents protocol injection in redirects and CRLF in headers",
		},
		{
			ID:          "php.wordpress.wp_validate_redirect",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_validate_redirect\s*\(`,
			MethodName:  "wp_validate_redirect",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "WordPress redirect validation against allowed hosts list",
		},
		{
			ID:          "php.symfony.urlgenerator",
			Language:    rules.LangPHP,
			Pattern:     `\$router->generate\s*\(|\$urlGenerator->generate\s*\(|UrlGeneratorInterface.*generate\s*\(`,
			ObjectType:  "Symfony\\Routing\\Generator",
			MethodName:  "generate",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Symfony URL generator produces safe URLs from named routes (no user-controlled URL)",
		},

		// --- SnkHeader sanitizers (HTTP header injection prevention) — additional ---
		{
			ID:          "php.trim.header",
			Language:    rules.LangPHP,
			Pattern:     `\btrim\s*\(.*["']\\r\\n`,
			MethodName:  "trim(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "trim() with explicit CRLF character list prevents header injection",
		},

		// --- SnkLDAP sanitizers (LDAP injection prevention) — additional ---
		{
			ID:          "php.ldaprecord.escape",
			Language:    rules.LangPHP,
			Pattern:     `LdapRecord\\Models.*::escape\s*\(|EscapesValue.*escape\s*\(`,
			ObjectType:  "LdapRecord",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LdapRecord library value escaping for LDAP filter and DN contexts",
		},
		{
			ID:          "php.addcslashes.ldap",
			Language:    rules.LangPHP,
			Pattern:     `\baddcslashes\s*\([^)]*['"]\\\\\s*,\s*=\s*\+\s*<\s*>\s*#\s*;`,
			MethodName:  "addcslashes(LDAP special chars)",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Manual LDAP DN special character escaping via addcslashes()",
		},
		{
			ID:          "php.preg_replace.ldap_special",
			Language:    rules.LangPHP,
			Pattern:     `\bpreg_replace\s*\(\s*['"]/\[.*\\\\,=\+<>#;\]`,
			MethodName:  "preg_replace(LDAP special)",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Regex replacement of LDAP-sensitive characters (\\,=+<>#;) prevents injection",
		},

		// --- Drupal 10+ sanitizers ---
		{
			ID:          "php.drupal.xss.filter",
			Language:    rules.LangPHP,
			Pattern:     `Xss::filter\s*\(`,
			ObjectType:  "Drupal\\Component\\Utility\\Xss",
			MethodName:  "Xss::filter",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Drupal XSS filter — strips dangerous HTML tags and attributes",
		},
		{
			ID:          "php.drupal.xss.filteradmin",
			Language:    rules.LangPHP,
			Pattern:     `Xss::filterAdmin\s*\(`,
			ObjectType:  "Drupal\\Component\\Utility\\Xss",
			MethodName:  "Xss::filterAdmin",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Drupal admin XSS filter — allows safe HTML subset for admin content",
		},
		{
			ID:          "php.drupal.html.escape",
			Language:    rules.LangPHP,
			Pattern:     `Html::escape\s*\(`,
			ObjectType:  "Drupal\\Component\\Utility\\Html",
			MethodName:  "Html::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Drupal HTML entity escaping via Html::escape()",
		},
		{
			ID:          "php.drupal.urlhelper.filterbadprotocol",
			Language:    rules.LangPHP,
			Pattern:     `UrlHelper::filterBadProtocol\s*\(`,
			ObjectType:  "Drupal\\Component\\Utility\\UrlHelper",
			MethodName:  "UrlHelper::filterBadProtocol",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Drupal URL protocol filter — removes javascript: and other dangerous schemes",
		},
		{
			ID:          "php.drupal.urlhelper.stripdangerousprotocols",
			Language:    rules.LangPHP,
			Pattern:     `UrlHelper::stripDangerousProtocols\s*\(`,
			ObjectType:  "Drupal\\Component\\Utility\\UrlHelper",
			MethodName:  "UrlHelper::stripDangerousProtocols",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Drupal strips dangerous URL protocols (javascript:, vbscript:, data:)",
		},

		// --- Phalcon sanitizers (Phalcon\Filter + Phalcon\Html\Escaper) ---
		// $this->escaper->escapeHtml/Js/Css/Url() (Phalcon\Html\Escaper /
		// Phalcon\Escaper) context-aware output escaping. ObjectType "Escaper"
		// scopes these to an escaper receiver.
		{
			ID:          "php.phalcon.escaper.escapehtml",
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?escaper->escapeHtml\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeHtml",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Phalcon Escaper::escapeHtml() HTML context escaping",
		},
		{
			ID:          "php.phalcon.escaper.escapejs",
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?escaper->escapeJs\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeJs",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Phalcon Escaper::escapeJs() JavaScript context escaping",
		},
		{
			ID:          "php.phalcon.escaper.escapecss",
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?escaper->escapeCss\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeCss",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Phalcon Escaper::escapeCss() CSS context escaping",
		},
		{
			ID:          "php.phalcon.escaper.escapeurl",
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?escaper->escapeUrl\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeUrl",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Phalcon Escaper::escapeUrl() URL context escaping",
		},
		// $this->filter->sanitize() (Phalcon\Filter) applies the framework's
		// named sanitizers (string, int, email, alphanum, striptags, …) which
		// strip injection metacharacters from the value, neutralizing the
		// common string-injection sinks.
		{
			ID:          "php.phalcon.filter.sanitize",
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?filter->sanitize\s*\(`,
			ObjectType:  "Filter",
			MethodName:  "sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Phalcon Filter::sanitize() named-filter input sanitization",
		},

		// --- Laravel crypto sanitizers (SnkCrypto) ---
		{
			ID:          "php.laravel.hash.make",
			Language:    rules.LangPHP,
			Pattern:     `Hash::make\s*\(`,
			ObjectType:  "Illuminate\\Support\\Facades\\Hash",
			MethodName:  "Hash::make",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Laravel Hash::make() bcrypt/argon2 password hashing (safe password storage)",
		},
		{
			ID:          "php.laravel.hash.check",
			Language:    rules.LangPHP,
			Pattern:     `Hash::check\s*\(`,
			ObjectType:  "Illuminate\\Support\\Facades\\Hash",
			MethodName:  "Hash::check",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Laravel Hash::check() constant-time password verification",
		},
		{
			ID:          "php.laravel.crypt.encrypt",
			Language:    rules.LangPHP,
			Pattern:     `Crypt::encrypt(?:String)?\s*\(`,
			ObjectType:  "Illuminate\\Support\\Facades\\Crypt",
			MethodName:  "Crypt::encrypt/encryptString",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Laravel Crypt::encrypt() AES-256-CBC envelope encryption with HMAC authentication",
		},

		// --- PHP native crypto sanitizers (SnkCrypto) ---
		{
			ID:          "php.openssl.encrypt",
			Language:    rules.LangPHP,
			Pattern:     `\bopenssl_encrypt\s*\(`,
			ObjectType:  "",
			MethodName:  "openssl_encrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PHP openssl_encrypt() authenticated encryption (replaces deprecated mcrypt)",
		},
		{
			ID:          "php.sodium.crypto_pwhash",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_crypto_pwhash(?:_str)?\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_crypto_pwhash/sodium_crypto_pwhash_str",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PHP sodium Argon2id password hashing (strongest native PHP password storage)",
		},
		{
			ID:          "php.sodium.crypto_pwhash_str_verify",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_crypto_pwhash_str_verify\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_crypto_pwhash_str_verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PHP sodium constant-time Argon2id password verification",
		},

		// --- Laravel trust boundary sanitizers (SnkTrustBoundary) ---
		{
			ID:          "php.laravel.gate.authorize",
			Language:    rules.LangPHP,
			Pattern:     `Gate::authorize\s*\(`,
			ObjectType:  "Illuminate\\Support\\Facades\\Gate",
			MethodName:  "Gate::authorize",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Laravel Gate::authorize() enforces authorization policy before trust boundary crossing",
		},

		// --- Symfony trust boundary sanitizers (SnkTrustBoundary) ---
		{
			ID:          "php.symfony.security.isgranted",
			Language:    rules.LangPHP,
			Pattern:     `->isGranted\s*\(`,
			ObjectType:  "Symfony\\Security",
			MethodName:  "isGranted",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Symfony Security isGranted() enforces role/permission check before trust boundary",
		},
		{
			ID:          "php.symfony.security.denyaccess",
			Language:    rules.LangPHP,
			Pattern:     `\$this->denyAccessUnlessGranted\s*\(`,
			ObjectType:  "Symfony\\AbstractController",
			MethodName:  "denyAccessUnlessGranted",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Symfony controller denyAccessUnlessGranted() blocks unauthorized trust boundary crossing",
		},

		// --- Laravel typed request accessors (SnkSQLQuery, SnkCommand) ---
		{
			ID:          "php.laravel.request.integer",
			Language:    rules.LangPHP,
			Pattern:     `\$request->integer\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "integer",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkEval},
			Description: "Laravel Request::integer() type-safe int accessor (restricts to numeric values)",
		},
		{
			ID:          "php.laravel.request.boolean",
			Language:    rules.LangPHP,
			Pattern:     `\$request->boolean\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "boolean",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkEval},
			Description: "Laravel Request::boolean() type-safe bool accessor (restricts to true/false)",
		},

		// --- Laravel string sanitizers ---
		{
			ID:          "php.laravel.str.slug",
			Language:    rules.LangPHP,
			Pattern:     `Str::slug\s*\(`,
			ObjectType:  "Illuminate\\Support\\Str",
			MethodName:  "Str::slug",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Laravel Str::slug() converts to lowercase ASCII-only hyphen-separated string (strips all special chars)",
		},

		// --- XSLT hardening (CWE-91) ---
		{
			ID:          "php.xsl.xsltprocessor.setsecurityprefs",
			Language:    rules.LangPHP,
			Pattern:     `->setSecurityPrefs\s*\(`,
			ObjectType:  "XSLTProcessor",
			MethodName:  "setSecurityPrefs",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XSLTProcessor::setSecurityPrefs restricts file/network/directory access during stylesheet processing — neutralizes XSLT injection side-effects",
		},
		// --- JWT signature-verification sanitizers (CWE-347) ---
		//
		// Pair with the JWT sinks in php_sinks.go. A token that has been
		// verified with an explicit signing algorithm (RS/HS/ES/PS of a
		// standard bit size) or validated against a lcobucci SignedWith
		// constraint is integrity-protected for downstream use.
		{
			ID:          "php.jwt.namshi.isvalid.with_algo",
			Language:    rules.LangPHP,
			Pattern:     `->isValid\s*\([^)]*['"](?:RS|HS|ES|PS)(?:256|384|512)['"]`,
			ObjectType:  "JWS",
			MethodName:  "isValid",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary},
			Description: "namshi/jose ->isValid($publicKey, 'RS256'|'HS256'|...) verifies the JWS signature with an explicit algorithm before claims are trusted",
		},
		{
			ID:          "php.jwt.lcobucci.signedwith",
			Language:    rules.LangPHP,
			Pattern:     `new\s+SignedWith\s*\(`,
			ObjectType:  "Lcobucci\\JWT\\Validation\\Constraint\\SignedWith",
			MethodName:  "SignedWith",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary},
			Description: "lcobucci/jwt SignedWith constraint passed to Validator::validate() enforces signature verification under a specific signer/key",
		},

		// --- libsodium AEAD / signature / MAC verification sanitizers (CWE-347, CWE-208) ---
		// Authenticated decryption returns false on auth-tag mismatch; signature/MAC
		// verifies are constant-time. All produce a verified-integrity result, which
		// neutralizes downstream crypto-trust sinks.
		{
			ID:          "php.sodium.crypto_auth_verify",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_crypto_auth_verify\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_crypto_auth_verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium constant-time HMAC-SHA512/256 verification (sodium_crypto_auth_verify)",
		},
		{
			ID:          "php.sodium.crypto_sign_verify_detached",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_crypto_sign_verify_detached\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_crypto_sign_verify_detached",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium Ed25519 detached signature verification (sodium_crypto_sign_verify_detached)",
		},
		{
			ID:          "php.sodium.compare",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_compare\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_compare",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium constant-time bytes comparison (sodium_compare) — prevents timing-side-channel leaks",
		},
		{
			ID:          "php.sodium.crypto_box_open",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_crypto_box_open\s*\(|\bsodium_crypto_box_seal_open\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_crypto_box_open/sodium_crypto_box_seal_open",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium authenticated public-key decryption — verifies Poly1305 auth tag before returning plaintext",
		},
		{
			ID:          "php.sodium.crypto_secretbox_open",
			Language:    rules.LangPHP,
			Pattern:     `\bsodium_crypto_secretbox_open\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_crypto_secretbox_open",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium authenticated symmetric decryption (XSalsa20-Poly1305) — returns false on auth-tag mismatch",
		},

		// --- intl IDN normalization (CWE-1007 anti-homograph for SSRF/redirect) ---
		{
			ID:          "php.intl.idn_to_ascii",
			Language:    rules.LangPHP,
			Pattern:     `\bidn_to_ascii\s*\(`,
			ObjectType:  "",
			MethodName:  "idn_to_ascii",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "intl idn_to_ascii() normalizes Unicode hostnames to Punycode (defeats homograph/IDN-spoof URLs in SSRF and open-redirect contexts)",
		},

		// --- WordPress sanitizer gaps (esc_xml, mime/class sanitize, kses filters, password verify) ---
		{
			ID:          "php.wordpress.esc_xml",
			Language:    rules.LangPHP,
			Pattern:     `\besc_xml\s*\(`,
			ObjectType:  "",
			MethodName:  "esc_xml",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "WordPress esc_xml() (5.5+) — escapes text for safe output inside XML/RSS payloads",
		},
		{
			ID:          "php.wordpress.sanitize_html_class",
			Language:    rules.LangPHP,
			Pattern:     `\bsanitize_html_class\s*\(`,
			ObjectType:  "",
			MethodName:  "sanitize_html_class",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "WordPress sanitize_html_class() — strips chars that are not valid in an HTML class attribute",
		},
		{
			ID:          "php.wordpress.sanitize_mime_type",
			Language:    rules.LangPHP,
			Pattern:     `\bsanitize_mime_type\s*\(`,
			ObjectType:  "",
			MethodName:  "sanitize_mime_type",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader},
			Description: "WordPress sanitize_mime_type() — restricts a MIME type string to RFC-allowed characters (safe for Content-Type headers)",
		},
		{
			ID:          "php.wordpress.wp_filter_nohtml_kses",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_filter_nohtml_kses\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_filter_nohtml_kses",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "WordPress wp_filter_nohtml_kses() — strips ALL HTML tags via wp_kses (used as a hook for option/comment fields where no markup is allowed)",
		},
		{
			ID:          "php.wordpress.wp_filter_post_kses",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_filter_post_kses\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_filter_post_kses",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "WordPress wp_filter_post_kses() — runs content through wp_kses with the post-permitted-HTML allowlist (used as a content_save_pre filter)",
		},
		{
			ID:          "php.wordpress.wp_check_password",
			Language:    rules.LangPHP,
			Pattern:     `\bwp_check_password\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_check_password",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "WordPress wp_check_password() — constant-time password verification against a stored phpass/bcrypt hash",
		},

		// Temporal-parse return-value sanitizers
		//
		// PHP DateTime parsers and strtotime-family functions take a
		// (possibly permissive) date/time string as their first argument and
		// return a strongly-typed DateTime/DateTimeImmutable/DateInterval
		// object or an int Unix timestamp. Once converted, the result cannot
		// carry SQL/shell metacharacters: integers are inherently safe, and
		// DateTime objects must be rendered via format() with a controlled
		// format string before reaching a string sink, bounding output to a
		// known charset (digits, dashes, colons, T, Z, +, .). Failure to
		// parse returns false (or throws DateMalformedStringException for the
		// DateTime/DateTimeImmutable constructors), never a tainted string.
		{
			ID:          "php.datetime.construct",
			Language:    rules.LangPHP,
			Pattern:     `\bnew\s+\\?DateTime\s*\(`,
			ObjectType:  "DateTime",
			MethodName:  "DateTime",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "PHP new DateTime($input) parses the string and returns a typed DateTime object (or throws DateMalformedStringException on PHP 8.3+); subsequent format() calls produce safe output bounded by the format spec",
		},
		{
			ID:          "php.datetimeimmutable.construct",
			Language:    rules.LangPHP,
			Pattern:     `\bnew\s+\\?DateTimeImmutable\s*\(`,
			ObjectType:  "DateTimeImmutable",
			MethodName:  "DateTimeImmutable",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "PHP new DateTimeImmutable($input) parses the string and returns a typed DateTimeImmutable object (or throws); same safety properties as DateTime",
		},
		{
			ID:          "php.date_create",
			Language:    rules.LangPHP,
			Pattern:     `\bdate_create\s*\(`,
			ObjectType:  "@global",
			MethodName:  "date_create",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "PHP date_create($input) is the procedural alias for new DateTime — returns DateTime|false (typed object on success)",
		},
		{
			ID:          "php.date_create_immutable",
			Language:    rules.LangPHP,
			Pattern:     `\bdate_create_immutable\s*\(`,
			ObjectType:  "@global",
			MethodName:  "date_create_immutable",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "PHP date_create_immutable($input) is the procedural alias for new DateTimeImmutable — returns DateTimeImmutable|false",
		},
		{
			ID:          "php.strtotime",
			Language:    rules.LangPHP,
			Pattern:     `\bstrtotime\s*\(`,
			ObjectType:  "@global",
			MethodName:  "strtotime",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "PHP strtotime($input) parses an English textual datetime and returns int|false (Unix timestamp); the resulting integer is inherently safe in SQL, shell, log, file, HTML, and redirect contexts",
		},
		{
			ID:          "php.dateinterval.createfromdatestring",
			Language:    rules.LangPHP,
			Pattern:     `DateInterval::createFromDateString\s*\(`,
			ObjectType:  "DateInterval",
			MethodName:  "createFromDateString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "PHP DateInterval::createFromDateString($input) parses a relative-time string and returns DateInterval|false (typed interval object)",
		},
		{
			ID:          "php.carbon.parse",
			Language:    rules.LangPHP,
			Pattern:     `Carbon::parse\s*\(`,
			ObjectType:  "Carbon",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Carbon\\Carbon::parse($input) (Briannesbitt\\Carbon — bundled with Laravel) parses a date string and returns a Carbon (DateTime subclass) instance; format() output is bounded by the format spec",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "php.mongodb.objectid",
			Language:    rules.LangPHP,
			Pattern:     `new\s+MongoDB\\BSON\\ObjectId\s*\(`,
			ObjectType:  "MongoDB\\BSON\\ObjectId",
			MethodName:  "ObjectId",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "MongoDB\\BSON\\ObjectId($hex) — validates and parses a 24-hex-char string into an ObjectId; rejects operator-injection payloads (CWE-943)",
		},
		{
			ID:          "php.mongodb.bson_document_init",
			Language:    rules.LangPHP,
			Pattern:     `MongoDB\\BSON\\Document::fromPHP\s*\(|MongoDB\\BSON\\fromPHP\s*\(`,
			ObjectType:  "MongoDB\\BSON\\Document",
			MethodName:  "fromPHP",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB\\BSON\\Document::fromPHP / fromPHP() — serialises a PHP array into a typed BSON document (values bound as typed BSON entries, not concatenated into a query string)",
		},
		{
			ID:          "php.mongodb.bson_serializable",
			Language:    rules.LangPHP,
			Pattern:     `->bsonSerialize\s*\(`,
			ObjectType:  "MongoDB\\BSON\\Serializable",
			MethodName:  "bsonSerialize",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB\\BSON\\Serializable::bsonSerialize() — explicit typed BSON serialisation pathway (values bound as typed BSON entries)",
		},
		{
			ID:          "php.mongodb.regex_from_pattern",
			Language:    rules.LangPHP,
			Pattern:     `new\s+MongoDB\\BSON\\Regex\s*\(`,
			ObjectType:  "MongoDB\\BSON\\Regex",
			MethodName:  "Regex",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB\\BSON\\Regex($pattern, $flags) — wraps a regex pattern as a typed BSON regex value (forces regex typing, prevents an operator-document payload from smuggling a $where clause)",
		},

		// --- PostgreSQL parameterized / escaping sanitizers (CWE-89) ---
		// The pgsql extension's safe APIs: pg_query_params() /
		// pg_send_query_params() bind values via $1, $2 placeholders;
		// pg_prepare()+pg_execute() use a named server-side prepared statement;
		// pg_escape_literal() / pg_escape_string() / pg_escape_identifier()
		// connection-aware escape values. All neutralize the pg_query sinks.
		{
			ID:          "php.pg_query_params",
			Language:    rules.LangPHP,
			Pattern:     `\bpg_query_params\s*\(|\bpg_send_query_params\s*\(`,
			ObjectType:  "",
			MethodName:  "pg_query_params/pg_send_query_params",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL pg_query_params()/pg_send_query_params() bind user values via $1/$2 placeholders (parameterized query — no SQL injection)",
		},
		{
			ID:          "php.pg_prepare",
			Language:    rules.LangPHP,
			Pattern:     `\bpg_prepare\s*\(`,
			ObjectType:  "",
			MethodName:  "pg_prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL pg_prepare() creates a server-side prepared statement (executed with pg_execute(), values bound separately — no SQL injection)",
		},
		{
			ID:          "php.pg_escape",
			Language:    rules.LangPHP,
			Pattern:     `\bpg_escape_literal\s*\(|\bpg_escape_string\s*\(|\bpg_escape_identifier\s*\(`,
			ObjectType:  "",
			MethodName:  "pg_escape_literal/pg_escape_string/pg_escape_identifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL connection-aware escaping (pg_escape_literal/pg_escape_string/pg_escape_identifier) for safe interpolation of values/identifiers",
		},

		// --- SQLite3 escaping sanitizer (CWE-89) ---
		// SQLite3::escapeString() escapes single quotes for safe interpolation
		// into a SQLite3 query string (prepared statements via SQLite3::prepare
		// are the preferred form, already covered by the generic prepare entry).
		{
			ID:          "php.sqlite3.escapestring",
			Language:    rules.LangPHP,
			Pattern:     `\bSQLite3::escapeString\s*\(|->escapeString\s*\(`,
			ObjectType:  "SQLite3",
			MethodName:  "escapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite3::escapeString() escapes quotes for safe interpolation into a SQLite3 query (prefer SQLite3::prepare with bound params)",
		},

		// --- laminas-escaper context-aware output encoders (CWE-79) ---
		// Laminas\Escaper\Escaper is the OWASP-recommended PHP output-encoding
		// library (formerly Zend\Escaper). Each method applies peer-reviewed,
		// context-specific escaping rules to defend against XSS at the output
		// boundary. ObjectType "Escaper" scopes to the canonical `$escaper`
		// receiver; the method names are library-specific so FP risk is low.
		// Per the library docs these are OUTPUT encoders only — they neutralize
		// the HTML-output (XSS) sink, NOT input filtering, SQL, command,
		// open-redirect, or template-injection (SSTI) sinks (HTML-escaping a
		// value does not make it safe to use as a template name/string).
		{
			ID:          "php.laminas.escaper.escapehtml",
			Language:    rules.LangPHP,
			Pattern:     `->escapeHtml\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeHtml",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Laminas\\Escaper\\Escaper::escapeHtml() — escapes a string for an HTML body context",
		},
		{
			ID:          "php.laminas.escaper.escapehtmlattr",
			Language:    rules.LangPHP,
			Pattern:     `->escapeHtmlAttr\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeHtmlAttr",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Laminas\\Escaper\\Escaper::escapeHtmlAttr() — escapes a string for an HTML attribute context (covers unquoted/illegally quoted attributes)",
		},
		{
			ID:          "php.laminas.escaper.escapejs",
			Language:    rules.LangPHP,
			Pattern:     `->escapeJs\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeJs",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Laminas\\Escaper\\Escaper::escapeJs() — escapes a string for a JavaScript context embedded in HTML",
		},
		{
			ID:          "php.laminas.escaper.escapecss",
			Language:    rules.LangPHP,
			Pattern:     `->escapeCss\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeCss",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Laminas\\Escaper\\Escaper::escapeCss() — escapes a string for a CSS context embedded in HTML",
		},
		{
			ID:          "php.laminas.escaper.escapeurl",
			Language:    rules.LangPHP,
			Pattern:     `->escapeUrl\s*\(`,
			ObjectType:  "Escaper",
			MethodName:  "escapeUrl",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Laminas\\Escaper\\Escaper::escapeUrl() — escapes a string for a URI/URI-parameter context embedded in HTML (rawurlencode-based; does not validate full redirect targets)",
		},
		// --- CodeIgniter 4 / Yii 2 output escaping ---
		// Both frameworks have request sources (and CodeIgniter a db->query()
		// SQL sink) modeled in php_sources.go / php_sinks.go, but had no
		// sanitizers — so the canonical XSS-prevention call in each was not
		// clearing taint, producing false positives on correctly-escaped output.
		{
			ID:          "php.codeigniter.esc",
			Language:    rules.LangPHP,
			Pattern:     `\besc\s*\(`,
			ObjectType:  "@global",
			MethodName:  "esc",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "CodeIgniter 4 esc() — context-aware output escaping helper (html/js/css/url/attr contexts); the framework's canonical XSS-prevention function",
		},
		{
			ID:          "php.yii.html.encode",
			Language:    rules.LangPHP,
			Pattern:     `Html::encode\s*\(`,
			ObjectType:  "Html",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Yii 2 yii\\helpers\\Html::encode() — HTML entity encoding (htmlspecialchars wrapper) for safe output in an HTML body/attribute context",
		},
		{
			ID:          "php.yii.htmlpurifier.process",
			Language:    rules.LangPHP,
			Pattern:     `HtmlPurifier::process\s*\(`,
			ObjectType:  "HtmlPurifier",
			MethodName:  "process",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Yii 2 yii\\helpers\\HtmlPurifier::process() — HTML Purifier-based sanitization that strips dangerous markup to prevent XSS in rendered HTML",
		},
	}
}
