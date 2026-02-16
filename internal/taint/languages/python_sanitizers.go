package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

func (c *PythonCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		{
			ID:          "py.html.escape",
			Language:    rules.LangPython,
			Pattern:     `html\.escape\(|escape\(|markupsafe\.escape\(`,
			ObjectType:  "",
			MethodName:  "html.escape/markupsafe.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML entity escaping",
		},
		{
			ID:          "py.bleach.clean",
			Language:    rules.LangPython,
			Pattern:     `bleach\.clean\(`,
			ObjectType:  "",
			MethodName:  "bleach.clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML sanitization via bleach",
		},
		{
			ID:          "py.markupsafe.markup",
			Language:    rules.LangPython,
			Pattern:     `markupsafe\.Markup\(|Markup\(`,
			ObjectType:  "markupsafe",
			MethodName:  "Markup",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "MarkupSafe Markup wrapper (marks string as safe HTML)",
		},
		{
			ID:          "py.django.strip_tags",
			Language:    rules.LangPython,
			Pattern:     `strip_tags\(|django\.utils\.html\.strip_tags\(`,
			ObjectType:  "django.utils.html",
			MethodName:  "strip_tags",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Django HTML tag stripping for XSS prevention",
		},
		{
			ID:          "py.int",
			Language:    rules.LangPython,
			Pattern:     `int\(`,
			ObjectType:  "",
			MethodName:  "int",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Integer conversion (restricts to numeric values)",
		},
		{
			ID:          "py.shlex.quote",
			Language:    rules.LangPython,
			Pattern:     `shlex\.quote\(`,
			ObjectType:  "",
			MethodName:  "shlex.quote",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Shell argument quoting for safe command execution",
		},
		{
			ID:          "py.os.path.basename",
			Language:    rules.LangPython,
			Pattern:     `os\.path\.basename\(`,
			ObjectType:  "",
			MethodName:  "os.path.basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract base filename (strips directory traversal)",
		},
		{
			ID:          "py.parameterized",
			Language:    rules.LangPython,
			Pattern:     `%s.*\(.*,`,
			ObjectType:  "cursor",
			MethodName:  "parameterized query",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Parameterized SQL query via cursor.execute with placeholders",
		},
		{
			ID:          "py.quote_plus",
			Language:    rules.LangPython,
			Pattern:     `urllib\.parse\.quote_plus\(`,
			ObjectType:  "",
			MethodName:  "quote_plus",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "URL encoding for safe inclusion in URLs and HTML",
		},
		{
			ID:          "py.yaml.safeloader",
			Language:    rules.LangPython,
			Pattern:     `yaml\.safe_load\(|yaml\.load\(.*Loader=yaml\.SafeLoader`,
			ObjectType:  "",
			MethodName:  "yaml.safe_load",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Safe YAML loading (disables arbitrary object construction)",
		},
		{
			ID:          "py.django.escapers",
			Language:    rules.LangPython,
			Pattern:     `force_escape|escapejs|urlencode`,
			ObjectType:  "",
			MethodName:  "Django escape filters",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Django template escape filters",
		},
		{
			ID:       "py.validators",
			Language: rules.LangPython,
			Pattern:  `validate\(|is_valid\(|clean\(`,
			ObjectType: "",
			MethodName:  "validate/is_valid/clean",
			Neutralizes: []taint.SinkCategory{
				taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite,
				taint.SnkHTMLOutput, taint.SnkRedirect,
			},
			Description: "General validation methods (effectiveness varies)",
		},

		// --- SQLAlchemy parameterized binding ---
		{
			ID:          "py.sqlalchemy.bindparams",
			Language:    rules.LangPython,
			Pattern:     `\.params\(|bindparam\(`,
			ObjectType:  "sqlalchemy",
			MethodName:  "params/bindparam",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLAlchemy bound parameter binding (prevents SQL injection)",
		},

		// --- Jinja2 autoescaping ---
		{
			ID:          "py.jinja2.autoescape",
			Language:    rules.LangPython,
			Pattern:     `autoescape\s*=\s*True|autoescape=select_autoescape`,
			ObjectType:  "jinja2",
			MethodName:  "autoescape=True",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Jinja2 autoescaping enabled (prevents XSS in templates)",
		},

		// --- Secrets module (cryptographically secure) ---
		{
			ID:          "py.secrets",
			Language:    rules.LangPython,
			Pattern:     `secrets\.token_hex\(|secrets\.token_urlsafe\(|secrets\.token_bytes\(`,
			ObjectType:  "secrets",
			MethodName:  "secrets.token_*",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random via secrets module",
		},

		// --- defusedxml safe parser ---
		{
			ID:          "py.defusedxml",
			Language:    rules.LangPython,
			Pattern:     `defusedxml\.\w+\.parse\(|defusedxml\.\w+\.fromstring\(`,
			ObjectType:  "defusedxml",
			MethodName:  "defusedxml.parse/fromstring",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Safe XML parsing via defusedxml (prevents XXE attacks)",
		},

		// --- Django conditional_escape ---
		{
			ID:          "py.django.conditional_escape",
			Language:    rules.LangPython,
			Pattern:     `conditional_escape\(`,
			ObjectType:  "django.utils.html",
			MethodName:  "conditional_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Django conditional HTML escaping for safe output",
		},

		// --- Crypto / Auth Sanitizers ---
		{
			ID:          "py.crypto.bcrypt.hashpw",
			Language:    rules.LangPython,
			Pattern:     `bcrypt\.hashpw\(|bcrypt\.gensalt\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt.hashpw",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password hashing (safe password storage)",
		},
		{
			ID:          "py.crypto.bcrypt.checkpw",
			Language:    rules.LangPython,
			Pattern:     `bcrypt\.checkpw\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt.checkpw",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password verification (constant-time comparison)",
		},
		{
			ID:          "py.crypto.argon2",
			Language:    rules.LangPython,
			Pattern:     `argon2\.PasswordHasher\(|\.hash\(|\.verify\(`,
			ObjectType:  "argon2",
			MethodName:  "argon2.PasswordHasher",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 password hashing (safe password storage)",
		},
		{
			ID:          "py.crypto.hmac.compare_digest",
			Language:    rules.LangPython,
			Pattern:     `hmac\.compare_digest\(`,
			ObjectType:  "hmac",
			MethodName:  "hmac.compare_digest",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Constant-time HMAC comparison (prevents timing attacks)",
		},
		{
			ID:          "py.django.csrf_protect",
			Language:    rules.LangPython,
			Pattern:     `@csrf_protect|csrf_token|CsrfViewMiddleware`,
			ObjectType:  "django.middleware.csrf",
			MethodName:  "csrf_protect",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Django CSRF protection middleware/decorator",
		},

		// --- Input validation sanitizers (CWE-20) ---
		{
			ID:          "py.pydantic.parse",
			Language:    rules.LangPython,
			Pattern:     `\.parse_obj\(|\.model_validate\(|BaseModel`,
			ObjectType:  "pydantic",
			MethodName:  "parse_obj/model_validate",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "Pydantic model validation and parsing (input validation)",
		},
		{
			ID:          "py.marshmallow.load",
			Language:    rules.LangPython,
			Pattern:     `\.load\s*\(|Schema\(\)\.dump\(`,
			ObjectType:  "marshmallow",
			MethodName:  "Schema.load",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Marshmallow schema deserialization and validation",
		},
		{
			ID:          "py.wtforms.validate",
			Language:    rules.LangPython,
			Pattern:     `form\.validate\(|form\.validate_on_submit\(|wtforms\.\w+Field`,
			ObjectType:  "wtforms",
			MethodName:  "form.validate",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "WTForms form validation",
		},
		{
			ID:          "py.cerberus.validate",
			Language:    rules.LangPython,
			Pattern:     `Validator\s*\([^)]*\)\s*\.validate\s*\(`,
			ObjectType:  "cerberus",
			MethodName:  "Validator.validate",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Cerberus schema validation",
		},

		// --- Infrastructure / Network Sanitizers ---
		{
			ID:          "py.ipaddress.validate",
			Language:    rules.LangPython,
			Pattern:     `ipaddress\.ip_address\(|ipaddress\.ip_network\(`,
			ObjectType:  "ipaddress",
			MethodName:  "ip_address/ip_network",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address validation and parsing (SSRF prevention)",
		},
		{
			ID:          "py.validators.url",
			Language:    rules.LangPython,
			Pattern:     `validators\.url\(|URLValidator\(`,
			ObjectType:  "validators",
			MethodName:  "validators.url/URLValidator",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL format validation via validators library or Django URLValidator",
		},

		// --- Path resolution sanitizers ---
		{
			ID:          "py.os.path.realpath",
			Language:    rules.LangPython,
			Pattern:     `os\.path\.realpath\(|os\.path\.abspath\(`,
			ObjectType:  "",
			MethodName:  "os.path.realpath/abspath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path resolution to absolute path (prevents relative path traversal)",
		},
		{
			ID:          "py.pathlib.resolve",
			Language:    rules.LangPython,
			Pattern:     `\.resolve\(\)`,
			ObjectType:  "pathlib.Path",
			MethodName:  "resolve",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Pathlib path resolution (resolves symlinks and relative components)",
		},

		// --- Regex escaping ---
		{
			ID:          "py.re.escape",
			Language:    rules.LangPython,
			Pattern:     `re\.escape\(`,
			ObjectType:  "",
			MethodName:  "re.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex metacharacter escaping (prevents ReDoS and injection in regex patterns)",
		},

		// --- Float conversion ---
		{
			ID:          "py.float",
			Language:    rules.LangPython,
			Pattern:     `float\(`,
			ObjectType:  "",
			MethodName:  "float",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Float conversion (restricts to numeric values)",
		},

		// --- Django escape ---
		{
			ID:          "py.django.escape",
			Language:    rules.LangPython,
			Pattern:     `django\.utils\.html\.escape\(`,
			ObjectType:  "django.utils.html",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Django HTML escaping function",
		},

		// --- DRF serializer.is_valid ---
		{
			ID:          "py.drf.serializer.is_valid",
			Language:    rules.LangPython,
			Pattern:     `serializer\.is_valid\(`,
			ObjectType:  "rest_framework.serializers",
			MethodName:  "is_valid",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Django REST Framework serializer validation",
		},

		// --- Pydantic model_validate / validator ---
		{
			ID:          "py.pydantic.validator",
			Language:    rules.LangPython,
			Pattern:     `@validator\(|@field_validator\(`,
			ObjectType:  "pydantic",
			MethodName:  "validator/field_validator",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "Pydantic field validator decorator",
		},

		// --- re.match for whitelist validation ---
		{
			ID:          "py.re.match.whitelist",
			Language:    rules.LangPython,
			Pattern:     `re\.match\(.*\^\[`,
			ObjectType:  "",
			MethodName:  "re.match (whitelist)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Regex whitelist match validation",
		},

		// --- os.path.normpath ---
		{
			ID:          "py.os.path.normpath",
			Language:    rules.LangPython,
			Pattern:     `os\.path\.normpath\(`,
			ObjectType:  "",
			MethodName:  "os.path.normpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path normalization (resolves double dots and slashes)",
		},

		// --- werkzeug secure_filename ---
		{
			ID:          "py.werkzeug.secure_filename",
			Language:    rules.LangPython,
			Pattern:     `secure_filename\(`,
			ObjectType:  "werkzeug.utils",
			MethodName:  "secure_filename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Werkzeug secure filename sanitization (strips path separators)",
		},

		// --- urllib.parse.quote ---
		{
			ID:          "py.urllib.parse.quote",
			Language:    rules.LangPython,
			Pattern:     `urllib\.parse\.quote\(`,
			ObjectType:  "",
			MethodName:  "urllib.parse.quote",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput, taint.SnkURLFetch},
			Description: "URL percent-encoding for safe URL construction",
		},

		// --- str() conversion ---
		{
			ID:          "py.str",
			Language:    rules.LangPython,
			Pattern:     `str\(`,
			ObjectType:  "",
			MethodName:  "str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String conversion (may limit injection in numeric contexts)",
		},

		// --- nh3 sanitizer ---
		{
			ID:          "py.nh3.clean",
			Language:    rules.LangPython,
			Pattern:     `nh3\.clean\(`,
			ObjectType:  "nh3",
			MethodName:  "clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "nh3 HTML sanitizer (Rust-based, successor to bleach)",
		},
	}
}
