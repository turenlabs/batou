package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *PythonCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		{
			ID:          "py.html.escape",
			Language:    rules.LangPython,
			Pattern:     `html\.escape\(|\bescape\(|markupsafe\.escape\(`,
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
			Pattern:     `\bint\(`,
			ObjectType:  "",
			MethodName:  "int",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL, taint.SnkCommand, taint.SnkURLFetch, taint.SnkTrustBoundary},
			Description: "Integer conversion (restricts to numeric values, eliminates URL/injection strings — a coerced int carries no trust-boundary payload)",
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
		// shlex.join (Python 3.8+) is the canonical companion to shlex.quote:
		// it shell-escapes every element of a token list and joins them into a
		// single safe command string (shlex.join(["ls", user]) -> "ls 'user'").
		// Scoped to ObjectType "shlex" so the bare method name "join" cannot
		// match unrelated str / os.path joins.
		{
			ID:          "py.shlex.join",
			Language:    rules.LangPython,
			Pattern:     `shlex\.join\(`,
			ObjectType:  "shlex",
			MethodName:  "join",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "shlex.join shell-escapes each list element into a safe command string (stdlib companion to shlex.quote)",
		},
		// PyMySQL / mysqlclient (MySQLdb) escape_string() escapes special
		// characters for a MySQL string literal — the Python analogue of PHP's
		// mysqli_real_escape_string (already modeled as a sanitizer). Callable
		// both as a module function (pymysql.escape_string(x)) and as a
		// connection method (conn.escape_string(x)); ObjectType "" covers both
		// receivers and the method name is MySQL-specific enough to avoid FPs.
		{
			ID:          "py.mysql.escape_string",
			Language:    rules.LangPython,
			Pattern:     `\.escape_string\s*\(|\bescape_string\s*\(`,
			ObjectType:  "",
			MethodName:  "escape_string",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PyMySQL/mysqlclient escape_string() escapes user input for MySQL string literals",
		},
		{
			ID:          "py.os.path.basename",
			Language:    rules.LangPython,
			Pattern:     `os\.path\.basename\(`,
			ObjectType:  "",
			MethodName:  "os.path.basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract base filename (strips directory traversal)",
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
		// yaml.load(..., Loader=yaml.SafeLoader) is equivalent to safe_load —
		// PyYAML's SafeLoader rejects the !!python/object/apply construction
		// that drives CVE-2017-18342. The base method name "load" collides
		// with many other sinks, so we gate via @argpattern on the call text
		// (must contain `Loader=` referencing a known-safe loader). This
		// neutralises the sink only when the loader is explicit; bare
		// `yaml.load(body)` still flows to py.yaml.load.
		{
			ID:          "py.yaml.load.safe_loader",
			Language:    rules.LangPython,
			Pattern:     `yaml\.load\s*\([^)]*Loader\s*=\s*(yaml\.)?(SafeLoader|CSafeLoader|BaseLoader|CBaseLoader)`,
			ObjectType:  "@argpattern",
			MethodName:  "load",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "yaml.load with explicit SafeLoader/BaseLoader Loader= kwarg (cannot construct arbitrary Python objects)",
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
		// --- Django template auto-escape (PR-CAT2py) ---
		// Django templates auto-escape by default — the rendered output of
		// `render_to_string(name, ctx)` / `render_to_response(name, ctx)` /
		// `render(request, name, ctx)` HTML-escapes every variable
		// substitution unless the template author explicitly uses
		// `mark_safe(...)` or the `|safe` filter inside the template (which
		// Batou cannot see from the call site). Recording the call shape as
		// a SnkHTMLOutput sanitizer keeps the safe-default path quiet
		// without sacrificing detection of the unsafe `mark_safe(user_input)`
		// pattern (still flagged by BATOU-XSS-* regex rules and the
		// per-language taint engine when the caller's context dict contains
		// a `mark_safe(...)` value).
		//
		// Why not also cover template-name injection? Tainted template
		// names are a separate concern (CWE-1336 SSTI) and Batou's
		// `template` rules / Jinja from_string sink already cover the
		// dangerous shape; making render_to_string a SnkTemplate sink here
		// would re-introduce the very flood of cross-file false positives
		// this entry removes.
		{
			ID:          "py.django.render.autoescape",
			Language:    rules.LangPython,
			Pattern:     `render_to_string\s*\(|render_to_response\s*\(|django\.shortcuts\.render\s*\(`,
			ObjectType:  "",
			MethodName:  "render_to_string/render_to_response/django.shortcuts.render",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Django template rendering — context variables are auto-escaped by default (mark_safe / |safe must be opted into explicitly inside the template)",
		},
		// Generic validate/is_valid/clean calls verify shape or schema;
		// they do not escape SQL, shell, or HTML metacharacters. Only the
		// trust boundary is protected (mass-assignment / field whitelist).
		{
			ID:          "py.validators",
			Language:    rules.LangPython,
			Pattern:     `\bvalidate\(|\bis_valid\(|\bclean\(`,
			ObjectType:  "",
			MethodName:  "validate/is_valid/clean",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "General validation methods (restricts to expected shape; does not escape content)",
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

		// --- defusedcsv safe CSV writer (drop-in replacement for csv) ---
		{
			ID:          "py.defusedcsv.writer",
			Language:    rules.LangPython,
			Pattern:     `defusedcsv\.writer\s*\(`,
			ObjectType:  "defusedcsv",
			MethodName:  "defusedcsv.writer",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "defusedcsv.writer() — drop-in safe replacement for csv.writer that escapes formula-leading characters (=, +, -, @), preventing CSV/formula injection",
		},
		{
			ID:          "py.defusedcsv.dictwriter",
			Language:    rules.LangPython,
			Pattern:     `defusedcsv\.DictWriter\s*\(`,
			ObjectType:  "defusedcsv",
			MethodName:  "defusedcsv.DictWriter",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "defusedcsv.DictWriter() — drop-in safe replacement for csv.DictWriter that escapes formula-leading characters (=, +, -, @), preventing CSV/formula injection",
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
		// Schema/type validators check shape, not content. They defend
		// against mass-assignment (trust boundary) but do NOT escape SQL,
		// shell, or HTML metacharacters — a str field can still contain
		// "'; DROP TABLE users;--" and pass validation.
		{
			ID:          "py.pydantic.parse",
			Language:    rules.LangPython,
			Pattern:     `\.parse_obj\(|\.model_validate\(|BaseModel`,
			ObjectType:  "pydantic",
			MethodName:  "parse_obj/model_validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Pydantic model validation (restricts fields to schema; does not escape content)",
		},
		{
			ID:          "py.marshmallow.load",
			Language:    rules.LangPython,
			Pattern:     `\.load\s*\(|Schema\(\)\.dump\(`,
			ObjectType:  "marshmallow",
			MethodName:  "Schema.load",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Marshmallow schema validation (restricts fields to schema; does not escape content)",
		},
		{
			ID:          "py.wtforms.validate",
			Language:    rules.LangPython,
			Pattern:     `form\.validate\(|form\.validate_on_submit\(|wtforms\.\w+Field`,
			ObjectType:  "wtforms",
			MethodName:  "form.validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "WTForms field validation (restricts fields to form schema; does not escape content)",
		},
		{
			ID:          "py.cerberus.validate",
			Language:    rules.LangPython,
			Pattern:     `Validator\s*\([^)]*\)\s*\.validate\s*\(`,
			ObjectType:  "cerberus",
			MethodName:  "Validator.validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Cerberus schema validation (restricts fields to schema; does not escape content)",
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
		// NOTE: os.path.normpath, os.path.realpath/abspath, and pathlib.Path.resolve()
		// are intentionally NOT registered as standalone sanitizers (PR-HHpy, mirrors Go's PR-HH).
		//
		// Each of these only canonicalizes a path; none of them rejects an escape:
		//   - normpath("../../etc/passwd")  → "../../etc/passwd"
		//   - realpath("../../etc/passwd")  → "/etc/passwd" (real, but outside the safe base!)
		//   - Path("../etc").resolve()     → "/etc" (same)
		// A complete CWE-22 defence requires a containment check on the result:
		//   - normpath(x).startswith(BASE)
		//   - Path(BASE).joinpath(x).resolve().is_relative_to(BASE)  (Py 3.9+)
		//   - os.path.commonpath([BASE, x]) == BASE
		//   - PurePosixPath(x).is_absolute() == False  (negative guard)
		// These combos are recognised by inferPythonPathGuardCategories in the
		// tsflow walker (Python guard-pattern matcher).

		// --- pathlib .resolve().relative_to(BASE) containment (CWE-22) ---
		// The canonical Python containment idiom that completes a resolve():
		//
		//   file_path = unresolved.resolve()
		//   file_path.relative_to(base)        # raises ValueError if outside base
		//   ... open(file_path)                # safe — escape already rejected
		//
		// Unlike `is_relative_to` (a bool predicate, Py 3.9+, already handled as
		// an if-guard), `relative_to` is called for its SIDE EFFECT: it raises
		// ValueError when the path escapes `base`, and that exception is caught
		// in a surrounding `try/except (ValueError, ...)` that returns 404. The
		// guard appears as a *bare expression statement* (its result discarded),
		// not an if-condition, so inferPythonPathGuard (if-only) never sees it.
		// The tsflow walker recognises this bare-statement form via
		// pyMatchBareStatementPathGuard and clears the path categories on the
		// receiver; this catalog entry documents the idiom and indexes the
		// `relative_to` / `realpath` method names for the matcher. Anchored via
		// @argpattern to the chained `.resolve().relative_to(` /
		// `realpath(...).startswith(` forms so it cannot fire on an unrelated
		// `relative_to` on a non-canonicalised value.
		{
			ID:          "py.pathlib.resolve.relative_to",
			Language:    rules.LangPython,
			Pattern:     `\.resolve\(\)\s*\.relative_to\(|os\.path\.realpath\([^)]*\)\.startswith\(|\brealpath\([^)]*\)\.startswith\(`,
			ObjectType:  "@argpattern",
			MethodName:  "relative_to/realpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite, taint.SnkUpload},
			Description: "pathlib Path.resolve().relative_to(base) / os.path.realpath(x).startswith(base) — canonical CWE-22 containment check (relative_to raises ValueError on escape; the realpath+startswith pair rejects paths outside base)",
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
			Pattern:     `\bfloat\(`,
			ObjectType:  "",
			MethodName:  "float",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkURLFetch},
			Description: "Float conversion (restricts to numeric values, eliminates URL strings)",
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
		// Decorator only signals that a custom validator runs; it does not
		// imply the field is escaped for any injection sink. Treat as a
		// trust boundary marker only.
		{
			ID:          "py.pydantic.validator",
			Language:    rules.LangPython,
			Pattern:     `@validator\(|@field_validator\(`,
			ObjectType:  "pydantic",
			MethodName:  "validator/field_validator",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Pydantic field validator decorator (custom validation; does not imply content escape)",
		},

		// --- re.match for whitelist validation ---
		{
			ID:          "py.re.match.whitelist",
			Language:    rules.LangPython,
			Pattern:     `re\.match\(.*\^\[`,
			ObjectType:  "",
			MethodName:  "re.match (whitelist)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkURLFetch},
			Description: "Regex whitelist match validation",
		},

		// --- os.path.normpath ---
		// NOT a standalone sanitizer — normpath("../etc/passwd") returns the
		// same string; it only collapses .. lexically without rejecting escapes.
		// See the path-resolution comment block above; the combo
		// `normpath(x).startswith(BASE)` is recognised by
		// inferPythonPathGuardCategories in the tsflow walker.

		// --- werkzeug secure_filename ---
		// ObjectType left empty so the matcher accepts both the bare
		// `secure_filename(x)` form (typical: `from werkzeug.utils import
		// secure_filename`) and the qualified `werkzeug.utils.secure_filename(x)`
		// form. The previous ObjectType "werkzeug.utils" required the call
		// receiver to literally be "werkzeug" or "utils", which never matches
		// the standard import-and-call shape.
		{
			ID:          "py.werkzeug.secure_filename",
			Language:    rules.LangPython,
			Pattern:     `secure_filename\(`,
			ObjectType:  "",
			MethodName:  "secure_filename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead, taint.SnkUpload},
			Description: "Werkzeug secure filename sanitization (strips path separators and unsafe chars from an uploaded file's name)",
		},

		// --- pathvalidate ---
		// pathvalidate.sanitize_filepath / sanitize_filename strip path-traversal
		// sequences and platform-invalid characters, returning a value safe to
		// use as a filename/path component. Both are complete sanitizers for
		// CWE-22 / CWE-434 (no guard required). ObjectType is left empty so
		// the matcher accepts both bare-name `sanitize_filepath(x)` (after
		// `from pathvalidate import ...`) and qualified
		// `pathvalidate.sanitize_filepath(x)` usage.
		{
			ID:          "py.pathvalidate.sanitize_filepath",
			Language:    rules.LangPython,
			Pattern:     `pathvalidate\.sanitize_filepath\s*\(|sanitize_filepath\s*\(`,
			ObjectType:  "",
			MethodName:  "sanitize_filepath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead, taint.SnkUpload},
			Description: "pathvalidate.sanitize_filepath strips invalid/traversal characters from a file path (CWE-22 mitigation)",
		},
		{
			ID:          "py.pathvalidate.sanitize_filename",
			Language:    rules.LangPython,
			Pattern:     `pathvalidate\.sanitize_filename\s*\(|sanitize_filename\s*\(`,
			ObjectType:  "",
			MethodName:  "sanitize_filename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead, taint.SnkUpload},
			Description: "pathvalidate.sanitize_filename strips invalid/traversal characters from a filename (CWE-22 / CWE-434 mitigation)",
		},

		// --- Uploaded-file content/type validation (CWE-434 defenses) ---
		// Detecting the real MIME type / image format from the uploaded bytes
		// (rather than trusting the client-supplied filename or Content-Type)
		// and rejecting non-allowlisted types neutralizes unrestricted-upload
		// taint flows.
		{
			ID:          "py.magic.from_buffer",
			Language:    rules.LangPython,
			Pattern:     `magic\.from_buffer\s*\(|magic\.Magic\s*\(`,
			ObjectType:  "magic",
			MethodName:  "magic.from_buffer/magic.Magic",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "python-magic libmagic content sniffing — detects the true MIME type of uploaded bytes (defends unrestricted file upload when paired with an allowlist)",
		},
		{
			ID:          "py.imghdr.what",
			Language:    rules.LangPython,
			Pattern:     `imghdr\.what\s*\(`,
			ObjectType:  "imghdr",
			MethodName:  "imghdr.what",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "imghdr.what() — detects the real image format of uploaded bytes (defends unrestricted file upload when paired with an allowlist)",
		},

		// --- Flask send_from_directory (safe file serving) ---
		{
			ID:          "py.flask.send_from_directory",
			Language:    rules.LangPython,
			Pattern:     `send_from_directory\(`,
			ObjectType:  "flask",
			MethodName:  "send_from_directory",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Flask send_from_directory uses safe_join to prevent path traversal",
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
			Pattern:     `\bstr\(`,
			ObjectType:  "",
			MethodName:  "str",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "String coercion — defeats NoSQL operator injection (a dict like {\"$ne\": null} becomes the literal string \"{'$ne': None}\"). Does NOT neutralize SQL or command injection: str() of an already-string payload is the identity, so the injection survives unchanged.",
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
		{
			ID:          "py.nh3.clean_text",
			Language:    rules.LangPython,
			Pattern:     `nh3\.clean_text\s*\(`,
			ObjectType:  "nh3",
			MethodName:  "clean_text",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "nh3 clean_text() HTML-escapes a string for safe text embedding (XSS)",
		},
		{
			ID:          "py.lxml.clean_html",
			Language:    rules.LangPython,
			Pattern:     `\.clean_html\s*\(|\bclean_html\s*\(`,
			ObjectType:  "",
			MethodName:  "clean_html",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "lxml.html.clean Cleaner.clean_html()/clean_html() strips dangerous markup (XSS)",
		},

		// --- Peewee ORM sanitizers ---
		{
			ID:          "py.peewee.fn",
			Language:    rules.LangPython,
			Pattern:     `\bfn\.\w+\(`,
			ObjectType:  "peewee",
			MethodName:  "fn.*",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Peewee fn.param() parameterized function calls (prevents SQL injection)",
		},
		{
			ID:          "py.peewee.parameterized",
			Language:    rules.LangPython,
			Pattern:     `\.SQL\([^,]+,\s*\[`,
			ObjectType:  "peewee",
			MethodName:  "SQL with params",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Peewee SQL() with parameter list (prevents SQL injection)",
		},
		{
			ID:          "py.peewee.where",
			Language:    rules.LangPython,
			Pattern:     `\.where\(.*==`,
			ObjectType:  "peewee",
			MethodName:  "where",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Peewee Model.select().where() query builder (parameterized)",
		},

		// --- Tortoise ORM sanitizers ---
		{
			ID:          "py.tortoise.filter",
			Language:    rules.LangPython,
			Pattern:     `\.filter\(`,
			ObjectType:  "tortoise",
			MethodName:  "filter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Tortoise ORM Model.filter() queryset (parameterized, prevents SQL injection)",
		},
		{
			ID:          "py.tortoise.parameterized",
			Language:    rules.LangPython,
			Pattern:     `execute_query\([^,]+,\s*\[`,
			ObjectType:  "tortoise",
			MethodName:  "execute_query with params",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Tortoise ORM execute_query() with parameter list (prevents SQL injection)",
		},

		// --- Header injection sanitizers (CWE-113) ---
		{
			ID:          "py.email.formataddr",
			Language:    rules.LangPython,
			Pattern:     `email\.utils\.formataddr\s*\(`,
			ObjectType:  "email.utils",
			MethodName:  "formataddr",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Safe email header address formatting (RFC 2822 compliant)",
		},

		// --- LDAP injection sanitizers (CWE-90) ---
		{
			ID:          "py.ldap.escape_filter_chars",
			Language:    rules.LangPython,
			Pattern:     `ldap\.filter\.escape_filter_chars\s*\(`,
			ObjectType:  "ldap.filter",
			MethodName:  "escape_filter_chars",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "python-ldap LDAP filter character escaping (prevents LDAP injection)",
		},
		{
			ID:          "py.ldap.escape_dn_chars",
			Language:    rules.LangPython,
			Pattern:     `ldap\.dn\.escape_dn_chars\s*\(`,
			ObjectType:  "ldap.dn",
			MethodName:  "escape_dn_chars",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "python-ldap DN component escaping (prevents LDAP DN injection)",
		},
		{
			ID:          "py.ldap3.escape",
			Language:    rules.LangPython,
			Pattern:     `ldap3\.utils\.\w+\.escape_\w+\s*\(`,
			ObjectType:  "ldap3.utils",
			MethodName:  "escape_filter_chars/escape_rdn",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "ldap3 library filter/DN escaping functions",
		},

		// --- Log injection sanitizers (CWE-117) ---
		{
			ID:          "py.structlog.logger",
			Language:    rules.LangPython,
			Pattern:     `structlog\.get_logger\s*\(|structlog\.wrap_logger\s*\(`,
			ObjectType:  "structlog",
			MethodName:  "get_logger/wrap_logger",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "structlog structured logging (key-value binding prevents log injection)",
		},
		{
			ID:          "py.json.dumps",
			Language:    rules.LangPython,
			Pattern:     `json\.dumps\s*\(`,
			ObjectType:  "json",
			MethodName:  "dumps",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "JSON serialization (escapes newlines and control characters)",
		},

		// --- Trust boundary sanitizers (CWE-501) ---
		{
			ID:          "py.django.cleaned_data",
			Language:    rules.LangPython,
			Pattern:     `\.cleaned_data\s*\[`,
			ObjectType:  "django.forms",
			MethodName:  "cleaned_data",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Django form validated/cleaned data (safe for session storage)",
		},
		{
			ID:          "py.itsdangerous.serializer",
			Language:    rules.LangPython,
			Pattern:     `itsdangerous\.\w+Serializer\s*\(`,
			ObjectType:  "itsdangerous",
			MethodName:  "URLSafeSerializer/TimedSerializer",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "itsdangerous signed serializer (cryptographic integrity for session data)",
		},
		// Server-generated tokens stored in the session ARE NOT a trust
		// boundary risk: the value never came from the user. Sentry's
		// `sudo.utils:50` (request.session[k] = get_random_string(12))
		// and `auth.py:165` (request.session["_next"] = next_url where
		// next_url has been validated by is_valid_redirect()) were the
		// motivating false positives — see PR-CAT3py write-up.
		{
			ID:          "py.trust.secrets.token",
			Language:    rules.LangPython,
			Pattern:     `secrets\.token_(?:hex|bytes|urlsafe)\s*\(`,
			ObjectType:  "secrets",
			MethodName:  "token_hex/token_bytes/token_urlsafe",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "secrets.token_*() — cryptographically secure server-generated token (safe for session storage; not user-influenced)",
		},
		{
			ID:          "py.trust.uuid",
			Language:    rules.LangPython,
			Pattern:     `uuid\.uuid[14]\s*\(`,
			ObjectType:  "uuid",
			MethodName:  "uuid.uuid1/uuid4",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "uuid.uuid1/uuid4() — server-generated UUID identifier (safe for session storage; not user-influenced)",
		},
		{
			ID:          "py.trust.os.urandom",
			Language:    rules.LangPython,
			Pattern:     `os\.urandom\s*\(`,
			ObjectType:  "os",
			MethodName:  "urandom",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "os.urandom() — OS cryptographic random bytes (safe for session storage; not user-influenced)",
		},
		{
			ID:          "py.trust.hashlib.hexdigest",
			Language:    rules.LangPython,
			Pattern:     `hashlib\.\w+\([^)]*\)\.hexdigest\s*\(\s*\)`,
			ObjectType:  "hashlib",
			MethodName:  "hexdigest",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "hashlib.<algo>(...).hexdigest() — server-computed hex digest (safe for session storage; even with tainted input the digest is fixed-shape hex)",
		},
		{
			ID:          "py.trust.hmac.hexdigest",
			Language:    rules.LangPython,
			Pattern:     `hmac\.(?:new|HMAC)\([^)]*\)\.hexdigest\s*\(\s*\)`,
			ObjectType:  "hmac",
			MethodName:  "hexdigest",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "hmac.new(...).hexdigest() — server-computed HMAC digest (safe for session storage; the secret key gates integrity)",
		},
		{
			ID:          "py.trust.jwt.encode",
			Language:    rules.LangPython,
			Pattern:     `jwt\.encode\s*\(`,
			ObjectType:  "jwt",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "jwt.encode() — server-signed JWT (HMAC/RS256 by SECRET_KEY; safe for session storage)",
		},
		{
			ID:          "py.trust.django.signing",
			Language:    rules.LangPython,
			Pattern:     `signing\.(?:dumps|TimestampSigner|Signer)\s*\(`,
			ObjectType:  "django.core.signing",
			MethodName:  "signing.dumps/TimestampSigner/Signer",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "django.core.signing.dumps/TimestampSigner/Signer — server-signed payload bound to SECRET_KEY (safe for session storage)",
		},
		{
			ID:          "py.trust.django.get_random_string",
			Language:    rules.LangPython,
			Pattern:     `get_random_string\s*\(`,
			ObjectType:  "django.utils.crypto",
			MethodName:  "get_random_string",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "django.utils.crypto.get_random_string() — server-generated random token (safe for session storage; not user-influenced)",
		},
		{
			ID:          "py.trust.is_valid_redirect",
			Language:    rules.LangPython,
			Pattern:     `is_valid_redirect\s*\(|url_has_allowed_host_and_scheme\s*\(|is_safe_url\s*\(`,
			ObjectType:  "",
			MethodName:  "is_valid_redirect/url_has_allowed_host_and_scheme/is_safe_url",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkRedirect},
			Description: "is_valid_redirect / url_has_allowed_host_and_scheme / is_safe_url — host-allowlist validation (safe to store as session next_url and to redirect to)",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "py.bson.objectid",
			Language:    rules.LangPython,
			Pattern:     `(?:bson\.)?ObjectId\s*\(`,
			ObjectType:  "bson",
			MethodName:  "ObjectId",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL, taint.SnkURLFetch},
			Description: "BSON ObjectId conversion (validates and converts to safe 24-hex-char ObjectId type, preventing NoSQL and SSRF injection)",
		},

		// --- Log injection sanitizers (CWE-117) ---
		{
			ID:          "py.log.crlf.replace",
			Language:    rules.LangPython,
			Pattern:     `\.replace\s*\(\s*['"]\\[rn]['"]|\.replace\s*\(\s*['"]\\r\\n['"]|re\.sub\s*\(\s*r?['"]\[\\[rn]\]+|translate\s*\(\s*\{?\s*(?:ord\s*\(\s*['"]\\[rn]['"]|10\s*:|13\s*:)`,
			ObjectType:  "",
			MethodName:  "replace/sub CRLF",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "CRLF stripping before logging (prevents log injection / log forging)",
		},
		{
			ID:          "py.log.structlog.bind",
			Language:    rules.LangPython,
			Pattern:     `structlog\.get_logger\s*\(.*\)\.bind\s*\(|logger\.bind\s*\(`,
			ObjectType:  "structlog",
			MethodName:  "bind",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Structlog key-value binding (safer than format string interpolation for logs)",
		},
		{
			ID:          "py.log.repr",
			Language:    rules.LangPython,
			Pattern:     `\brepr\s*\(`,
			ObjectType:  "",
			MethodName:  "repr",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "repr() escapes control characters including CRLF (safe for log output)",
		},
		{
			ID:          "py.log.json.dumps",
			Language:    rules.LangPython,
			Pattern:     `json\.dumps\s*\(`,
			ObjectType:  "json",
			MethodName:  "dumps",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "JSON encoding escapes control characters (safe for structured logs)",
		},

		// --- XPath injection sanitizers (CWE-643) ---
		{
			ID:          "py.xpath.lxml.xpath.variables",
			Language:    rules.LangPython,
			Pattern:     `\.xpath\s*\([^)]*,\s*\w+\s*=`,
			ObjectType:  "lxml.etree",
			MethodName:  "xpath (with variable binding)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "lxml XPath with parameterized variable binding ($var syntax, prevents injection)",
		},
		{
			ID:          "py.xpath.quoteattr",
			Language:    rules.LangPython,
			Pattern:     `xml\.sax\.saxutils\.quoteattr\s*\(|saxutils\.quoteattr\s*\(|quoteattr\s*\(`,
			ObjectType:  "xml.sax.saxutils",
			MethodName:  "quoteattr",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XML attribute quoting (escapes quotes and special chars for XPath expressions)",
		},
		{
			ID:          "py.lxml.etree.xslt.strparam",
			Language:    rules.LangPython,
			Pattern:     `etree\.XSLT\.strparam\s*\(|XSLT\.strparam\s*\(`,
			ObjectType:  "lxml.etree.XSLT",
			MethodName:  "strparam",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "lxml XSLT.strparam wraps an untrusted string as an XPath string literal — safe to pass as an XSLT parameter without interpolation",
		},

		// --- Deserialization sanitizers (CWE-502) ---
		{
			ID:          "py.deser.hmac.verify",
			Language:    rules.LangPython,
			Pattern:     `hmac\.compare_digest\s*\(|hmac\.HMAC\s*\(.*\)\.verify\s*\(`,
			ObjectType:  "hmac",
			MethodName:  "compare_digest/verify",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "HMAC integrity verification before deserialization (prevents forged payloads)",
		},
		{
			ID:          "py.deser.jsonschema.validate",
			Language:    rules.LangPython,
			Pattern:     `jsonschema\.validate\s*\(|fastjsonschema\.validate\s*\(`,
			ObjectType:  "jsonschema",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JSON schema validation before deserialization (enforces structure)",
		},

		// --- Eval / code injection sanitizers (CWE-94) ---
		{
			ID:          "py.eval.ast.literal_eval",
			Language:    rules.LangPython,
			Pattern:     `ast\.literal_eval\s*\(`,
			ObjectType:  "ast",
			MethodName:  "literal_eval",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "ast.literal_eval is safe evaluator (only accepts literals: strings, numbers, tuples, lists, dicts, bools, None)",
		},
		{
			ID:          "py.eval.restrictedpython",
			Language:    rules.LangPython,
			Pattern:     `RestrictedPython\.compile_restricted\s*\(|compile_restricted\s*\(`,
			ObjectType:  "RestrictedPython",
			MethodName:  "compile_restricted",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "RestrictedPython sandbox compilation (neutralizes dangerous builtins)",
		},

		// --- SSTI / template injection sanitizers (CWE-1336) ---
		{
			ID:          "py.template.jinja.sandbox",
			Language:    rules.LangPython,
			Pattern:     `jinja2\.sandbox\.SandboxedEnvironment\s*\(|SandboxedEnvironment\s*\(|ImmutableSandboxedEnvironment\s*\(`,
			ObjectType:  "jinja2.sandbox",
			MethodName:  "SandboxedEnvironment",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate},
			Description: "Jinja2 SandboxedEnvironment (blocks attribute access and unsafe operations)",
		},
		{
			ID:          "py.template.jinja.autoescape",
			Language:    rules.LangPython,
			Pattern:     `autoescape\s*=\s*(?:True|select_autoescape\s*\(|jinja2\.select_autoescape)`,
			ObjectType:  "jinja2",
			MethodName:  "autoescape=True",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Jinja2 autoescape enabled (HTML-escapes all variables by default)",
		},

		// --- HTTP header injection sanitizers (CWE-113) ---
		{
			ID:          "py.header.crlf.filter",
			Language:    rules.LangPython,
			Pattern:     `\.replace\s*\(\s*['"]\\[rn]['"]\s*,\s*['"]['"]|re\.sub\s*\(\s*r?['"]\[\\[rn]\]`,
			ObjectType:  "",
			MethodName:  "replace/sub CRLF for header",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "CRLF stripping before setting HTTP header (prevents header injection)",
		},
		{
			ID:          "py.header.werkzeug.http.http_date",
			Language:    rules.LangPython,
			Pattern:     `werkzeug\.http\.http_date\s*\(|werkzeug\.http\.dump_cookie\s*\(`,
			ObjectType:  "werkzeug.http",
			MethodName:  "http_date/dump_cookie",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Werkzeug HTTP header serializers (properly escape cookie and date values)",
		},

		// --- URL / SSRF sanitizers (CWE-918) ---
		{
			ID:          "py.ssrf.urlparse.hostname.allowlist",
			Language:    rules.LangPython,
			Pattern:     `urlparse\s*\([^)]*\)\.hostname\s+in\s+|\.hostname\s+in\s+(?:ALLOWED|WHITELIST|allowed_)`,
			ObjectType:  "urllib.parse",
			MethodName:  "urlparse().hostname allowlist",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Hostname allowlist check against parsed URL (prevents SSRF to arbitrary hosts)",
		},

		{
			ID:          "py.ssrf.urlparse.scheme.check",
			Language:    rules.LangPython,
			Pattern:     `\.scheme\s+(in|==)\s+.*https?|\.scheme\s+not\s+in`,
			ObjectType:  "urllib.parse",
			MethodName:  "urlparse().scheme check",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URL scheme validation (restricts to http/https, prevents file:// gopher:// SSRF bypass)",
		},
		{
			ID:          "py.ssrf.yarl.host.allowlist",
			Language:    rules.LangPython,
			Pattern:     `yarl\.URL\s*\([^)]*\)\.host\s+in\s+|\.host\s+in\s+(?:ALLOWED|WHITELIST|allowed_|SAFE_)`,
			ObjectType:  "yarl",
			MethodName:  "yarl.URL().host allowlist",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Hostname allowlist check via yarl URL parsing (prevents SSRF to arbitrary hosts)",
		},
		{
			ID:          "py.ssrf.ipaddress.is_private",
			Language:    rules.LangPython,
			Pattern:     `\.is_private\b|\.is_loopback\b|\.is_reserved\b|\.is_link_local\b`,
			ObjectType:  "ipaddress",
			MethodName:  "is_private/is_loopback/is_reserved",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address classification check (prevents SSRF to internal/private networks)",
		},

		// --- Archive extraction sanitizer (CWE-22, CVE-2007-4559) ---
		{
			ID:          "py.tarfile.data_filter",
			Language:    rules.LangPython,
			Pattern:     `filter\s*=\s*['"]data['"]|\.extraction_filter\s*=\s*tarfile\.data_filter`,
			ObjectType:  "tarfile",
			MethodName:  "data_filter",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Python 3.12+ tarfile data_filter prevents path traversal in archive extraction (PEP 706)",
		},
		// --- Redirect sanitizers (CWE-601) ---
		{
			ID:          "py.redirect.django.url_has_allowed_host",
			Language:    rules.LangPython,
			Pattern:     `url_has_allowed_host_and_scheme\s*\(|is_safe_url\s*\(`,
			ObjectType:  "",
			MethodName:  "url_has_allowed_host_and_scheme/is_safe_url",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Django canonical redirect validator (checks host allowlist and scheme; is_safe_url renamed in Django 3.0)",
		},
		// --- App-level redirect validators (PR-CAT2py) ---
		// `is_valid_redirect(url, allowed_hosts=...)` is a project-local
		// convention (Sentry, Pinterest, Lyft, etc.) that wraps Django's
		// canonical url_has_allowed_host_and_scheme with an app-specific
		// allowlist. Treat it as a SnkRedirect sanitizer so flows guarded
		// by `if is_valid_redirect(next_url, allowed_hosts=ALLOWED): ...`
		// stop firing. Sentry triage attributed 4/5 open-redirect false
		// positives to this single gate.
		{
			ID:          "py.redirect.is_valid_redirect",
			Language:    rules.LangPython,
			Pattern:     `is_valid_redirect\s*\(`,
			ObjectType:  "",
			MethodName:  "is_valid_redirect",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Application-level redirect URL validator (Sentry-style is_valid_redirect / safe-host check)",
		},

		// --- Eval / code injection sanitizers (CWE-94) ---
		{
			ID:          "py.eval.simpleeval",
			Language:    rules.LangPython,
			Pattern:     `simple_eval\s*\(|SimpleEval\s*\(`,
			ObjectType:  "simpleeval",
			MethodName:  "simple_eval/SimpleEval",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "simpleeval safe expression evaluator (AST-based, only allows basic math/string ops, no imports or builtins)",
		},
		{
			ID:          "py.eval.numexpr",
			Language:    rules.LangPython,
			Pattern:     `numexpr\.evaluate\s*\(`,
			ObjectType:  "numexpr",
			MethodName:  "evaluate",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "numexpr safe numeric expression evaluator (only numeric/array operations, no code execution)",
		},

		// --- Deserialization sanitizers (CWE-502) ---
		{
			ID:          "py.deser.json.loads",
			Language:    rules.LangPython,
			Pattern:     `json\.loads?\s*\(`,
			ObjectType:  "json",
			MethodName:  "json.load/json.loads",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Safe JSON parsing (output is Python primitives only — no arbitrary code execution unlike pickle/yaml)",
		},
		{
			ID:          "py.deser.django.signing",
			Language:    rules.LangPython,
			Pattern:     `django\.core\.signing\.loads\s*\(|django\.core\.signing\.dumps\s*\(`,
			ObjectType:  "django.core.signing",
			MethodName:  "signing.loads/dumps",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Django signed serialization (HMAC-verified with SECRET_KEY before deserializing)",
		},
		{
			ID:          "py.deser.tomllib",
			Language:    rules.LangPython,
			Pattern:     `tomllib\.loads?\s*\(|toml\.loads?\s*\(`,
			ObjectType:  "tomllib",
			MethodName:  "tomllib.load/loads",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "TOML parsing (safe format — no code execution possible, stdlib since Python 3.11)",
		},

		// --- XPath injection sanitizers (CWE-643) ---
		{
			ID:          "py.xpath.saxutils.escape",
			Language:    rules.LangPython,
			Pattern:     `xml\.sax\.saxutils\.escape\s*\(|saxutils\.escape\s*\(`,
			ObjectType:  "xml.sax.saxutils",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XML special character escaping (&, <, >) for safe XPath value construction",
		},

		// --- Additional SSRF sanitizers (CWE-918) ---
		{
			ID:          "py.uuid",
			Language:    rules.LangPython,
			Pattern:     `uuid\.UUID\s*\(`,
			ObjectType:  "uuid",
			MethodName:  "UUID",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkURLFetch},
			Description: "UUID parsing — converts string to validated UUID format (32 hex chars + dashes), cannot be a URL",
		},
		{
			ID:          "py.socket.inet_aton",
			Language:    rules.LangPython,
			Pattern:     `socket\.inet_aton\s*\(`,
			ObjectType:  "socket",
			MethodName:  "inet_aton",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IPv4 address parsing — validates dotted-quad format, raises error on invalid addresses (SSRF IP validation)",
		},
		{
			ID:          "py.socket.inet_pton",
			Language:    rules.LangPython,
			Pattern:     `socket\.inet_pton\s*\(`,
			ObjectType:  "socket",
			MethodName:  "inet_pton",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address parsing (IPv4/IPv6) — strict format validation, raises error on invalid addresses (SSRF IP validation)",
		},
		{
			ID:          "py.django.validate_ipaddress",
			Language:    rules.LangPython,
			Pattern:     `validate_ipv4_address\s*\(|validate_ipv46_address\s*\(|validate_ipv6_address\s*\(`,
			ObjectType:  "django.core.validators",
			MethodName:  "validate_ipv4_address/validate_ipv46_address",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Django IP address validators — raise ValidationError on non-IP input (SSRF prevention)",
		},
		{
			ID:          "py.tldextract",
			Language:    rules.LangPython,
			Pattern:     `tldextract\.extract\s*\(`,
			ObjectType:  "tldextract",
			MethodName:  "extract",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Domain extraction via tldextract — decomposes URL into subdomain/domain/suffix for allowlist validation",
		},
		{
			ID:          "py.ssrf.netloc.allowlist",
			Language:    rules.LangPython,
			Pattern:     `\.netloc\s+in\s+|urlparse.*\.netloc\s+in\s+|urlsplit.*\.netloc\s+in\s+`,
			ObjectType:  "urllib.parse",
			MethodName:  "urlparse().netloc allowlist",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URL netloc (host:port) checked against allowlist — prevents SSRF to unauthorized hosts",
		},
		{
			ID:          "py.ssrf.ipaddress.strict",
			Language:    rules.LangPython,
			Pattern:     `ipaddress\.IPv4Address\s*\(|ipaddress\.IPv6Address\s*\(`,
			ObjectType:  "ipaddress",
			MethodName:  "IPv4Address/IPv6Address",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Strict IP version validation — rejects non-IP strings and wrong-version addresses (SSRF prevention)",
		},
		{
			ID:          "py.django.validate_email",
			Language:    rules.LangPython,
			Pattern:     `django\.core\.validators\.validate_email\s*\(|validate_email\s*\(`,
			ObjectType:  "django.core.validators",
			MethodName:  "validate_email",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Django email format validator — raises ValidationError on malformed emails (length-limited, prevents trivial header injection in mail recipients)",
		},
		{
			ID:          "py.django.validate_slug",
			Language:    rules.LangPython,
			Pattern:     `django\.core\.validators\.validate_slug\s*\(|validate_slug\s*\(`,
			ObjectType:  "django.core.validators",
			MethodName:  "validate_slug",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite, taint.SnkURLFetch, taint.SnkSQLQuery},
			Description: "Django ASCII slug validator — strict allowlist [a-zA-Z0-9_-] prevents path traversal, URL/SQL injection",
		},
		{
			ID:          "py.django.validate_unicode_slug",
			Language:    rules.LangPython,
			Pattern:     `django\.core\.validators\.validate_unicode_slug\s*\(|validate_unicode_slug\s*\(`,
			ObjectType:  "django.core.validators",
			MethodName:  "validate_unicode_slug",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite, taint.SnkURLFetch},
			Description: "Django Unicode slug validator — allowlist of Unicode word chars + hyphen, rejects path/URL metacharacters",
		},
		{
			ID:          "py.django.validate_ipv6_address",
			Language:    rules.LangPython,
			Pattern:     `django\.core\.validators\.validate_ipv6_address\s*\(|validate_ipv6_address\s*\(`,
			ObjectType:  "django.core.validators",
			MethodName:  "validate_ipv6_address",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Django IPv6 address validator — raises ValidationError on non-IPv6 input (fills gap in py.django.validate_ipaddress which only covers v4 / v46)",
		},
		{
			ID:          "py.werkzeug.security.safe_join",
			Language:    rules.LangPython,
			Pattern:     `werkzeug\.security\.safe_join\s*\(|safe_join\s*\(`,
			ObjectType:  "werkzeug.security",
			MethodName:  "safe_join",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Werkzeug safe path join — returns None on traversal attempts (../, absolute paths, Windows device names) so subsequent open() fails closed",
		},
		{
			ID:          "py.email_validator.validate_email",
			Language:    rules.LangPython,
			Pattern:     `email_validator\.validate_email\s*\(|validate_email\s*\(`,
			ObjectType:  "email_validator",
			MethodName:  "validate_email",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "email-validator (FastAPI/Pydantic EmailStr) — raises EmailNotValidError on malformed addresses, returns normalized output",
		},

		// --- psycopg sql composition (safe dynamic SQL for psycopg2/psycopg3) ---
		// psycopg.sql.Identifier and psycopg.sql.Literal wrap untrusted strings
		// for safe inclusion as identifiers (table/column names) or literals
		// in composed SQL via sql.SQL("...{}").format(...). Identifiers and
		// literals can't be parameterized via $1/%s placeholders, so this is
		// the canonical safe pattern recommended by the psycopg docs.
		// Refs: https://www.psycopg.org/docs/sql.html
		//       https://www.psycopg.org/psycopg3/docs/api/sql.html
		{
			ID:          "py.psycopg.sql.identifier",
			Language:    rules.LangPython,
			Pattern:     `psycopg2?\.sql\.Identifier\s*\(|sql\.Identifier\s*\(`,
			ObjectType:  "psycopg.sql",
			MethodName:  "Identifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "psycopg sql.Identifier — quotes/escapes a name as a SQL identifier (table/column) for safe composition with sql.SQL().format()",
		},
		{
			ID:          "py.psycopg.sql.literal",
			Language:    rules.LangPython,
			Pattern:     `psycopg2?\.sql\.Literal\s*\(|sql\.Literal\s*\(`,
			ObjectType:  "psycopg.sql",
			MethodName:  "Literal",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "psycopg sql.Literal — wraps a value with the adapter's SQL-quoting rules for safe inclusion in a composed sql.SQL() statement",
		},

		// --- python-slugify ---
		// slugify(text) returns a URL/filesystem-safe ASCII slug consisting of
		// only [a-z0-9-] (configurable). It strips path separators, traversal
		// sequences (..), null bytes, and any non-allowlisted characters, so
		// downstream open()/Path/url-join cannot escape an intended directory
		// or host component.
		// Ref: https://github.com/un33k/python-slugify
		{
			ID:          "py.python_slugify.slugify",
			Language:    rules.LangPython,
			Pattern:     `slugify\.slugify\s*\(|(?:^|[^.])\bslugify\s*\(`,
			ObjectType:  "slugify",
			MethodName:  "slugify",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite, taint.SnkURLFetch},
			Description: "python-slugify slugify() — strict ASCII slug allowlist [a-z0-9-] strips path separators, traversal, and host metacharacters",
		},

		// --- passlib password hashing/verification (CWE-916, CWE-327) ---
		// passlib is a comprehensive password hashing library widely used in
		// Django (django-allauth), Flask (Flask-Security), and FastAPI
		// (FastAPI-Users). It exposes one PasswordHash object per algorithm
		// under passlib.hash, each with a uniform `.hash(secret)` and
		// `.verify(secret, hash)` interface where the plaintext is always
		// the FIRST positional argument.
		//
		// Matcher note: the canonical passlib idiom is
		//   from passlib.hash import bcrypt  # or argon2, pbkdf2_sha256, ...
		//   bcrypt.hash(secret)
		//   bcrypt.verify(secret, stored_hash)
		// so the receiver IS the algorithm name (`bcrypt`, `argon2`, etc.).
		// The standard `bcrypt` library exposes `hashpw`/`checkpw` (already
		// covered by py.crypto.bcrypt.*) but NOT `hash`/`verify`, so these
		// new entries do not conflict with that catalog. Neutralizes
		// SnkCrypto only — bcrypt/argon2/pbkdf2 hashes are safe to log/store
		// (the whole point), but they are still attacker-controlled strings,
		// so SnkSQLQuery / SnkLog flows are intentionally not cleared.
		// Refs: https://passlib.readthedocs.io/en/stable/lib/passlib.ifc.html
		//       https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html
		{
			ID:          "py.passlib.bcrypt.hash",
			Language:    rules.LangPython,
			Pattern:     `bcrypt\.hash\s*\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt.hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.bcrypt.hash(secret) — bcrypt password hashing (memory-hard variant of blowfish; OWASP-recommended for credential storage)",
		},
		{
			ID:          "py.passlib.bcrypt.verify",
			Language:    rules.LangPython,
			Pattern:     `bcrypt\.verify\s*\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt.verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.bcrypt.verify(secret, hash) — constant-time bcrypt password verification",
		},
		{
			ID:          "py.passlib.argon2.hash",
			Language:    rules.LangPython,
			Pattern:     `argon2\.hash\s*\(`,
			ObjectType:  "argon2",
			MethodName:  "argon2.hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.argon2.hash(secret) — Argon2 password hashing (winner of Password Hashing Competition; OWASP-preferred)",
		},
		{
			ID:          "py.passlib.argon2.verify",
			Language:    rules.LangPython,
			Pattern:     `argon2\.verify\s*\(`,
			ObjectType:  "argon2",
			MethodName:  "argon2.verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.argon2.verify(secret, hash) — constant-time Argon2 password verification",
		},
		{
			ID:          "py.passlib.pbkdf2_sha256.hash",
			Language:    rules.LangPython,
			Pattern:     `pbkdf2_sha256\.hash\s*\(`,
			ObjectType:  "pbkdf2_sha256",
			MethodName:  "pbkdf2_sha256.hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.pbkdf2_sha256.hash(secret) — PBKDF2-SHA256 password hashing (FIPS-compliant alternative to bcrypt/argon2)",
		},
		{
			ID:          "py.passlib.pbkdf2_sha256.verify",
			Language:    rules.LangPython,
			Pattern:     `pbkdf2_sha256\.verify\s*\(`,
			ObjectType:  "pbkdf2_sha256",
			MethodName:  "pbkdf2_sha256.verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.pbkdf2_sha256.verify(secret, hash) — constant-time PBKDF2-SHA256 password verification",
		},
		{
			ID:          "py.passlib.pbkdf2_sha512.hash",
			Language:    rules.LangPython,
			Pattern:     `pbkdf2_sha512\.hash\s*\(`,
			ObjectType:  "pbkdf2_sha512",
			MethodName:  "pbkdf2_sha512.hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.pbkdf2_sha512.hash(secret) — PBKDF2-SHA512 password hashing (FIPS-compliant; longer hash output)",
		},
		{
			ID:          "py.passlib.pbkdf2_sha512.verify",
			Language:    rules.LangPython,
			Pattern:     `pbkdf2_sha512\.verify\s*\(`,
			ObjectType:  "pbkdf2_sha512",
			MethodName:  "pbkdf2_sha512.verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "passlib.hash.pbkdf2_sha512.verify(secret, hash) — constant-time PBKDF2-SHA512 password verification",
		},

		// --- XPath string-literal escape (CWE-643 sanitizer) ---
		// Replacing the single-quote with &apos; (or with \' / "" depending on
		// dialect) inside a string flowing into an XPath query neutralises
		// quote-break injection — that's the only metachar that escapes an
		// XPath '...' literal. Pattern matches `<var>.replace('\'', '&apos;')`
		// and a handful of equivalent forms; the method name alone is too
		// generic to register, so we rely on the pattern carrying the literal
		// single-quote + apos replacement.
		{
			ID:          "py.str.replace.xpath_apos",
			Language:    rules.LangPython,
			Pattern:     `\.replace\s*\([^)]*&apos;`,
			ObjectType:  "@argpattern",
			MethodName:  "replace",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "str.replace(\"'\", \"&apos;\") — XPath quote escape (neutralises XPath injection via the only metachar that breaks a '...' literal)",
		},

		// =================================================================
		// Mined from public MIT-licensed security-model data.
		// Final sanitizer batch.
		// =================================================================

		{
			ID:          "py.pymongo.sanitize",
			Language:    rules.LangPython,
			Pattern:     `\.sanitize\s*\(`,
			ObjectType:  "mongosanitizer.sanitizer",
			MethodName:  "sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "pymongo MongoSanitizer.sanitize() — strips NoSQL operators from a query dict",
		},
		// bson.ObjectId(hex) validates and returns a typed ObjectId. If the
		// hex is malformed pymongo raises bson.errors.InvalidId; the typed
		// ObjectId cannot smuggle a MongoDB operator into a query filter.
		{
			ID:          "py.bson.objectid",
			Language:    rules.LangPython,
			Pattern:     `\bObjectId\s*\(`,
			ObjectType:  "bson",
			MethodName:  "ObjectId",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson.ObjectId(value) constructor — validates and converts to a typed 24-hex-char ObjectId; rejects operator-injection payloads (CWE-943)",
		},
		// pymongo's bson.SON / bson.son.SON binds key/value pairs as an
		// ordered typed BSON document. Like dict→BSON in the standard
		// driver path, values are bound as typed BSON entries rather than
		// string-concatenated.
		{
			ID:          "py.bson.son",
			Language:    rules.LangPython,
			Pattern:     `\bbson\.SON\s*\(|\bSON\s*\(`,
			ObjectType:  "bson.SON",
			MethodName:  "SON",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson.SON ordered BSON document constructor — values bound as typed BSON entries (no string interpolation)",
		},
		// `re.escape(user_input)` escapes regex metacharacters before
		// embedding in a $regex MongoDB query. Without it, an attacker
		// could supply `.*` or `^admin$` to broaden the match.
		{
			ID:          "py.re.escape.nosql",
			Language:    rules.LangPython,
			Pattern:     `re\.escape\s*\(`,
			ObjectType:  "re",
			MethodName:  "re.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "re.escape — escapes regex metacharacters before embedding user input in a $regex MongoDB filter (prevents broadened-match injection)",
		},
		// Beanie / Motor / mongoengine use Pydantic models as their
		// document schema. When the validated model is passed to
		// .insert_one / .update_one its fields are bound as typed BSON,
		// not coerced into raw operator dicts.
		{
			ID:          "py.beanie.model_validate",
			Language:    rules.LangPython,
			Pattern:     `\bmodel_validate\s*\(|\.parse_obj\s*\(`,
			ObjectType:  "pydantic.BaseModel",
			MethodName:  "model_validate/parse_obj",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "Pydantic BaseModel.model_validate / parse_obj — typed-field validation prevents an attacker-supplied operator key from reaching a MongoDB filter",
		},

		// --- Header injection (CWE-93 CRLF) — strip / typed-header helpers ---
		{
			ID:          "py.header.strip_crlf",
			Language:    rules.LangPython,
			Pattern:     `\.replace\s*\(\s*['"]\\r['"]\s*,\s*['"]['"]\s*\)|\.replace\s*\(\s*['"]\\n['"]\s*,\s*['"]['"]\s*\)|re\.sub\s*\(\s*['"][^'"]*\[\\\\r\\\\n\]`,
			ObjectType:  "str",
			MethodName:  "str.replace(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Manual CR/LF stripping (str.replace('\\r', '') / .replace('\\n', '') / re.sub(r'[\\r\\n]', '', s)) — defends header / log injection (CWE-93)",
		},
		{
			ID:          "py.werkzeug.headers_typed",
			Language:    rules.LangPython,
			Pattern:     `werkzeug\.datastructures\.Headers\s*\(|EnvironHeaders\s*\(`,
			ObjectType:  "werkzeug.datastructures.Headers",
			MethodName:  "Headers/EnvironHeaders",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Werkzeug Headers / EnvironHeaders — typed multi-dict header container that rejects CR/LF on .add() / .__setitem__()",
		},
		{
			ID:          "py.email.headerregistry",
			Language:    rules.LangPython,
			Pattern:     `email\.headerregistry\.|email\.policy\.default|Address\s*\(`,
			ObjectType:  "email.headerregistry",
			MethodName:  "headerregistry",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "email.headerregistry (Python 3.6+ email package) — parses RFC-5322 headers strictly (rejects CRLF / non-printable characters)",
		},

		// --- Eval sanitizers — typed-coercion + safe-loaders ---
		{
			ID:          "py.simpleeval.simpleeval",
			Language:    rules.LangPython,
			Pattern:     `simpleeval\.simple_eval\s*\(|SimpleEval\s*\(\s*\)\.eval\s*\(`,
			ObjectType:  "simpleeval",
			MethodName:  "simple_eval",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "simpleeval simple_eval — restricted Python expression evaluator (no attribute access, no imports, no builtin call) — safe replacement for eval()",
		},
		{
			ID:          "py.asteval.asteval",
			Language:    rules.LangPython,
			Pattern:     `asteval\.Interpreter\s*\(\s*\)|interp\s*\(\s*[^)]+\)`,
			ObjectType:  "asteval.Interpreter",
			MethodName:  "asteval.Interpreter",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "asteval Interpreter — AST-walking restricted Python evaluator without exec/import/__attr (safe expression evaluator)",
		},
		{
			ID:          "py.numexpr.evaluate",
			Language:    rules.LangPython,
			Pattern:     `numexpr\.evaluate\s*\(`,
			ObjectType:  "numexpr",
			MethodName:  "numexpr.evaluate",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "numexpr.evaluate — numeric-only expression evaluator (only arithmetic / numpy operations, no Python builtins / imports)",
		},

		// --- ReDoS sanitizers (CWE-1333 / CWE-400) ---
		// SnkRegexDoS (py.re.compile) previously had NO neutralizing entry, so
		// any tainted value reaching a re.* call kept the flow live even when
		// the developer had defanged it. Two canonical defences exist:
		//   1. re.escape(user_input) — every regex metacharacter in the user
		//      string is backslash-escaped, so the value becomes a *literal*
		//      pattern. An attacker can no longer introduce the nested
		//      quantifiers / alternation that drive catastrophic backtracking,
		//      which is the entire ReDoS attack surface. (The existing
		//      py.re.escape / py.re.escape.nosql entries neutralise SnkEval /
		//      SnkSQLQuery / SnkNoSQL but deliberately NOT SnkRegexDoS, so this
		//      is the one missing category.)
		//   2. The third-party `regex` module accepts a `timeout=` keyword on
		//      compile() and on the one-shot match/search/sub/etc. helpers that
		//      bounds total matching time and raises TimeoutError — turning an
		//      unbounded DoS into a caught exception.
		{
			ID:          "py.redos.re.escape",
			Language:    rules.LangPython,
			Pattern:     `re\.escape\s*\(`,
			ObjectType:  "re",
			MethodName:  "re.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "re.escape(user_input) — backslash-escapes every regex metacharacter so the value is matched literally; an attacker can no longer inject the nested quantifiers/alternation that cause catastrophic backtracking (ReDoS)",
		},
		{
			ID:          "py.redos.regex.timeout.compile",
			Language:    rules.LangPython,
			Pattern:     `regex\.compile\s*\([^)]*timeout\s*=`,
			ObjectType:  "regex",
			MethodName:  "regex.compile(timeout=)",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "regex.compile(pattern, timeout=...) — the third-party `regex` module bounds total matching time and raises TimeoutError, converting an unbounded ReDoS into a caught exception",
		},
		{
			ID:          "py.redos.regex.timeout.methods",
			Language:    rules.LangPython,
			Pattern:     `regex\.(?:match|search|fullmatch|findall|finditer|sub|subn|split)\s*\([^)]*timeout\s*=`,
			ObjectType:  "regex",
			MethodName:  "regex.match/search/sub(timeout=)",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "regex.<method>(pattern, ..., timeout=...) — one-shot `regex` module helpers with a matching-time bound that raises TimeoutError, neutralising ReDoS on a tainted pattern or haystack",
		},

		// =====================================================================
		// ECL2 coverage-breadth cleanup wave — Python sanitizers
		// Each sanitizer is both a detection category (a recognised safe-API the
		// catalog should know) and the FP control that keeps the paired ECL2
		// sink (added in python_sinks.go) clean on correct usage.
		// =====================================================================

		// setattr mass-assignment allowlist guard. Frameworks and hardened code
		// validate the attribute name against an explicit allowlist before
		// setattr — `if name in ALLOWED_FIELDS:` / `if attr in WHITELIST` — so
		// only known-safe fields can be written. The membership test is the
		// recognised neutraliser for the py.setattr.massassign trust-boundary
		// sink. Also covers Django's RestFramework `fields`/`Meta.fields`
		// allowlist idiom and `operator.attrgetter`-style fixed accessors.
		{
			ID:          "py.massassign.allowlist",
			Language:    rules.LangPython,
			Pattern:     `\bin\s+(?:ALLOWED|ALLOW|WHITELIST|SAFE_FIELDS|PERMITTED|EDITABLE|MUTABLE|WRITABLE)\w*\b`,
			ObjectType:  "",
			MethodName:  "allowlist membership guard",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Attribute-name allowlist membership check (`if name in ALLOWED_FIELDS:`) before setattr — restricts mass assignment to known-safe fields",
		},

		// string.Template tainted-template control: a HARDCODED/constant template
		// with only tainted *values* is the safe shape — but the catalog already
		// distinguishes that (taint only fires when the template arg is tainted).
		// The recognised neutraliser is restricting the substitution mapping to a
		// validated/typed model: marshmallow `Schema.load`, pydantic
		// `model_validate`/`parse_obj`, or an explicit dict literal. Those are
		// already SnkTrustBoundary/Deserialize sanitizers; extend the strongest
		// (pydantic/marshmallow validators) to neutralise SnkTemplate so a
		// validated mapping into substitute() stays clean.
		{
			ID:          "py.template.validated_mapping",
			Language:    rules.LangPython,
			Pattern:     `\.model_validate\s*\(|\.parse_obj\s*\(|Schema\s*\(\s*\)\.load\s*\(`,
			ObjectType:  "pydantic.BaseModel",
			MethodName:  "model_validate/parse_obj/Schema.load",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate},
			Description: "pydantic model_validate/parse_obj or marshmallow Schema().load — coerces a substitution mapping to a validated/typed object before string.Template.substitute(), removing attacker-controlled access paths",
		},

		// Static-analysis-friendly proxy validation: urlparse(...).hostname checked
		// against an allowlist before building an httpx proxy / requests proxies —
		// the same host-allowlist shape that defends the request-URL SSRF sinks.
		// Reuse is_private/ip_address style is already covered; add the explicit
		// trusted-proxy-constant idiom (a proxy read from settings/env constant,
		// not request data — no taint reaches it) is handled by the engine. This
		// sanitizer recognises an explicit scheme/host allowlist guard for the
		// proxy URL.
		{
			ID:          "py.ssrf.proxy.allowlist",
			Language:    rules.LangPython,
			Pattern:     `\bin\s+(?:ALLOWED_PROXIES|TRUSTED_PROXIES|PROXY_ALLOWLIST)\b`,
			ObjectType:  "",
			MethodName:  "trusted-proxy allowlist",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Proxy-host allowlist membership check before httpx.Client(proxy=)/requests(proxies=) — restricts outbound traffic to vetted proxies (SSRF defense)",
		},
	}
}
