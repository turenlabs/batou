package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Laravel-specific security rule patterns
// ---------------------------------------------------------------------------

var (
	// BATOU-FW-LARAVEL-001: DB::raw() with user input
	reLaravelDBRaw       = regexp.MustCompile(`DB::raw\s*\(\s*(?:\$|["'][^"']*\$)`)
	reLaravelDBRawConcat = regexp.MustCompile(`DB::raw\s*\(\s*["'][^"']*["']\s*\.\s*\$`)
	// DB::select/statement/insert/update/delete with raw SQL containing variables
	reLaravelDBSelect = regexp.MustCompile(`DB::(?:select|statement|insert|update|delete)\s*\(\s*"[^"]*\$`)

	// BATOU-FW-LARAVEL-002: Blade {!! !!} unescaped output
	reLaravelBladeUnescaped = regexp.MustCompile(`\{!!\s*\$`)

	// BATOU-FW-LARAVEL-003: Mass assignment via the unbounded request bag.
	// Matches both the `$request->all()` property form and the `request()->all()`
	// global-helper form, as well as `$request->input()` / `request()->input()`
	// with no key (the whole bag). The `new Model(...)` constructor form is
	// handled by reLaravelNewModelAll below.
	reLaravelCreateAll = regexp.MustCompile(`(?:::create|::update|::insert|::fill|::forceCreate|::forceFill)\s*\(\s*(?:\$request|request\s*\(\s*\))->(?:all\(\)|input\(\s*\))`)
	reLaravelNewAll    = regexp.MustCompile(`->(?:create|update|fill|forceFill|forceCreate)\s*\(\s*(?:\$request|request\s*\(\s*\))->(?:all\(\)|input\(\s*\))`)
	// `new SomeModel($request->all())` / `new SomeModel(request()->all())` — the
	// dangerous-construction variant: an Eloquent model hydrated directly from
	// the unbounded request array. The class name is an upper-cased identifier
	// (PHP class convention) so this does not match `new SomeException(...)`-style
	// non-models any more than it should — the request-bag arg is the signal.
	reLaravelNewModelAll = regexp.MustCompile(`\bnew\s+\\?[A-Z]\w*\s*\(\s*(?:\$request|request\s*\(\s*\))->(?:all\(\)|input\(\s*\))`)

	// BATOU-FW-LARAVEL-004: APP_DEBUG=true in env files
	reLaravelAppDebug = regexp.MustCompile(`(?i)APP_DEBUG\s*=\s*true`)

	// BATOU-FW-LARAVEL-005: APP_KEY hardcoded or default
	reLaravelAppKeyDefault  = regexp.MustCompile(`(?i)APP_KEY\s*=\s*base64:`)
	reLaravelAppKeyHardcode = regexp.MustCompile(`(?i)['"]APP_KEY['"]\s*=>\s*['"][^'"]+['"]`)

	// BATOU-FW-LARAVEL-006: Unserialize with user input
	reLaravelUnserialize = regexp.MustCompile(`\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|request|input)`)

	// BATOU-FW-LARAVEL-007: Storage/file operations with user input
	reLaravelStorageGet = regexp.MustCompile(`Storage::(?:get|read|download|url|path|exists|delete)\s*\(\s*\$request->`)

	// BATOU-FW-LARAVEL-008: insecure session/cookie configuration. Laravel's
	// session config (config/session.php) and the cookie() helper / Cookie
	// facade control the HttpOnly, Secure, and SameSite flags. Disabling them
	// exposes the session cookie to JS theft (XSS), cleartext interception, and
	// CSRF. We match the config keys set to false/null and the cookie() helper
	// invoked with an explicit httpOnly=false / secure=false argument.
	reLaravelCookieHttpOnlyOff = regexp.MustCompile(`(?i)['"]http_only['"]\s*=>\s*(?:false|null|env\([^)]*,\s*false\s*\))`)
	reLaravelCookieSecureOff   = regexp.MustCompile(`(?i)['"]secure['"]\s*=>\s*false`)
	reLaravelCookieSameSiteOff = regexp.MustCompile(`(?i)['"]same_site['"]\s*=>\s*(?:null|['"]none['"])`)
	// Cookie::make(...) / Cookie::forever(...) ending in a `false` positional —
	// the helper signature is make($name,$value,$minutes,$path,$domain,$secure,
	// $httpOnly,...), so a trailing `, false)` disables httpOnly. Anchored on the
	// Cookie facade ONLY (not the bare `cookie()` helper, which is too loose and
	// would collide with setcookie-style calls).
	reLaravelCookieMakeInsecure = regexp.MustCompile(`Cookie::(?:make|forever)\s*\([^)]*,\s*false\s*\)`)

	// BATOU-FW-LARAVEL-009: Laravel Validator FACADE built from a non-literal
	// rules set — Validator::make($data, $rules) where the 2nd positional (the
	// rules) is a VARIABLE or array_merge() result rather than an inline array
	// literal. A dynamic rule set can be weakened (drop `required`, widen a
	// regex) to bypass validation.
	//
	// IRON-RULE NOTE: we anchor ONLY on the `Validator::make` facade. The bare
	// `->validate($x)` method form is deliberately NOT matched — `validate()` is
	// an extremely common method name across PHP (Symfony's own Validator
	// component, password hashers, entity validators) and matching it collides
	// on essentially every codebase. Facade-anchored = Laravel-specific.
	reLaravelValidatorVar   = regexp.MustCompile(`Validator::make\s*\(\s*[^,]+,\s*\$\w+\s*[,)]`)
	reLaravelValidatorMerge = regexp.MustCompile(`Validator::make\s*\(\s*[^,]+,\s*array_merge\s*\(`)

	// BATOU-FW-LARAVEL-010: Blade <form> POST without an @csrf token. A POST/
	// PUT/PATCH/DELETE form in a Blade template that omits @csrf (or
	// csrf_field()) is rejected by Laravel's VerifyCsrfToken middleware in
	// normal operation, but the omission usually means the route was excepted
	// from CSRF protection — a genuine CSRF hole. We detect the opening <form>
	// with a state-changing method and rely on the per-file absence check.
	reLaravelBladeForm        = regexp.MustCompile(`(?i)<form\b[^>]*\bmethod\s*=\s*['"](?:post|put|patch|delete)['"]`)
	reLaravelBladeMethodSpoof = regexp.MustCompile(`(?i)@method\s*\(\s*['"](?:put|patch|delete)['"]`)
	reLaravelCsrfToken        = regexp.MustCompile(`(?i)@csrf\b|csrf_field\s*\(|name\s*=\s*['"]_token['"]`)

	// Laravel-context markers. A single-file scan cannot otherwise tell a
	// Laravel app apart from Symfony / Nextcloud / generic PHP, where the same
	// `'secure' => false` array key and `<form method=post>` shapes are NOT
	// Laravel cookie/CSRF issues. The cookie- and CSRF-coverage rules below are
	// gated on at least one of these markers so they never fire outside Laravel.
	reLaravelMarker = regexp.MustCompile(`(?i)Illuminate\\|use\s+Illuminate|->withCookie\b|\bCookie::(?:make|forever|queue)\b|namespace\s+App\\|->validate\s*\(|@csrf\b|@method\s*\(|SESSION_SECURE_COOKIE|config\(['"]session\.`)
)

// phpIsLaravelContext reports whether the file content shows Laravel-specific
// markers (Illuminate use, Cookie facade, Blade directives, App namespace,
// Laravel session config). Used to gate the cookie/CSRF coverage rules so they
// do not misfire on Symfony / generic PHP that happens to share a surface shape.
func phpIsLaravelContext(ctx *rules.ScanContext) bool {
	if rules.GMatchFile(reLaravelMarker, ctx) {
		return true
	}
	fp := ctx.FilePath
	// Blade template files are unambiguously Laravel.
	if strings.Contains(fp, ".blade.php") {
		return true
	}
	// Laravel's canonical config layout: config/session.php / config/cookie is
	// the file where the session-cookie flags live. Symfony/Nextcloud do not use
	// this path, so it is a reliable Laravel marker for the cookie-flag rule.
	return strings.Contains(fp, "config/session.php") || strings.Contains(fp, "config/cookie.php")
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-001: DB::raw() SQL injection
// ---------------------------------------------------------------------------

type LaravelDBRaw struct{}

func (r *LaravelDBRaw) ID() string                      { return "BATOU-FW-LARAVEL-001" }
func (r *LaravelDBRaw) Name() string                    { return "LaravelDBRaw" }
func (r *LaravelDBRaw) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *LaravelDBRaw) Description() string {
	return "Detects Laravel DB::raw() and raw SQL queries with PHP variable interpolation, which can lead to SQL injection."
}
func (r *LaravelDBRaw) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelDBRaw) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched bool
		var title string
		if rules.GMatchLower(reLaravelDBRaw, line, lowered[i]) || rules.GMatchLower(reLaravelDBRawConcat, line, lowered[i]) {
			matched = true
			title = "Laravel DB::raw() with variable interpolation (SQLi)"
		} else if rules.GMatchLower(reLaravelDBSelect, line, lowered[i]) {
			matched = true
			title = "Laravel DB::select/statement with variable interpolation (SQLi)"
		}
		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "DB::raw() or raw SQL queries with PHP variable interpolation allow an attacker to inject arbitrary SQL. Laravel's query builder provides parameterized query support that should be used instead.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use parameterized bindings: DB::raw('YEAR(?) = ?', [$col, $year]) or query builder methods: ->whereRaw('age > ?', [$age]).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "sql-injection", "db-raw"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-002: Blade {!! !!} unescaped output
// ---------------------------------------------------------------------------

type LaravelBladeUnescaped struct{}

func (r *LaravelBladeUnescaped) ID() string                      { return "BATOU-FW-LARAVEL-002" }
func (r *LaravelBladeUnescaped) Name() string                    { return "LaravelBladeUnescaped" }
func (r *LaravelBladeUnescaped) DefaultSeverity() rules.Severity { return rules.High }
func (r *LaravelBladeUnescaped) Description() string {
	return "Detects Laravel Blade {!! !!} unescaped output with variables, which bypasses HTML escaping and can lead to XSS."
}
func (r *LaravelBladeUnescaped) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelBladeUnescaped) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reLaravelBladeUnescaped, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Laravel Blade {!! !!} unescaped output",
				Description:   "Blade's {!! !!} syntax outputs content without HTML escaping. If the variable contains user input, this creates an XSS vulnerability. Use {{ }} for auto-escaped output.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use {{ $variable }} for auto-escaped output. If raw HTML is needed, sanitize with strip_tags() or a library like HTMLPurifier before using {!! !!}.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "blade", "xss", "unescaped"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-003: Mass assignment via $request->all()
// ---------------------------------------------------------------------------

type LaravelMassAssignment struct{}

func (r *LaravelMassAssignment) ID() string                      { return "BATOU-FW-LARAVEL-003" }
func (r *LaravelMassAssignment) Name() string                    { return "LaravelMassAssignment" }
func (r *LaravelMassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r *LaravelMassAssignment) Description() string {
	return "Detects Laravel mass assignment via $request->all() passed directly to Eloquent create/update, bypassing fillable/guarded protection."
}
func (r *LaravelMassAssignment) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelMassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reLaravelCreateAll, line, lowered[i]) || rules.GMatchLower(reLaravelNewAll, line, lowered[i]) || rules.GMatchLower(reLaravelNewModelAll, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Laravel mass assignment via the unbounded request bag",
				Description:   "Hydrating an Eloquent model from $request->all() / request()->all() / request()->input() (including `new Model($request->all())`) lets an attacker set any model attribute — is_admin, role, foreign keys. Even with $fillable/$guarded, passing the whole request bag is the dangerous-construction smell that should be replaced with an explicit field list.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use $request->only(['field1', 'field2']) or $request->validated() (after form request validation) instead of $request->all().",
				CWEID:         "CWE-915",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "mass-assignment", "eloquent"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-004: APP_DEBUG=true
// ---------------------------------------------------------------------------

type LaravelDebugMode struct{}

func (r *LaravelDebugMode) ID() string                      { return "BATOU-FW-LARAVEL-004" }
func (r *LaravelDebugMode) Name() string                    { return "LaravelDebugMode" }
func (r *LaravelDebugMode) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LaravelDebugMode) Description() string {
	return "Detects APP_DEBUG=true in Laravel .env or config files, which exposes stack traces, database credentials, and application internals."
}
func (r *LaravelDebugMode) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP, rules.LangAny}
}

func (r *LaravelDebugMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Check .env files and PHP config files
	isEnvFile := strings.HasSuffix(ctx.FilePath, ".env") ||
		strings.HasSuffix(ctx.FilePath, ".env.production") ||
		strings.HasSuffix(ctx.FilePath, ".env.staging")
	isPHP := ctx.Language == rules.LangPHP

	if !isEnvFile && !isPHP {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reLaravelAppDebug, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Laravel APP_DEBUG=true (information disclosure)",
				Description:   "APP_DEBUG=true exposes detailed error pages including stack traces, database credentials, environment variables, and file paths to all users. This must be set to false in production.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set APP_DEBUG=false in production .env files. Use logging instead of debug mode for error tracking.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "debug", "misconfiguration", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-005: APP_KEY exposure
// ---------------------------------------------------------------------------

type LaravelAppKey struct{}

func (r *LaravelAppKey) ID() string                      { return "BATOU-FW-LARAVEL-005" }
func (r *LaravelAppKey) Name() string                    { return "LaravelAppKey" }
func (r *LaravelAppKey) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *LaravelAppKey) Description() string {
	return "Detects hardcoded or committed Laravel APP_KEY values, which can lead to session forgery and remote code execution."
}
func (r *LaravelAppKey) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP, rules.LangAny}
}

func (r *LaravelAppKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	isEnvFile := strings.HasSuffix(ctx.FilePath, ".env") ||
		strings.Contains(ctx.FilePath, ".env.")
	isPHP := ctx.Language == rules.LangPHP

	if !isEnvFile && !isPHP {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched bool
		var title string
		if isEnvFile && rules.GMatchLower(reLaravelAppKeyDefault, line, lowered[i]) {
			matched = true
			title = "Laravel APP_KEY committed in .env file"
		} else if isPHP && rules.GMatchLower(reLaravelAppKeyHardcode, line, lowered[i]) {
			matched = true
			title = "Laravel APP_KEY hardcoded in PHP config"
		}
		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "The Laravel APP_KEY is used for encryption and session signing. A leaked APP_KEY allows attackers to forge session cookies and, when SESSION_DRIVER=cookie, achieve remote code execution via PHP deserialization.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never commit APP_KEY to version control. Generate a unique key per environment with 'php artisan key:generate'. Add .env to .gitignore.",
				CWEID:         "CWE-798",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "secret", "app-key", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-006: Unserialize with user input
// ---------------------------------------------------------------------------

type LaravelUnserialize struct{}

func (r *LaravelUnserialize) ID() string                      { return "BATOU-FW-LARAVEL-006" }
func (r *LaravelUnserialize) Name() string                    { return "LaravelUnserialize" }
func (r *LaravelUnserialize) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *LaravelUnserialize) Description() string {
	return "Detects PHP unserialize() with user input, which can lead to remote code execution via object injection."
}
func (r *LaravelUnserialize) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelUnserialize) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reLaravelUnserialize, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP unserialize() with user input (object injection)",
				Description:   "unserialize() with user-controlled data allows an attacker to instantiate arbitrary PHP objects, triggering magic methods (__wakeup, __destruct) that can lead to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use json_decode() instead of unserialize() for user data. If unserialize is required, use the allowed_classes option: unserialize($data, ['allowed_classes' => false]).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "php", "deserialization", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-007: Storage operations with user input
// ---------------------------------------------------------------------------

type LaravelStorageTraversal struct{}

func (r *LaravelStorageTraversal) ID() string                      { return "BATOU-FW-LARAVEL-007" }
func (r *LaravelStorageTraversal) Name() string                    { return "LaravelStorageTraversal" }
func (r *LaravelStorageTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *LaravelStorageTraversal) Description() string {
	return "Detects Laravel Storage facade operations with direct user input, which may allow path traversal to access arbitrary files."
}
func (r *LaravelStorageTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelStorageTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reLaravelStorageGet, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Laravel Storage operation with direct user input (path traversal risk)",
				Description:   "Passing $request->input() directly to Storage facade methods allows an attacker to use ../ sequences to access files outside the intended storage directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate and sanitize file paths before passing to Storage methods. Use basename() to strip directory components, or validate against an allowlist of permitted paths.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"laravel", "path-traversal", "storage"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-008: insecure session/cookie configuration (HttpOnly /
// Secure / SameSite disabled). CWE-1004 (missing HttpOnly), CWE-614 (missing
// Secure), CWE-1275 (weak SameSite).
// ---------------------------------------------------------------------------

type LaravelInsecureCookie struct{}

func (r *LaravelInsecureCookie) ID() string                      { return "BATOU-FW-LARAVEL-008" }
func (r *LaravelInsecureCookie) Name() string                    { return "LaravelInsecureCookie" }
func (r *LaravelInsecureCookie) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LaravelInsecureCookie) Description() string {
	return "Detects Laravel session/cookie configuration that disables the HttpOnly, Secure, or SameSite protections, or a Cookie::make()/cookie() call with httpOnly turned off — exposing session cookies to XSS theft, cleartext interception, and CSRF (CWE-1004 / CWE-614 / CWE-1275)."
}
func (r *LaravelInsecureCookie) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelInsecureCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	// Gate on Laravel context: the `'secure' => false` / `'http_only' => false`
	// array-key shape is shared by Symfony cookies, test fixtures, and generic
	// PHP config arrays, where it is not a Laravel session-cookie finding.
	if !phpIsLaravelContext(ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var why, cwe string
		switch {
		case rules.GMatchLower(reLaravelCookieHttpOnlyOff, line, lowered[i]):
			why = "session 'http_only' is disabled — the session cookie is readable from JavaScript, so any XSS can steal it"
			cwe = "CWE-1004"
		case rules.GMatchLower(reLaravelCookieSecureOff, line, lowered[i]):
			why = "session 'secure' is false — the session cookie is transmitted over plain HTTP and can be intercepted"
			cwe = "CWE-614"
		case rules.GMatchLower(reLaravelCookieSameSiteOff, line, lowered[i]):
			why = "session 'same_site' is null/'none' — the cookie is sent on cross-site requests, enabling CSRF"
			cwe = "CWE-1275"
		case rules.GMatchLower(reLaravelCookieMakeInsecure, line, lowered[i]):
			why = "Cookie::make()/cookie() is called with httpOnly disabled — the cookie is exposed to client-side script"
			cwe = "CWE-1004"
		default:
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Laravel insecure cookie/session flag",
			Description:   "The application " + why + ". Session and authentication cookies must set HttpOnly, Secure, and a strict SameSite to resist theft, interception, and cross-site request forgery.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "In config/session.php set 'http_only' => true, 'secure' => env('SESSION_SECURE_COOKIE', true), and 'same_site' => 'lax' (or 'strict'). For ad-hoc cookies, pass httpOnly=true and secure=true to cookie()/Cookie::make().",
			CWEID:         cwe,
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"laravel", "cookie", "session", "misconfiguration"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-009: Validator built from a non-literal (variable / merged)
// rules set — attacker- or config-influenced validation that can be weakened
// or bypassed (CWE-89 / input-validation weakening).
// ---------------------------------------------------------------------------

type LaravelUnsafeValidator struct{}

func (r *LaravelUnsafeValidator) ID() string                      { return "BATOU-FW-LARAVEL-009" }
func (r *LaravelUnsafeValidator) Name() string                    { return "LaravelUnsafeValidator" }
func (r *LaravelUnsafeValidator) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LaravelUnsafeValidator) Description() string {
	return "Detects Validator::make()/$request->validate() whose rules argument is a variable or array_merge() result rather than an inline literal — a dynamic rule set can be weakened or bypassed, undermining input validation (CWE-89)."
}
func (r *LaravelUnsafeValidator) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelUnsafeValidator) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	if !strings.Contains(ctx.Content, "Validator::make") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reLaravelValidatorVar, line, lowered[i]) &&
			!rules.GMatchLower(reLaravelValidatorMerge, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Laravel validator built from a non-literal rules set",
			Description:   "The validation rules are supplied as a variable or array_merge() result rather than an inline literal. If any part of that rule set is attacker- or request-influenced, the validation can be weakened (dropping `required`, widening a pattern) or bypassed entirely — the guarantees of a fixed rule set are lost.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Define validation rules as an inline literal array (or a dedicated FormRequest::rules() method) so they cannot be influenced at runtime. If rules must be composed, build them from trusted constants only, never from request data.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"laravel", "validation", "input-validation"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-LARAVEL-010: Blade <form> with a state-changing method but no @csrf
// token (CWE-352). Laravel rejects such POSTs via VerifyCsrfToken — an omitted
// token almost always means the route was excluded from CSRF protection, a
// genuine CSRF hole. Per-file: fires only when a state-changing <form>/@method
// spoof exists AND no @csrf / csrf_field() / _token field appears in the file.
// ---------------------------------------------------------------------------

type LaravelMissingCSRF struct{}

func (r *LaravelMissingCSRF) ID() string                      { return "BATOU-FW-LARAVEL-010" }
func (r *LaravelMissingCSRF) Name() string                    { return "LaravelMissingCSRF" }
func (r *LaravelMissingCSRF) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LaravelMissingCSRF) Description() string {
	return "Detects a Blade <form> with a POST/PUT/PATCH/DELETE method (or @method spoof) that omits the @csrf token — missing CSRF protection (CWE-352)."
}
func (r *LaravelMissingCSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *LaravelMissingCSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	c := ctx.Content
	// @csrf is a Blade construct: require an actual Blade template. A raw .php
	// HTML template, a Symfony Twig test, or an HTML string inside a unit test
	// is NOT a Laravel CSRF finding even when it contains `<form method=post>`.
	if !strings.Contains(ctx.FilePath, ".blade.php") {
		return nil
	}
	// Require a <form> to be present.
	if !strings.Contains(c, "<form") {
		return nil
	}
	// If the file contains ANY csrf token directive, treat all forms as
	// protected (the token may be in a shared partial / different form, but a
	// per-file presence check is the conservative, FP-safe heuristic).
	if reLaravelCsrfToken.MatchString(c) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reLaravelBladeForm, line, lowered[i]) && !rules.GMatchLower(reLaravelBladeMethodSpoof, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Blade form without @csrf token (missing CSRF protection)",
			Description:   "This Blade template defines a state-changing form (POST/PUT/PATCH/DELETE) but no @csrf / csrf_field() token appears in the file. Laravel's VerifyCsrfToken middleware rejects such requests, so a missing token usually means the route was excepted from CSRF protection — letting an attacker forge the request from another origin.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Add @csrf immediately inside every state-changing <form>. Do not add the route to VerifyCsrfToken's $except list unless it is a stateless API endpoint protected by another mechanism (signed URL, token auth).",
			CWEID:         "CWE-352",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"laravel", "csrf", "blade"},
		})
	}
	return findings
}
