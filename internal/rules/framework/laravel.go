package framework

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Laravel-specific security rule patterns
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-LARAVEL-001: DB::raw() with user input
	reLaravelDBRaw       = regexp.MustCompile(`DB::raw\s*\(\s*(?:\$|["'][^"']*\$)`)
	reLaravelDBRawConcat = regexp.MustCompile(`DB::raw\s*\(\s*["'][^"']*["']\s*\.\s*\$`)
	// DB::select/statement/insert/update/delete with raw SQL containing variables
	reLaravelDBSelect = regexp.MustCompile(`DB::(?:select|statement|insert|update|delete)\s*\(\s*"[^"]*\$`)

	// GTSS-FW-LARAVEL-002: Blade {!! !!} unescaped output
	reLaravelBladeUnescaped = regexp.MustCompile(`\{!!\s*\$`)

	// GTSS-FW-LARAVEL-003: Mass assignment via $request->all()
	reLaravelCreateAll = regexp.MustCompile(`(?:::create|::update|::insert|::fill|::forceCreate)\s*\(\s*\$request->all\(\)`)
	reLaravelNewAll    = regexp.MustCompile(`->(?:create|update|fill|forceFill)\s*\(\s*\$request->all\(\)`)

	// GTSS-FW-LARAVEL-004: APP_DEBUG=true in env files
	reLaravelAppDebug = regexp.MustCompile(`(?i)APP_DEBUG\s*=\s*true`)

	// GTSS-FW-LARAVEL-005: APP_KEY hardcoded or default
	reLaravelAppKeyDefault  = regexp.MustCompile(`(?i)APP_KEY\s*=\s*base64:`)
	reLaravelAppKeyEmpty    = regexp.MustCompile(`(?i)APP_KEY\s*=\s*$`)
	reLaravelAppKeyHardcode = regexp.MustCompile(`(?i)['"]APP_KEY['"]\s*=>\s*['"][^'"]+['"]`)

	// GTSS-FW-LARAVEL-006: Unserialize with user input
	reLaravelUnserialize = regexp.MustCompile(`\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|request|input)`)

	// GTSS-FW-LARAVEL-007: Storage/file operations with user input
	reLaravelStorageGet = regexp.MustCompile(`Storage::(?:get|read|download|url|path|exists|delete)\s*\(\s*\$request->`)
)

// ---------------------------------------------------------------------------
// GTSS-FW-LARAVEL-001: DB::raw() SQL injection
// ---------------------------------------------------------------------------

type LaravelDBRaw struct{}

func (r *LaravelDBRaw) ID() string                      { return "GTSS-FW-LARAVEL-001" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched bool
		var title string
		if reLaravelDBRaw.MatchString(line) || reLaravelDBRawConcat.MatchString(line) {
			matched = true
			title = "Laravel DB::raw() with variable interpolation (SQLi)"
		} else if reLaravelDBSelect.MatchString(line) {
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
// GTSS-FW-LARAVEL-002: Blade {!! !!} unescaped output
// ---------------------------------------------------------------------------

type LaravelBladeUnescaped struct{}

func (r *LaravelBladeUnescaped) ID() string                      { return "GTSS-FW-LARAVEL-002" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reLaravelBladeUnescaped.MatchString(line) {
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
// GTSS-FW-LARAVEL-003: Mass assignment via $request->all()
// ---------------------------------------------------------------------------

type LaravelMassAssignment struct{}

func (r *LaravelMassAssignment) ID() string                      { return "GTSS-FW-LARAVEL-003" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reLaravelCreateAll.MatchString(line) || reLaravelNewAll.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Laravel mass assignment via $request->all()",
				Description:   "Passing $request->all() directly to Eloquent create/update allows an attacker to set any model attribute, including is_admin, role, or foreign keys. Even with $fillable/$guarded on the model, $request->all() is a code smell indicating insufficient input filtering.",
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
// GTSS-FW-LARAVEL-004: APP_DEBUG=true
// ---------------------------------------------------------------------------

type LaravelDebugMode struct{}

func (r *LaravelDebugMode) ID() string                      { return "GTSS-FW-LARAVEL-004" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reLaravelAppDebug.MatchString(line) {
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
// GTSS-FW-LARAVEL-005: APP_KEY exposure
// ---------------------------------------------------------------------------

type LaravelAppKey struct{}

func (r *LaravelAppKey) ID() string                      { return "GTSS-FW-LARAVEL-005" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched bool
		var title string
		if isEnvFile && reLaravelAppKeyDefault.MatchString(line) {
			matched = true
			title = "Laravel APP_KEY committed in .env file"
		} else if isPHP && reLaravelAppKeyHardcode.MatchString(line) {
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
// GTSS-FW-LARAVEL-006: Unserialize with user input
// ---------------------------------------------------------------------------

type LaravelUnserialize struct{}

func (r *LaravelUnserialize) ID() string                      { return "GTSS-FW-LARAVEL-006" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reLaravelUnserialize.MatchString(line) {
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
// GTSS-FW-LARAVEL-007: Storage operations with user input
// ---------------------------------------------------------------------------

type LaravelStorageTraversal struct{}

func (r *LaravelStorageTraversal) ID() string                      { return "GTSS-FW-LARAVEL-007" }
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
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reLaravelStorageGet.MatchString(line) {
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
