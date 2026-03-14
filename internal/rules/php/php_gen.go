package php

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for BATOU-PHP-025 .. BATOU-PHP-034
// ---------------------------------------------------------------------------

// PHP-025: unserialize without allowed_classes
var (
	reUnserializeCall    = regexp.MustCompile(`\bunserialize\s*\(`)
	reAllowedClasses     = regexp.MustCompile(`allowed_classes`)
)

// PHP-026: extract() with superglobals
var (
	reExtractSuperglobal = regexp.MustCompile(`\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`)
)

// PHP-027: Laravel Blade raw output
var (
	reBladeRawOutput = regexp.MustCompile(`\{!!\s*\$`)
)

// PHP-028: preg_replace /e modifier
var (
	rePregReplaceEGen = regexp.MustCompile(`\bpreg_replace\s*\(\s*["']/[^"']*(?:/|\\/)e["']`)
	rePregReplaceEAltGen = regexp.MustCompile(`\bpreg_replace\s*\(\s*["'][^"']+e["']\s*,`)
)

// PHP-029: Laravel guarded empty
var (
	reGuardedEmpty = regexp.MustCompile(`\$guarded\s*=\s*\[\s*\]`)
)

// PHP-030: assert with string
var (
	reAssertString    = regexp.MustCompile(`\bassert\s*\(\s*["']`)
	reAssertVariable  = regexp.MustCompile(`\bassert\s*\(\s*\$`)
)

// PHP-031: Hardcoded APP_KEY
var (
	reHardcodedAppKey = regexp.MustCompile(`APP_KEY\s*=\s*base64:[A-Za-z0-9+/=]{32,}`)
)

// PHP-032: Variable variables with superglobals
var (
	reVarVarSuperglobal = regexp.MustCompile(`\$\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`)
)

// PHP-033: Redis pubsub unserialize
var (
	reUnserializeMsg   = regexp.MustCompile(`\bunserialize\s*\(\s*\$(?:message|data|payload|body)`)
	reRedisPubsub      = regexp.MustCompile(`(?i)(?:redis|pubsub|subscribe|channel|queue|broker)`)
)

// PHP-034: Unsafe file upload path
var (
	reMoveUploadedFile     = regexp.MustCompile(`\bmove_uploaded_file\s*\(`)
	reMoveUploadedFileUser = regexp.MustCompile(`\bmove_uploaded_file\s*\([^,]+,\s*[^)]*\$_(?:GET|POST|REQUEST)`)
)

// ---------------------------------------------------------------------------
// BATOU-PHP-025: unserialize Without allowed_classes
// ---------------------------------------------------------------------------

type UnserializeNoFilter struct{}

func (r *UnserializeNoFilter) ID() string                      { return "BATOU-PHP-025" }
func (r *UnserializeNoFilter) Name() string                    { return "PHPUnserializeNoFilter" }
func (r *UnserializeNoFilter) Description() string             { return "Detects PHP unserialize() without allowed_classes restriction, enabling object injection." }
func (r *UnserializeNoFilter) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UnserializeNoFilter) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *UnserializeNoFilter) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reUnserializeCall.MatchString(line) {
			continue
		}
		// Skip if allowed_classes is specified
		if reAllowedClasses.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP unserialize() without allowed_classes restriction",
			Description:   "unserialize() without the 'allowed_classes' option allows instantiation of arbitrary PHP classes. Attackers can craft serialized payloads that trigger __wakeup(), __destruct(), or __toString() magic methods in gadget classes to achieve remote code execution.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use unserialize($data, ['allowed_classes' => false]) to prevent object instantiation, or specify an explicit list: ['allowed_classes' => ['AllowedClass']]. Prefer json_decode() for untrusted data.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "unserialize", "deserialization", "object-injection"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-026: extract() With Superglobals
// ---------------------------------------------------------------------------

type ExtractSuperglobals struct{}

func (r *ExtractSuperglobals) ID() string                      { return "BATOU-PHP-026" }
func (r *ExtractSuperglobals) Name() string                    { return "PHPExtractSuperglobals" }
func (r *ExtractSuperglobals) Description() string             { return "Detects extract() with $_GET/$_POST/$_REQUEST/$_COOKIE, overwriting local variables." }
func (r *ExtractSuperglobals) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ExtractSuperglobals) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *ExtractSuperglobals) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reExtractSuperglobal.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "extract() with superglobals overwrites local variables",
			Description:   "extract() with $_GET, $_POST, $_REQUEST, or $_COOKIE imports all user-controlled request parameters as local variables, overwriting any existing variables. An attacker can set $isAdmin=1, $authenticated=true, or overwrite file paths, database queries, and configuration values.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Never use extract() with superglobals. Access parameters directly via $_GET['key'] or use a framework's request object. If extract() is necessary, use EXTR_SKIP flag and prefix: extract($data, EXTR_PREFIX_ALL, 'user_').",
			CWEID:         "CWE-621",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "extract", "superglobals", "variable-overwrite"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-027: Laravel Blade Raw Output
// ---------------------------------------------------------------------------

type BladeRawOutput struct{}

func (r *BladeRawOutput) ID() string                      { return "BATOU-PHP-027" }
func (r *BladeRawOutput) Name() string                    { return "PHPBladeRawOutput" }
func (r *BladeRawOutput) Description() string             { return "Detects Laravel Blade {!! !!} raw output which bypasses XSS auto-escaping." }
func (r *BladeRawOutput) DefaultSeverity() rules.Severity { return rules.High }
func (r *BladeRawOutput) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *BladeRawOutput) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reBladeRawOutput.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Laravel Blade {!! !!} raw output bypasses XSS escaping",
			Description:   "The {!! $variable !!} syntax in Laravel Blade outputs content without HTML escaping. If the variable contains user input, this creates a cross-site scripting (XSS) vulnerability. Attackers can inject JavaScript to steal session cookies, redirect users, or modify page content.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use {{ $variable }} instead of {!! $variable !!} for auto-escaping. If raw HTML is required, sanitize with a library like HTMLPurifier before passing to the view. Use Laravel's e() helper for manual escaping.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "laravel", "blade", "xss", "raw-output"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-028: preg_replace /e Modifier
// ---------------------------------------------------------------------------

type PregReplaceEval struct{}

func (r *PregReplaceEval) ID() string                      { return "BATOU-PHP-028" }
func (r *PregReplaceEval) Name() string                    { return "PHPPregReplaceEval" }
func (r *PregReplaceEval) Description() string             { return "Detects preg_replace with /e modifier which evaluates replacement as PHP code." }
func (r *PregReplaceEval) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PregReplaceEval) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PregReplaceEval) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rePregReplaceEGen.MatchString(line) && !rePregReplaceEAltGen.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "preg_replace with /e modifier evaluates code",
			Description:   "The /e modifier in preg_replace() evaluates the replacement string as PHP code using eval(). If any part of the matched input flows into the replacement, an attacker can execute arbitrary PHP code. This modifier was removed in PHP 7.0 for security reasons.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Replace preg_replace() with /e modifier with preg_replace_callback(): preg_replace_callback('/pattern/', function($matches) { return process($matches); }, $subject). This is both safer and compatible with PHP 7+.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "preg-replace", "eval", "code-injection"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-029: Laravel $guarded = []
// ---------------------------------------------------------------------------

type LaravelGuardedEmpty struct{}

func (r *LaravelGuardedEmpty) ID() string                      { return "BATOU-PHP-029" }
func (r *LaravelGuardedEmpty) Name() string                    { return "PHPLaravelGuardedEmpty" }
func (r *LaravelGuardedEmpty) Description() string             { return "Detects Laravel model with $guarded = [] which allows mass assignment of all attributes." }
func (r *LaravelGuardedEmpty) DefaultSeverity() rules.Severity { return rules.High }
func (r *LaravelGuardedEmpty) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *LaravelGuardedEmpty) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reGuardedEmpty.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Laravel $guarded = [] allows mass assignment of all attributes",
			Description:   "Setting $guarded to an empty array in a Laravel Eloquent model makes all attributes mass-assignable. An attacker can set any column value including is_admin, role, password, email, or foreign keys by adding extra fields to form submissions or API requests.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use $fillable instead of $guarded to explicitly allowlist mass-assignable attributes: protected $fillable = ['name', 'email']. Alternatively, set $guarded to protect sensitive fields: protected $guarded = ['id', 'is_admin', 'role'].",
			CWEID:         "CWE-915",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "laravel", "mass-assignment", "eloquent"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-030: assert With String
// ---------------------------------------------------------------------------

type AssertStringEval struct{}

func (r *AssertStringEval) ID() string                      { return "BATOU-PHP-030" }
func (r *AssertStringEval) Name() string                    { return "PHPAssertStringEval" }
func (r *AssertStringEval) Description() string             { return "Detects PHP assert() with string argument which is evaluated as code." }
func (r *AssertStringEval) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *AssertStringEval) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *AssertStringEval) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		confidence := "high"

		if reAssertString.MatchString(line) {
			matched = true
		} else if reAssertVariable.MatchString(line) {
			matched = true
			confidence = "medium"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP assert() with string/variable evaluates as code",
				Description:   "In PHP < 8.0, assert() with a string argument evaluates it as PHP code via eval(). If user input reaches assert(), an attacker can execute arbitrary PHP code. Even with variables, if the variable contains user-controlled data, this is exploitable.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use assert() with a boolean expression instead of a string: assert($x > 0) instead of assert('$x > 0'). In production, disable assert evaluation: ini_set('assert.active', 0) or zend.assertions = -1 in php.ini.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"php", "assert", "code-injection", "eval"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-031: Hardcoded APP_KEY
// ---------------------------------------------------------------------------

type HardcodedAppKey struct{}

func (r *HardcodedAppKey) ID() string                      { return "BATOU-PHP-031" }
func (r *HardcodedAppKey) Name() string                    { return "PHPHardcodedAppKey" }
func (r *HardcodedAppKey) Description() string             { return "Detects hardcoded Laravel APP_KEY in source files." }
func (r *HardcodedAppKey) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedAppKey) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *HardcodedAppKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reHardcodedAppKey.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Hardcoded Laravel APP_KEY in source code",
			Description:   "The Laravel APP_KEY is hardcoded in the source file. This key is used for encrypting session cookies, CSRF tokens, and all Crypt::encrypt() data. If the key is committed to version control, anyone with repo access can decrypt cookies, forge sessions, and potentially achieve remote code execution via deserialization.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Store APP_KEY in environment variables or a secrets manager. Use 'php artisan key:generate' to create a new key. Add .env to .gitignore and never commit secrets to version control.",
			CWEID:         "CWE-798",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "laravel", "secrets", "app-key", "hardcoded"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-032: Variable Variables With Superglobals
// ---------------------------------------------------------------------------

type VariableVariables struct{}

func (r *VariableVariables) ID() string                      { return "BATOU-PHP-032" }
func (r *VariableVariables) Name() string                    { return "PHPVariableVariables" }
func (r *VariableVariables) Description() string             { return "Detects PHP variable variables ($$) with superglobals, enabling variable overwrite." }
func (r *VariableVariables) DefaultSeverity() rules.Severity { return rules.High }
func (r *VariableVariables) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *VariableVariables) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reVarVarSuperglobal.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Variable variables ($$) with superglobals",
			Description:   "Using variable variables ($$) with superglobals like $_GET or $_POST allows an attacker to control which variable is read or written. This can overwrite security-critical variables (e.g., $isAdmin, $authenticated) or read sensitive data by controlling the variable name via request parameters.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Access superglobal values directly: $_GET['key'] instead of $$_GET['key']. Use associative arrays or objects instead of dynamic variable names. Validate variable names against an allowlist if dynamic access is required.",
			CWEID:         "CWE-621",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "variable-variables", "superglobals"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-033: Redis PubSub unserialize
// ---------------------------------------------------------------------------

type RedisPubsubUnserialize struct{}

func (r *RedisPubsubUnserialize) ID() string                      { return "BATOU-PHP-033" }
func (r *RedisPubsubUnserialize) Name() string                    { return "PHPRedisPubsubUnserialize" }
func (r *RedisPubsubUnserialize) Description() string             { return "Detects unserialize() on message/data variables in Redis/pubsub context." }
func (r *RedisPubsubUnserialize) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RedisPubsubUnserialize) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *RedisPubsubUnserialize) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	// Only flag if the file has redis/pubsub context
	if !reRedisPubsub.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reUnserializeMsg.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "unserialize() on Redis/pubsub message data",
			Description:   "Calling unserialize() on message or data variables received from Redis pub/sub, message queues, or event channels deserializes untrusted input. If an attacker can publish messages to the channel, they can send crafted payloads to achieve remote code execution via PHP object injection.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use json_decode() instead of unserialize() for message deserialization. If unserialize() is required, use ['allowed_classes' => false] or specify explicit classes. Authenticate and validate messages from pub/sub channels.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "redis", "pubsub", "unserialize", "deserialization"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-034: Unsafe File Upload Path
// ---------------------------------------------------------------------------

type UnsafeUploadPath struct{}

func (r *UnsafeUploadPath) ID() string                      { return "BATOU-PHP-034" }
func (r *UnsafeUploadPath) Name() string                    { return "PHPUnsafeUploadPath" }
func (r *UnsafeUploadPath) Description() string             { return "Detects move_uploaded_file with user-controlled destination path from superglobals." }
func (r *UnsafeUploadPath) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UnsafeUploadPath) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *UnsafeUploadPath) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reMoveUploadedFileUser.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "move_uploaded_file with user-controlled destination path",
			Description:   "move_uploaded_file() uses a destination path derived from $_GET, $_POST, or $_REQUEST. An attacker can control the file path to write uploaded files to arbitrary locations (e.g., web root to upload a PHP shell, or overwrite configuration files). Path traversal via ../ enables writing outside the intended directory.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Never use user input in the destination path. Generate a random filename: $dest = $uploadDir . '/' . bin2hex(random_bytes(16)) . '.ext'. Validate the upload directory with realpath() and ensure the resolved path starts with the expected base directory.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "upload", "path-traversal", "move-uploaded-file"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&UnserializeNoFilter{})
	rules.Register(&ExtractSuperglobals{})
	rules.Register(&BladeRawOutput{})
	rules.Register(&PregReplaceEval{})
	rules.Register(&LaravelGuardedEmpty{})
	rules.Register(&AssertStringEval{})
	rules.Register(&HardcodedAppKey{})
	rules.Register(&VariableVariables{})
	rules.Register(&RedisPubsubUnserialize{})
	rules.Register(&UnsafeUploadPath{})
}
