package rust

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// RS-001: Unsafe block usage
var (
	reUnsafeBlock    = regexp.MustCompile(`\bunsafe\s*\{`)
	reRawPtrDeref    = regexp.MustCompile(`\*\s*(?:mut\s+|const\s+)?\w+|(?:\*\w+)\s*[.=;]`)
	reTransmute      = regexp.MustCompile(`(?:std::mem::)?transmute\s*[:<(]`)
	reTransmuteBytes = regexp.MustCompile(`(?:std::mem::)?transmute_copy\s*[:<(]`)
)

// RS-002: Command injection
var (
	reCommandNew      = regexp.MustCompile(`Command::new\s*\(\s*(?:format!\s*\(|&?\s*[a-zA-Z_]\w*)`)
	reCommandNewShell = regexp.MustCompile(`Command::new\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*\)`)
	reCommandArg      = regexp.MustCompile(`\.arg\s*\(\s*(?:format!\s*\(|&?\s*[a-zA-Z_]\w*)`)
	reCommandArgs     = regexp.MustCompile(`\.args\s*\(\s*(?:\[|vec!\s*\[|&?\s*[a-zA-Z_]\w*)`)
)

// RS-003: SQL injection
var (
	reSQLFormat     = regexp.MustCompile(`(?:sqlx::query|diesel::sql_query|\.execute)\s*\(\s*&?\s*format!\s*\(`)
	reSQLConcat     = regexp.MustCompile(`(?:sqlx::query|diesel::sql_query|\.execute)\s*\(\s*&?\s*(?:\w+\s*\+|[a-zA-Z_]\w*\s*\.\s*as_str)`)
	reSQLQueryVar   = regexp.MustCompile(`(?:sqlx::query|diesel::sql_query)\s*\(\s*&?\s*[a-zA-Z_]\w*\s*\)`)
	reSQLKeywords   = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+`)
)

// RS-004: Path traversal
var (
	rePathFromUser = regexp.MustCompile(`(?:std::)?fs::(?:read|write|read_to_string|read_dir|remove_file|remove_dir_all|create_dir_all|copy|rename|metadata)\s*\(\s*(?:format!\s*\(|&?\s*[a-zA-Z_]\w*)`)
	reTokioFS      = regexp.MustCompile(`tokio::fs::(?:read|write|read_to_string|remove_file|remove_dir_all|create_dir_all|copy|rename)\s*\(\s*(?:format!\s*\(|&?\s*[a-zA-Z_]\w*)`)
	rePathJoin     = regexp.MustCompile(`\.join\s*\(\s*(?:&?\s*[a-zA-Z_]\w*|format!\s*\()`)
)

// RS-005: Insecure deserialization
var (
	reSerdeFromStr   = regexp.MustCompile(`serde_json::from_str\s*\(`)
	reSerdeFromSlice = regexp.MustCompile(`serde_json::from_slice\s*\(`)
	reBincodeDe      = regexp.MustCompile(`bincode::deserialize\s*\(`)
	reRmpDe          = regexp.MustCompile(`rmp_serde::from_(?:read|slice)\s*\(`)
	reCborDe         = regexp.MustCompile(`ciborium::from_reader\s*\(`)
)

// RS-006: Insecure TLS
var (
	reDangerAcceptInvalidCerts = regexp.MustCompile(`\.danger_accept_invalid_certs\s*\(\s*true\s*\)`)
	reDangerAcceptInvalidHosts = regexp.MustCompile(`\.danger_accept_invalid_hostnames\s*\(\s*true\s*\)`)
	reTLSNativeNoVerify        = regexp.MustCompile(`TlsConnector::builder\s*\(\s*\)\s*(?:.*\n)*?.*\.danger_accept_invalid_certs\s*\(\s*true\s*\)`)
	reRustlsNoVerify           = regexp.MustCompile(`\.with_custom_certificate_verifier\s*\(`)
)

// RS-007: Panic in web handler
var (
	reUnwrapCall = regexp.MustCompile(`\.unwrap\s*\(\s*\)`)
	reExpectCall = regexp.MustCompile(`\.expect\s*\(\s*"`)
	// Actix/Axum handler detection
	reActixHandler = regexp.MustCompile(`(?:async\s+)?fn\s+\w+\s*\([^)]*(?:web::(?:Query|Path|Json|Form|Data)|HttpRequest|extract::(?:Query|Path|Json))`)
	reAxumHandler  = regexp.MustCompile(`(?:async\s+)?fn\s+\w+\s*\([^)]*(?:extract::(?:Query|Path|Json)|axum::extract)`)
	reRouteAttr    = regexp.MustCompile(`#\[(?:get|post|put|delete|patch)\s*\(`)
)

// RS-008: Insecure random
var (
	reThreadRng      = regexp.MustCompile(`\bthread_rng\s*\(\s*\)`)
	reRandGeneric    = regexp.MustCompile(`\brand::random\s*(?:::<|[(])`)
	reSecurityContext = regexp.MustCompile(`(?i)(?:token|secret|key|nonce|iv|salt|password|csrf|session|otp|api.?key|auth)`)
)

// RS-009: Memory unsafety patterns
var (
	reFromRawParts = regexp.MustCompile(`(?:slice::)?from_raw_parts(?:_mut)?\s*\(`)
	reMemForget    = regexp.MustCompile(`(?:std::mem::)?forget\s*\(`)
	reBoxFromRaw   = regexp.MustCompile(`Box::from_raw\s*\(`)
	reAsPtr        = regexp.MustCompile(`\.as_(?:mut_)?ptr\s*\(\s*\)`)
	rePtrWrite     = regexp.MustCompile(`(?:std::ptr::)?(?:write|read|copy|copy_nonoverlapping)\s*\(`)
	rePtrNull      = regexp.MustCompile(`(?:std::ptr::)?(?:null|null_mut)\s*\(\s*\)`)
)

// RS-010: CORS misconfiguration
var (
	reCorsPermissive  = regexp.MustCompile(`CorsLayer::(?:permissive|very_permissive)\s*\(\s*\)`)
	reCorsAnyOrigin   = regexp.MustCompile(`\.allow_origin\s*\(\s*(?:Any|HeaderValue::from_static\s*\(\s*"\*"\s*\))`)
	reCorsCredentials = regexp.MustCompile(`\.allow_credentials\s*\(\s*true\s*\)`)
	reActixCorsAny    = regexp.MustCompile(`Cors::(?:permissive|default)\s*\(\s*\)\s*(?:.*\n)*?.*\.allow_any_origin\s*\(\s*\)`)
	reActixCorsOpen   = regexp.MustCompile(`\.allow_any_origin\s*\(\s*\)`)
)

// ---------------------------------------------------------------------------
// Comment detection
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|/\*|\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// RS-001: Unsafe Block Usage
// ---------------------------------------------------------------------------

type UnsafeBlock struct{}

func (r UnsafeBlock) ID() string                    { return "BATOU-RS-001" }
func (r UnsafeBlock) Name() string                  { return "Unsafe Block Usage" }
func (r UnsafeBlock) DefaultSeverity() rules.Severity { return rules.Medium }
func (r UnsafeBlock) Description() string {
	return "Detects unsafe blocks containing raw pointer dereferences, transmute, or other memory-unsafe operations that bypass Rust's safety guarantees."
}
func (r UnsafeBlock) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r UnsafeBlock) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inUnsafe := false
	unsafeBraceDepth := 0
	unsafeStartLine := 0

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reUnsafeBlock.MatchString(line) {
			inUnsafe = true
			unsafeStartLine = i
			unsafeBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
		}

		if inUnsafe {
			if i != unsafeStartLine {
				unsafeBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			}

			severity := r.DefaultSeverity()
			var title, desc string

			if reTransmute.MatchString(line) || reTransmuteBytes.MatchString(line) {
				severity = rules.High
				title = "Unsafe transmute in unsafe block"
				desc = "std::mem::transmute reinterprets bits of one type as another, bypassing all type safety. Incorrect use causes undefined behavior, memory corruption, and potential code execution."
			} else if reFromRawParts.MatchString(line) {
				severity = rules.High
				title = "Unsafe from_raw_parts in unsafe block"
				desc = "slice::from_raw_parts constructs a slice from a raw pointer and length. Invalid pointer or length causes undefined behavior."
			} else if i == unsafeStartLine {
				title = "Unsafe block detected"
				desc = "This unsafe block bypasses Rust's memory safety guarantees. Review carefully for raw pointer dereferences, transmute calls, or FFI boundary issues."
			}

			if title != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      severity,
					SeverityLabel: severity.String(),
					Title:         title,
					Description:   desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Minimize unsafe blocks. Wrap unsafe operations in safe abstractions with documented safety invariants. Use #[deny(unsafe_op_in_unsafe_fn)] to require unsafe blocks inside unsafe fns.",
					CWEID:         "CWE-119",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "unsafe", "memory-safety"},
				})
			}

			if unsafeBraceDepth <= 0 {
				inUnsafe = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-002: Command Injection
// ---------------------------------------------------------------------------

type CommandInjection struct{}

func (r CommandInjection) ID() string                    { return "BATOU-RS-002" }
func (r CommandInjection) Name() string                  { return "Command Injection" }
func (r CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r CommandInjection) Description() string {
	return "Detects Command::new with format! or user-controlled input, and shell invocations (sh -c, bash -c) with dynamic arguments."
}
func (r CommandInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Shell invocation: Command::new("sh") / Command::new("bash")
		if reCommandNewShell.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "Shell invocation via Command::new",
				Description:   "Command::new invokes a shell interpreter (sh/bash/cmd). Any user-controlled data in .arg() arguments can inject arbitrary commands via shell metacharacters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Avoid shell invocation. Call the target program directly: Command::new(\"ping\").arg(\"-c\").arg(\"3\").arg(&host). This prevents shell metacharacter injection.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "command-injection", "shell"},
			})
			continue
		}

		// Command::new with format! macro
		if strings.Contains(line, "Command::new") && strings.Contains(line, "format!") {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "Command::new with format! string interpolation",
				Description:   "The program name passed to Command::new is constructed via format!, which may include user input. This allows command injection if the interpolated values are user-controlled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Pass a static program name to Command::new and use .arg() for dynamic values: Command::new(\"prog\").arg(&user_input).",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "command-injection", "format-string"},
			})
			continue
		}

		// .arg() with format! macro
		if reCommandArg.MatchString(line) && strings.Contains(line, "format!") {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Command .arg() with format! string interpolation",
				Description:   "A command argument is built with format!, which may include user input. If the command was invoked via a shell, this enables command injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Pass each argument separately: .arg(&value) instead of .arg(format!(\"--flag={}\", value)).",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "command-injection", "format-string"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-003: SQL Injection
// ---------------------------------------------------------------------------

type SQLInjection struct{}

func (r SQLInjection) ID() string                    { return "BATOU-RS-003" }
func (r SQLInjection) Name() string                  { return "SQL Injection" }
func (r SQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r SQLInjection) Description() string {
	return "Detects SQL queries built with format! or string concatenation in sqlx::query, diesel::sql_query, or rusqlite execute calls."
}
func (r SQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r SQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// SQL query with format! macro
		if reSQLFormat.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL query built with format! macro",
				Description:   "A SQL query is constructed using format! string interpolation. User-controlled values inserted via format! are not parameterized, enabling SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use parameterized queries: sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(&user_id), or the sqlx::query! macro for compile-time checked queries.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "sql-injection", "format-string"},
			})
			continue
		}

		// SQL query with string concatenation
		if reSQLConcat.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL query built with string concatenation",
				Description:   "A SQL query string is built via concatenation. If any concatenated part contains user input, this enables SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use parameterized queries with .bind() or the sqlx::query! macro. Never concatenate user input into SQL strings.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "sql-injection", "string-concat"},
			})
			continue
		}

		// SQL query with variable that might contain format! result
		if reSQLQueryVar.MatchString(line) {
			// Check nearby lines for format! building the query string
			hasFormat := false
			start := i - 5
			if start < 0 {
				start = 0
			}
			for j := start; j < i; j++ {
				if strings.Contains(lines[j], "format!") && reSQLKeywords.MatchString(lines[j]) {
					hasFormat = true
					break
				}
			}
			if hasFormat {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "SQL query variable built with format!",
					Description:   "A SQL query is passed as a variable that was constructed using format! with SQL keywords. This pattern enables SQL injection.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use parameterized queries: sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(&id).",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "sql-injection"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-004: Path Traversal
// ---------------------------------------------------------------------------

type PathTraversal struct{}

func (r PathTraversal) ID() string                    { return "BATOU-RS-004" }
func (r PathTraversal) Name() string                  { return "Path Traversal" }
func (r PathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r PathTraversal) Description() string {
	return "Detects std::fs and tokio::fs operations with user-controlled paths, and Path::join with user input without canonicalize/starts_with guards."
}
func (r PathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for path validation guards in the file
	hasCanonicalize := strings.Contains(ctx.Content, ".canonicalize()")
	hasStartsWith := strings.Contains(ctx.Content, ".starts_with(")
	hasFileName := strings.Contains(ctx.Content, ".file_name()")
	hasGuard := hasCanonicalize || (hasStartsWith && hasCanonicalize) || hasFileName

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Direct fs operations with variable path
		if rePathFromUser.MatchString(line) || reTokioFS.MatchString(line) {
			if hasGuard {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "File system operation with user-controlled path",
				Description:   "A file system operation uses a variable path without path traversal guards. An attacker can use ../ sequences to access files outside the intended directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Canonicalize the path and verify it starts with the allowed base directory: let canonical = path.canonicalize()?; assert!(canonical.starts_with(&base_dir));",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "path-traversal", "file-access"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-005: Insecure Deserialization
// ---------------------------------------------------------------------------

type InsecureDeserialization struct{}

func (r InsecureDeserialization) ID() string                    { return "BATOU-RS-005" }
func (r InsecureDeserialization) Name() string                  { return "Insecure Deserialization" }
func (r InsecureDeserialization) DefaultSeverity() rules.Severity { return rules.High }
func (r InsecureDeserialization) Description() string {
	return "Detects deserialization of untrusted data using serde_json, bincode, rmp_serde, or ciborium from potentially user-controlled sources."
}
func (r InsecureDeserialization) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r InsecureDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file has user input sources (web framework extractors, stdin, etc.)
	hasUserInput := strings.Contains(ctx.Content, "web::Json") ||
		strings.Contains(ctx.Content, "web::Query") ||
		strings.Contains(ctx.Content, "extract::Json") ||
		strings.Contains(ctx.Content, "HttpRequest") ||
		strings.Contains(ctx.Content, "hyper::Request") ||
		strings.Contains(ctx.Content, "stdin") ||
		strings.Contains(ctx.Content, "TcpStream") ||
		strings.Contains(ctx.Content, "body_bytes") ||
		strings.Contains(ctx.Content, "body_string")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Binary deserialization is always risky with untrusted input
		if reBincodeDe.MatchString(line) || reRmpDe.MatchString(line) || reCborDe.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Binary deserialization of potentially untrusted data",
				Description:   "Binary deserialization formats (bincode, rmp, ciborium) can cause panics or resource exhaustion when processing crafted input. Unlike JSON, binary formats provide less structural validation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Validate and limit input size before deserialization. Use bincode::Options::with_limit() or add explicit length checks. Prefer JSON for untrusted network input.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "deserialization", "binary-format"},
			})
			continue
		}

		// JSON deserialization in context with user input
		if hasUserInput && (reSerdeFromStr.MatchString(line) || reSerdeFromSlice.MatchString(line)) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "JSON deserialization of user-controlled data",
				Description:   "serde_json deserialization of user-controlled input. While serde_json is generally safe, deeply nested or large payloads can cause stack overflows or resource exhaustion.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Set payload size limits on the HTTP framework. Use serde_json::from_str with validated/bounded input. Consider adding #[serde(deny_unknown_fields)] on target structs.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"rust", "deserialization", "json"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-006: Insecure TLS
// ---------------------------------------------------------------------------

type InsecureTLS struct{}

func (r InsecureTLS) ID() string                    { return "BATOU-RS-006" }
func (r InsecureTLS) Name() string                  { return "Insecure TLS Configuration" }
func (r InsecureTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r InsecureTLS) Description() string {
	return "Detects TLS configurations that disable certificate verification via danger_accept_invalid_certs(true) or danger_accept_invalid_hostnames(true)."
}
func (r InsecureTLS) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r InsecureTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reDangerAcceptInvalidCerts.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "TLS certificate verification disabled",
				Description:   "danger_accept_invalid_certs(true) disables TLS certificate verification, allowing man-in-the-middle attacks. All TLS connections made with this client will accept any certificate, including self-signed and expired ones.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Remove danger_accept_invalid_certs(true). For self-signed certificates in development, use a custom CA bundle. For testing, gate this behind a test-only configuration.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "tls", "certificate-validation"},
			})
		}

		if reDangerAcceptInvalidHosts.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "TLS hostname verification disabled",
				Description:   "danger_accept_invalid_hostnames(true) disables hostname verification. A valid certificate for any domain will be accepted, enabling man-in-the-middle attacks via certificates issued for attacker-controlled domains.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Remove danger_accept_invalid_hostnames(true). Hostname verification ensures the certificate matches the server you intended to connect to.",
				CWEID:         "CWE-297",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "tls", "hostname-validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-007: Panic in Web Handler
// ---------------------------------------------------------------------------

type PanicInHandler struct{}

func (r PanicInHandler) ID() string                    { return "BATOU-RS-007" }
func (r PanicInHandler) Name() string                  { return "Panic in Web Handler" }
func (r PanicInHandler) DefaultSeverity() rules.Severity { return rules.Medium }
func (r PanicInHandler) Description() string {
	return "Detects .unwrap() and .expect() calls inside web request handlers. Panics in handlers can crash the server or cause denial of service."
}
func (r PanicInHandler) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r PanicInHandler) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only check files that look like web handlers
	isWebFile := reActixHandler.MatchString(ctx.Content) ||
		reAxumHandler.MatchString(ctx.Content) ||
		reRouteAttr.MatchString(ctx.Content)
	if !isWebFile {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	inHandler := false
	handlerBraceDepth := 0

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Detect handler function start
		if reActixHandler.MatchString(line) || reAxumHandler.MatchString(line) {
			inHandler = true
			handlerBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		// Also detect route attribute on previous line
		if i > 0 && reRouteAttr.MatchString(lines[i-1]) && strings.Contains(line, "fn ") {
			inHandler = true
			handlerBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inHandler {
			handlerBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if reUnwrapCall.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "unwrap() in web request handler",
					Description:   "Calling .unwrap() in a web request handler will panic and crash the handler (or the entire server if panic=abort) when the Result/Option is Err/None. This creates a denial-of-service vulnerability exploitable by crafted requests.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use ? operator to propagate errors: let value = operation()?; Or use .unwrap_or_default(), .unwrap_or_else(|_| ...), or match/if-let for explicit error handling.",
					CWEID:         "CWE-248",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "panic", "web-handler", "dos"},
				})
			}

			if reExpectCall.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "expect() in web request handler",
					Description:   "Calling .expect() in a web request handler will panic with the given message on Err/None. This can crash the handler or server, causing denial of service.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Replace .expect(\"msg\") with the ? operator and proper error response: let val = op().map_err(|e| HttpResponse::InternalServerError().body(\"error\"))?;",
					CWEID:         "CWE-248",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "panic", "web-handler", "dos"},
				})
			}

			if handlerBraceDepth <= 0 {
				inHandler = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-008: Insecure Random
// ---------------------------------------------------------------------------

type InsecureRandom struct{}

func (r InsecureRandom) ID() string                    { return "BATOU-RS-008" }
func (r InsecureRandom) Name() string                  { return "Insecure Random for Security Context" }
func (r InsecureRandom) DefaultSeverity() rules.Severity { return rules.Medium }
func (r InsecureRandom) Description() string {
	return "Detects use of rand::thread_rng() or rand::random() in security-sensitive contexts (token generation, key derivation, CSRF tokens) instead of OsRng or a CSPRNG."
}
func (r InsecureRandom) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r InsecureRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag if the file has security-sensitive context
	if !reSecurityContext.MatchString(ctx.Content) {
		return nil
	}

	// If OsRng is used, likely already using proper CSPRNG
	if strings.Contains(ctx.Content, "OsRng") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reThreadRng.MatchString(line) || reRandGeneric.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Non-cryptographic RNG in security-sensitive context",
				Description:   "thread_rng()/rand::random() uses a non-cryptographic PRNG (currently ChaCha12). While better than many PRNGs, for security-critical values (tokens, keys, nonces), use rand::rngs::OsRng which draws from the OS CSPRNG.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use OsRng for cryptographic operations: use rand::rngs::OsRng; let token: [u8; 32] = OsRng.gen(); Or use the rand crate's getrandom feature.",
				CWEID:         "CWE-338",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "random", "crypto"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-009: Memory Unsafety Patterns
// ---------------------------------------------------------------------------

type MemoryUnsafety struct{}

func (r MemoryUnsafety) ID() string                    { return "BATOU-RS-009" }
func (r MemoryUnsafety) Name() string                  { return "Memory Unsafety Patterns" }
func (r MemoryUnsafety) DefaultSeverity() rules.Severity { return rules.High }
func (r MemoryUnsafety) Description() string {
	return "Detects dangerous memory operations: transmute, from_raw_parts, mem::forget with manual Drop, Box::from_raw, and raw pointer operations that can cause memory corruption."
}
func (r MemoryUnsafety) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r MemoryUnsafety) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re         *regexp.Regexp
		title      string
		desc       string
		suggestion string
		confidence string
		cweid      string
	}

	patterns := []pattern{
		{
			reTransmute,
			"Unsafe transmute call",
			"std::mem::transmute reinterprets bits of one type as another without any checks. Incorrect transmute can cause undefined behavior, create invalid values, or violate invariants.",
			"Use safe casts (as, From/Into), or bytemuck::cast for POD types. If transmute is necessary, document the exact safety invariants.",
			"high",
			"CWE-704",
		},
		{
			reFromRawParts,
			"Unsafe from_raw_parts",
			"slice::from_raw_parts constructs a slice from a raw pointer and length. If the pointer is invalid, the length exceeds allocated memory, or the memory is not properly aligned, this causes undefined behavior.",
			"Ensure the pointer is valid, properly aligned, and points to allocated memory of at least the specified length. Prefer safe slice operations.",
			"high",
			"CWE-119",
		},
		{
			reMemForget,
			"mem::forget usage (potential resource leak)",
			"std::mem::forget prevents the destructor from running. If paired with manual resource cleanup or Drop implementations, forgetting to call the destructor can leak resources or cause double-free if cleanup is done elsewhere.",
			"Use ManuallyDrop instead of mem::forget for clearer ownership semantics. Ensure any paired manual cleanup is correctly handled.",
			"medium",
			"CWE-401",
		},
		{
			reBoxFromRaw,
			"Box::from_raw (unsafe ownership transfer)",
			"Box::from_raw takes ownership of a raw pointer. The pointer must have been allocated via Box (or the global allocator), and must not be freed elsewhere. Double-free or use-after-free results from incorrect usage.",
			"Ensure the pointer was originally created by Box::into_raw or the global allocator. Each raw pointer must be reconstituted into Box exactly once.",
			"high",
			"CWE-415",
		},
		{
			rePtrWrite,
			"Raw pointer write/read/copy operation",
			"Direct raw pointer operations (ptr::write, ptr::read, ptr::copy) bypass Rust's safety guarantees. Invalid pointers, overlapping regions, or incorrect sizes cause undefined behavior.",
			"Prefer safe abstractions. If raw pointers are necessary, document safety invariants and minimize the scope of unsafe blocks.",
			"medium",
			"CWE-119",
		},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		for _, p := range patterns {
			if p.re.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         p.title,
					Description:   p.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    p.suggestion,
					CWEID:         p.cweid,
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    p.confidence,
					Tags:          []string{"rust", "memory-safety", "unsafe"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// RS-010: CORS Misconfiguration
// ---------------------------------------------------------------------------

type CORSMisconfig struct{}

func (r CORSMisconfig) ID() string                    { return "BATOU-RS-010" }
func (r CORSMisconfig) Name() string                  { return "CORS Misconfiguration" }
func (r CORSMisconfig) DefaultSeverity() rules.Severity { return rules.Medium }
func (r CORSMisconfig) Description() string {
	return "Detects overly permissive CORS configurations: CorsLayer::permissive(), any origin with credentials, or Cors::permissive() in Actix."
}
func (r CORSMisconfig) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r CORSMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// CorsLayer::permissive() (tower-http)
		if reCorsPermissive.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CorsLayer::permissive() allows all origins",
				Description:   "CorsLayer::permissive() allows requests from any origin with any method and headers. This is intended for development only and should not be used in production.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Configure CORS explicitly: CorsLayer::new().allow_origin([\"https://yourdomain.com\".parse().unwrap()]).allow_methods([Method::GET, Method::POST]).",
				CWEID:         "CWE-942",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "cors", "misconfiguration"},
			})
			continue
		}

		// Actix Cors::permissive()
		if strings.Contains(line, "Cors::permissive()") {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Actix Cors::permissive() allows all origins",
				Description:   "Cors::permissive() in Actix-web allows requests from any origin. This bypasses same-origin policy protections.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Configure CORS with specific allowed origins: Cors::default().allowed_origin(\"https://yourdomain.com\").",
				CWEID:         "CWE-942",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "cors", "actix", "misconfiguration"},
			})
			continue
		}

		// Any origin with credentials
		if reActixCorsOpen.MatchString(line) || reCorsAnyOrigin.MatchString(line) {
			// Check if credentials are also enabled nearby
			start := i - 5
			if start < 0 {
				start = 0
			}
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			for j := start; j < end; j++ {
				if reCorsCredentials.MatchString(lines[j]) {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      rules.High,
						SeverityLabel: rules.High.String(),
						Title:         "CORS allows any origin with credentials",
						Description:   "CORS is configured to allow any origin AND allow credentials. This combination allows any website to make authenticated requests to your API, potentially stealing user data or performing unauthorized actions.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   truncate(line, 120),
						Suggestion:    "Never combine allow_any_origin with allow_credentials(true). Specify exact allowed origins when credentials are needed.",
						CWEID:         "CWE-942",
						OWASPCategory: "A05:2021-Security Misconfiguration",
						Language:      ctx.Language,
						Confidence:    "high",
						Tags:          []string{"rust", "cors", "credentials", "misconfiguration"},
					})
					break
				}
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(UnsafeBlock{})
	rules.Register(CommandInjection{})
	rules.Register(SQLInjection{})
	rules.Register(PathTraversal{})
	rules.Register(InsecureDeserialization{})
	rules.Register(InsecureTLS{})
	rules.Register(PanicInHandler{})
	rules.Register(InsecureRandom{})
	rules.Register(MemoryUnsafety{})
	rules.Register(CORSMisconfig{})
}
