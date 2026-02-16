package rust

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Rust extension rules (BATOU-RS-011 .. BATOU-RS-018)
// ---------------------------------------------------------------------------

// RS-011: Unsafe block with raw pointer dereference
var (
	reUnsafeDeref     = regexp.MustCompile(`\bunsafe\s*\{`)
	reRawPtrDerefStar = regexp.MustCompile(`\*(?:mut\s+|const\s+)?\w+\.\w+|\*\w+\s*[;,=]`)
	rePtrOffset       = regexp.MustCompile(`\.offset\s*\(|\.add\s*\(|\.sub\s*\(`)
	reDerefRaw        = regexp.MustCompile(`\*\s*[a-zA-Z_]\w*\s*(?:\.|\[|as\s)`)
)

// RS-012: SQL injection via format! in query
var (
	reSQLFormatDirect  = regexp.MustCompile(`format!\s*\(\s*"[^"]*(?i:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+`)
	reSQLQueryFormat   = regexp.MustCompile(`(?:query|execute|prepare)\s*\(\s*&?\s*format!\s*\(`)
	reSQLConcatDirect  = regexp.MustCompile(`"[^"]*(?i:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*"\s*\.\s*to_owned|format!\s*\([^)]*(?i:SELECT|INSERT)`)
)

// RS-013: std::process::Command with user input
var (
	reCommandNewVar   = regexp.MustCompile(`Command::new\s*\(\s*&?\s*[a-zA-Z_]\w*\s*\)`)
	reCommandArgVar   = regexp.MustCompile(`\.arg\s*\(\s*&?\s*format!\s*\(`)
	reCommandShellUser = regexp.MustCompile(`Command::new\s*\(\s*"(?:sh|bash|cmd|powershell)"\s*\)\s*\.\s*arg\s*\(\s*"-c"\s*\)\s*\.\s*arg\s*\(`)
)

// RS-014: unwrap() in production code
var (
	reUnwrapGeneric  = regexp.MustCompile(`\.unwrap\s*\(\s*\)`)
	reExpectGeneric  = regexp.MustCompile(`\.expect\s*\(\s*"`)
	// Context to determine it's not a test
	reTestAttr       = regexp.MustCompile(`#\[(?:test|cfg\s*\(\s*test\s*\))]`)
	reTestMod        = regexp.MustCompile(`mod\s+tests?\s*\{`)
)

// RS-015: transmute between incompatible types
var (
	reTransmuteCall   = regexp.MustCompile(`transmute\s*::\s*<[^>]+,\s*[^>]+>\s*\(`)
	reTransmuteGeneric = regexp.MustCompile(`(?:std::mem::)?transmute\s*\(`)
	reTransmuteUnchecked = regexp.MustCompile(`transmute_copy\s*\(`)
)

// RS-016: regex without size/time limit
var (
	reRegexNew       = regexp.MustCompile(`Regex::new\s*\(\s*(?:&?\s*[a-zA-Z_]\w*|&?\s*format!\s*\()`)
	reRegexSetNew    = regexp.MustCompile(`RegexSet::new\s*\(`)
	reRegexSizeLimit = regexp.MustCompile(`\.size_limit\s*\(|RegexBuilder.*\.size_limit|\.dfa_size_limit`)
)

// RS-017: actix-web/warp/axum without TLS config
var (
	reActixBind      = regexp.MustCompile(`HttpServer::new.*\.bind\s*\(\s*"(?:0\.0\.0\.0|127\.0\.0\.1|localhost):\d+"`)
	reWarpServe      = regexp.MustCompile(`warp::serve\s*\(.*\)\s*\.run\s*\(`)
	reAxumBind       = regexp.MustCompile(`axum::Server::bind\s*\(|TcpListener::bind\s*\(`)
	reTLSConfig      = regexp.MustCompile(`\.bind_rustls|\.bind_openssl|\.tls\s*\(|RustlsConfig|SslAcceptor|\.tls_config`)
)

// RS-018: FFI without proper bounds checking
var (
	reExternBlock    = regexp.MustCompile(`extern\s+"C"\s*\{`)
	reFFIFnDecl      = regexp.MustCompile(`pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+\w+\s*\(`)
	reFFIRawPtr      = regexp.MustCompile(`\*(?:mut|const)\s+\w+`)
	reCStringFromPtr  = regexp.MustCompile(`CStr::from_ptr\s*\(|CString::from_raw\s*\(`)
	reSliceFromPtr   = regexp.MustCompile(`slice::from_raw_parts\s*\(|Vec::from_raw_parts\s*\(`)
)

func init() {
	rules.Register(RustUnsafePtrDeref{})
	rules.Register(RustSQLFormat{})
	rules.Register(RustCommandUser{})
	rules.Register(RustUnwrapProd{})
	rules.Register(RustTransmuteIncompat{})
	rules.Register(RustRegexNoLimit{})
	rules.Register(RustNoTLS{})
	rules.Register(RustFFIBounds{})
}

// ---------------------------------------------------------------------------
// BATOU-RS-011: Rust unsafe block with raw pointer dereference
// ---------------------------------------------------------------------------

type RustUnsafePtrDeref struct{}

func (r RustUnsafePtrDeref) ID() string                      { return "BATOU-RS-011" }
func (r RustUnsafePtrDeref) Name() string                    { return "RustUnsafePtrDeref" }
func (r RustUnsafePtrDeref) Description() string             { return "Detects Rust unsafe blocks containing raw pointer dereferences or offset arithmetic, which bypass memory safety." }
func (r RustUnsafePtrDeref) DefaultSeverity() rules.Severity { return rules.High }
func (r RustUnsafePtrDeref) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustUnsafePtrDeref) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inUnsafe := false
	unsafeBraceDepth := 0

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reUnsafeDeref.MatchString(line) {
			inUnsafe = true
			unsafeBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
		}

		if inUnsafe {
			if !reUnsafeDeref.MatchString(line) {
				unsafeBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			}

			if reDerefRaw.MatchString(line) || rePtrOffset.MatchString(line) {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Rust unsafe raw pointer dereference",
					Description:   "A raw pointer is dereferenced or manipulated via offset/add/sub inside an unsafe block. Invalid pointer arithmetic or dereferencing a dangling/null pointer causes undefined behavior: memory corruption, data races, or arbitrary code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Verify pointer validity before dereferencing: check for null, ensure the pointer is aligned, and confirm the memory is still allocated. Use safe abstractions where possible. Document safety invariants with // SAFETY: comments.",
					CWEID:         "CWE-787",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"rust", "unsafe", "pointer-deref", "memory-safety"},
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
// BATOU-RS-012: Rust SQL injection via format! in query
// ---------------------------------------------------------------------------

type RustSQLFormat struct{}

func (r RustSQLFormat) ID() string                      { return "BATOU-RS-012" }
func (r RustSQLFormat) Name() string                    { return "RustSQLFormat" }
func (r RustSQLFormat) Description() string             { return "Detects Rust SQL injection via format! macro building SQL query strings." }
func (r RustSQLFormat) DefaultSeverity() rules.Severity { return rules.High }
func (r RustSQLFormat) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustSQLFormat) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reSQLQueryFormat.FindString(line); m != "" {
			matched = m
			desc = "A SQL query method (query/execute/prepare) receives a string built with format!(). User input interpolated via format! is not parameterized, enabling SQL injection."
		} else if m := reSQLFormatDirect.FindString(line); m != "" {
			matched = m
			desc = "A format! macro builds a string containing SQL keywords (SELECT, INSERT, UPDATE, DELETE). If this string is used in a database query, interpolated values enable SQL injection."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust SQL injection via format! macro",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries: sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(&id) or the sqlx::query! compile-time checked macro. For diesel, use .filter(column.eq(value)).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "sql-injection", "format-macro"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-013: Rust std::process::Command with user input
// ---------------------------------------------------------------------------

type RustCommandUser struct{}

func (r RustCommandUser) ID() string                      { return "BATOU-RS-013" }
func (r RustCommandUser) Name() string                    { return "RustCommandUser" }
func (r RustCommandUser) Description() string             { return "Detects Rust std::process::Command with variable program names or format! in arguments, enabling command injection." }
func (r RustCommandUser) DefaultSeverity() rules.Severity { return rules.High }
func (r RustCommandUser) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustCommandUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reCommandShellUser.FindString(line); m != "" {
			matched = m
			desc = "Command::new invokes a shell (sh/bash/cmd) with -c flag and a user-controlled argument. The shell interprets metacharacters in the argument, enabling arbitrary command injection."
		} else if m := reCommandNewVar.FindString(line); m != "" {
			matched = m
			desc = "Command::new() receives a variable as the program name. If the variable is user-controlled, an attacker can execute any binary on the system."
		} else if m := reCommandArgVar.FindString(line); m != "" {
			matched = m
			desc = "Command .arg() receives a format! string. If the formatted string contains user input and the command runs through a shell, this enables command injection."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust Command with user input",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use a static program name in Command::new and pass user input as separate .arg() calls: Command::new(\"ls\").arg(&user_path). Never invoke sh -c with user input. Validate the program name against an allowlist.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "command-injection", "process"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-014: Rust unwrap() in production code
// ---------------------------------------------------------------------------

type RustUnwrapProd struct{}

func (r RustUnwrapProd) ID() string                      { return "BATOU-RS-014" }
func (r RustUnwrapProd) Name() string                    { return "RustUnwrapProd" }
func (r RustUnwrapProd) Description() string             { return "Detects Rust unwrap()/expect() calls outside test code that can panic in production, causing denial of service." }
func (r RustUnwrapProd) DefaultSeverity() rules.Severity { return rules.Medium }
func (r RustUnwrapProd) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustUnwrapProd) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip test files
	if strings.Contains(ctx.FilePath, "_test") || strings.Contains(ctx.FilePath, "/tests/") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inTestMod := false
	testBraceDepth := 0

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Track test modules to skip
		if reTestAttr.MatchString(line) || reTestMod.MatchString(line) {
			inTestMod = true
			testBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inTestMod {
			testBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if testBraceDepth <= 0 {
				inTestMod = false
			}
			continue
		}

		if reUnwrapGeneric.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust unwrap() in production code (panic risk)",
				Description:   "Calling .unwrap() panics when the Result is Err or the Option is None. In production code, this can crash the application or thread, causing denial of service if triggered by user input (e.g., invalid data, missing fields).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use the ? operator for error propagation, .unwrap_or_default() for safe defaults, or match/if-let for explicit handling. Reserve unwrap() for cases with compile-time proof of safety (e.g., static regex).",
				CWEID:         "CWE-248",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"rust", "unwrap", "panic", "dos"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-015: Rust transmute between incompatible types
// ---------------------------------------------------------------------------

type RustTransmuteIncompat struct{}

func (r RustTransmuteIncompat) ID() string                      { return "BATOU-RS-015" }
func (r RustTransmuteIncompat) Name() string                    { return "RustTransmuteIncompat" }
func (r RustTransmuteIncompat) Description() string             { return "Detects Rust transmute/transmute_copy calls which reinterpret memory between types, bypassing all type safety." }
func (r RustTransmuteIncompat) DefaultSeverity() rules.Severity { return rules.High }
func (r RustTransmuteIncompat) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustTransmuteIncompat) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reTransmuteCall.FindString(line); m != "" {
			matched = m
			desc = "transmute with explicit type parameters reinterprets the bits of one type as another. If the types have different sizes, layouts, or invariants, this causes undefined behavior including memory corruption."
		} else if m := reTransmuteUnchecked.FindString(line); m != "" {
			matched = m
			desc = "transmute_copy copies the bits of a value and reinterprets them as another type. Unlike transmute, it does not check that the types are the same size, making it even more dangerous."
		} else if m := reTransmuteGeneric.FindString(line); m != "" {
			matched = m
			desc = "transmute call detected. std::mem::transmute reinterprets bits without any safety checks. Incorrect usage causes undefined behavior, invalid values, or memory corruption."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust transmute between types (type safety bypass)",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use safe alternatives: as for numeric casts, From/Into for conversions, bytemuck::cast for POD types, or zerocopy for zero-copy parsing. If transmute is unavoidable, add a // SAFETY: comment explaining why the conversion is valid.",
				CWEID:         "CWE-843",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "transmute", "type-confusion", "memory-safety"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-016: Rust regex without size/time limit
// ---------------------------------------------------------------------------

type RustRegexNoLimit struct{}

func (r RustRegexNoLimit) ID() string                      { return "BATOU-RS-016" }
func (r RustRegexNoLimit) Name() string                    { return "RustRegexNoLimit" }
func (r RustRegexNoLimit) Description() string             { return "Detects Rust Regex::new() with variable or format! patterns without size_limit, enabling ReDoS." }
func (r RustRegexNoLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r RustRegexNoLimit) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustRegexNoLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if size limits are configured
	if reRegexSizeLimit.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reRegexNew.FindString(line); m != "" {
			matched = m
		} else if m := reRegexSetNew.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust Regex without size/time limit",
				Description:   "Regex::new() is called with a variable or dynamic pattern without configuring a size_limit. While Rust's regex crate guarantees linear-time matching, a user-controlled pattern can still compile into a very large DFA consuming excessive memory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use RegexBuilder with size_limit and dfa_size_limit: RegexBuilder::new(&pattern).size_limit(1_000_000).dfa_size_limit(1_000_000).build(). Validate pattern length before compilation.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "regex", "redos", "resource-limit"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-017: Rust actix-web/warp/axum without TLS config
// ---------------------------------------------------------------------------

type RustNoTLS struct{}

func (r RustNoTLS) ID() string                      { return "BATOU-RS-017" }
func (r RustNoTLS) Name() string                    { return "RustNoTLS" }
func (r RustNoTLS) Description() string             { return "Detects Rust web servers (actix-web, warp, axum) binding to addresses without TLS configuration." }
func (r RustNoTLS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r RustNoTLS) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustNoTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if TLS is configured
	if reTLSConfig.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reActixBind.FindString(line); m != "" {
			matched = m
			desc = "Actix-web HttpServer binds to an address without TLS (bind instead of bind_rustls/bind_openssl). All HTTP traffic is transmitted in plaintext."
		} else if m := reWarpServe.FindString(line); m != "" {
			matched = m
			desc = "Warp server runs without TLS (.run instead of .tls). All HTTP traffic is transmitted in plaintext."
		} else if m := reAxumBind.FindString(line); m != "" {
			matched = m
			desc = "Axum server binds to an address without TLS configuration. All HTTP traffic is transmitted in plaintext."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust web server without TLS",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Configure TLS: for Actix use .bind_rustls() or .bind_openssl(); for Warp use .tls().cert_path().key_path(); for Axum use axum_server::bind_rustls(). Alternatively, terminate TLS at a reverse proxy (nginx, Caddy).",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "tls", "plaintext", "web-server"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-018: Rust FFI without proper bounds checking
// ---------------------------------------------------------------------------

type RustFFIBounds struct{}

func (r RustFFIBounds) ID() string                      { return "BATOU-RS-018" }
func (r RustFFIBounds) Name() string                    { return "RustFFIBounds" }
func (r RustFFIBounds) Description() string             { return "Detects Rust FFI (extern \"C\") functions with raw pointer parameters or unsafe C string/slice conversions without bounds checking." }
func (r RustFFIBounds) DefaultSeverity() rules.Severity { return rules.High }
func (r RustFFIBounds) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustFFIBounds) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: no FFI in the file
	if !reExternBlock.MatchString(ctx.Content) && !reFFIFnDecl.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if reFFIFnDecl.MatchString(line) && reFFIRawPtr.MatchString(line) {
			matched = strings.TrimSpace(line)
			desc = "An extern \"C\" function accepts raw pointer parameters. Raw pointers from C code may be null, dangling, misaligned, or point to insufficient memory. Without validation, dereferencing these pointers causes undefined behavior."
		} else if m := reCStringFromPtr.FindString(line); m != "" {
			matched = m
			desc = "CStr::from_ptr or CString::from_raw constructs a Rust string from a C pointer. If the C string is not null-terminated, not valid UTF-8, or the pointer is invalid, this causes undefined behavior or panics."
		} else if m := reSliceFromPtr.FindString(line); m != "" {
			// Only flag in FFI context
			if strings.Contains(ctx.Content, "extern \"C\"") {
				matched = m
				desc = "slice::from_raw_parts or Vec::from_raw_parts in FFI context. The C caller must guarantee the pointer is valid, properly aligned, and the length does not exceed allocated memory. Buffer overflows result from incorrect length values."
			}
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rust FFI without proper bounds checking",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate all FFI inputs: check pointers for null before dereferencing, validate lengths against known bounds, use CStr::from_ptr only on null-terminated strings. Add // SAFETY: comments documenting caller requirements.",
				CWEID:         "CWE-120",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "ffi", "bounds-checking", "memory-safety"},
			})
		}
	}
	return findings
}
