package rust

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Rust generated rules (BATOU-RS-019 .. BATOU-RS-028)
// ---------------------------------------------------------------------------

// RS-019: transmute type confusion
var (
	reTransmuteUsage = regexp.MustCompile(`(?:std::mem::)?transmute\s*[:<(]|(?:std::mem::)?transmute\s*\(`)
)

// RS-020: Box::from_raw double-free
var (
	reBoxFromRawCall = regexp.MustCompile(`Box::from_raw\s*\(`)
)

// RS-021: Integer overflow in unsafe
var (
	reUnsafeBlockStart = regexp.MustCompile(`\bunsafe\s*\{`)
	rePtrAddOffset     = regexp.MustCompile(`\.(?:add|offset)\s*\(`)
	reCheckedAdd       = regexp.MustCompile(`checked_add`)
)

// RS-022: FFI null check missing
var (
	reExternCFn      = regexp.MustCompile(`extern\s+"C"`)
	rePtrRetUnwrap   = regexp.MustCompile(`\.unwrap\s*\(\s*\)`)
)

// RS-023: libc unsafe functions
var (
	reLibcUnsafe = regexp.MustCompile(`libc::(?:memcpy|strcpy|strcat|sprintf)\s*\(`)
)

// RS-024: Tokio async race
var (
	reMutRefAwait = regexp.MustCompile(`&\s*mut\s+\w+.*\.await|\.await.*&\s*mut\s+\w+`)
)

// RS-025: Cargo wildcard dependency
var (
	reCargoWildcard = regexp.MustCompile(`=\s*"\*"`)
)

// RS-026: Diesel raw SQL injection
var (
	reDieselSQLFormat = regexp.MustCompile(`sql_query\s*\(\s*&?\s*format!\s*\(`)
)

// RS-027: Unsafe without safety comment
var (
	reUnsafeBrace  = regexp.MustCompile(`\bunsafe\s*\{`)
	reSafetyComment = regexp.MustCompile(`//\s*SAFETY:`)
)

// RS-028: Missing deny unsafe_op_in_unsafe_fn
var (
	rePubUnsafeFn     = regexp.MustCompile(`pub\s+unsafe\s+fn\s+`)
	reDenyUnsafeOp    = regexp.MustCompile(`deny\s*\(\s*unsafe_op_in_unsafe_fn\s*\)`)
)

func init() {
	rules.Register(RustTransmuteConfusion{})
	rules.Register(RustBoxFromRawDoubleFree{})
	rules.Register(RustIntOverflowUnsafe{})
	rules.Register(RustFFINullCheck{})
	rules.Register(RustLibcUnsafe{})
	rules.Register(RustTokioAsyncRace{})
	rules.Register(RustCargoWildcard{})
	rules.Register(RustDieselSQLi{})
	rules.Register(RustUnsafeNoSafety{})
	rules.Register(RustMissingDenyUnsafeOp{})
}

// ---------------------------------------------------------------------------
// BATOU-RS-019: transmute type confusion
// ---------------------------------------------------------------------------

type RustTransmuteConfusion struct{}

func (r RustTransmuteConfusion) ID() string                      { return "BATOU-RS-019" }
func (r RustTransmuteConfusion) Name() string                    { return "RustTransmuteConfusion" }
func (r RustTransmuteConfusion) Description() string             { return "Detects std::mem::transmute usage which reinterprets bits of one type as another, bypassing all type safety and potentially causing undefined behavior." }
func (r RustTransmuteConfusion) DefaultSeverity() rules.Severity { return rules.Critical }
func (r RustTransmuteConfusion) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustTransmuteConfusion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reTransmuteUsage.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Type confusion via std::mem::transmute",
				Description:   "std::mem::transmute reinterprets the bits of one type as another without any validation. Transmuting between incompatible types causes undefined behavior, including memory corruption, invalid enum discriminants, and violation of type invariants that can lead to arbitrary code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use safe alternatives: as casts for numeric conversions, From/Into traits, or bytemuck::cast for POD types. If transmute is unavoidable, add a // SAFETY: comment documenting the exact invariants being upheld.",
				CWEID:         "CWE-843",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "transmute", "type-confusion", "unsafe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-020: Box::from_raw double-free
// ---------------------------------------------------------------------------

type RustBoxFromRawDoubleFree struct{}

func (r RustBoxFromRawDoubleFree) ID() string                      { return "BATOU-RS-020" }
func (r RustBoxFromRawDoubleFree) Name() string                    { return "RustBoxFromRawDoubleFree" }
func (r RustBoxFromRawDoubleFree) Description() string             { return "Detects Box::from_raw() which takes ownership of a raw pointer. Incorrect usage leads to double-free or use-after-free vulnerabilities." }
func (r RustBoxFromRawDoubleFree) DefaultSeverity() rules.Severity { return rules.Critical }
func (r RustBoxFromRawDoubleFree) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustBoxFromRawDoubleFree) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reBoxFromRawCall.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Box::from_raw may cause double-free",
				Description:   "Box::from_raw() takes ownership of a raw pointer and will deallocate the memory when the Box is dropped. If the same pointer is passed to Box::from_raw() more than once, or if the pointer was not allocated by Box, this causes a double-free vulnerability that can lead to memory corruption and arbitrary code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Ensure the pointer was originally created by Box::into_raw() and is reconstituted exactly once. Document ownership transfer with // SAFETY: comments. Consider using Arc or Rc for shared ownership instead.",
				CWEID:         "CWE-415",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "double-free", "box", "memory-safety", "unsafe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-021: Integer overflow in unsafe
// ---------------------------------------------------------------------------

type RustIntOverflowUnsafe struct{}

func (r RustIntOverflowUnsafe) ID() string                      { return "BATOU-RS-021" }
func (r RustIntOverflowUnsafe) Name() string                    { return "RustIntOverflowUnsafe" }
func (r RustIntOverflowUnsafe) Description() string             { return "Detects pointer .add() or .offset() inside unsafe blocks without checked_add, which can cause integer overflow leading to out-of-bounds memory access." }
func (r RustIntOverflowUnsafe) DefaultSeverity() rules.Severity { return rules.High }
func (r RustIntOverflowUnsafe) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustIntOverflowUnsafe) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasCheckedAdd := reCheckedAdd.MatchString(ctx.Content)
	if hasCheckedAdd {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inUnsafe := false
	unsafeBraceDepth := 0

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reUnsafeBlockStart.MatchString(line) {
			inUnsafe = true
			unsafeBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inUnsafe {
			unsafeBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if rePtrAddOffset.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Pointer arithmetic in unsafe block without overflow check",
					Description:   "Pointer .add() or .offset() is used inside an unsafe block without checked_add to guard against integer overflow. If the offset calculation overflows, the resulting pointer will point to an unintended memory location, causing out-of-bounds reads or writes.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use checked_add() to detect overflow before pointer arithmetic: let offset = base.checked_add(count).expect(\"overflow\"); Alternatively, use safe slice indexing with bounds checks.",
					CWEID:         "CWE-190",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "integer-overflow", "pointer-arithmetic", "unsafe"},
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
// BATOU-RS-022: FFI null check missing
// ---------------------------------------------------------------------------

type RustFFINullCheck struct{}

func (r RustFFINullCheck) ID() string                      { return "BATOU-RS-022" }
func (r RustFFINullCheck) Name() string                    { return "RustFFINullCheck" }
func (r RustFFINullCheck) Description() string             { return "Detects extern \"C\" FFI functions whose return values are used with .unwrap() without null pointer checks." }
func (r RustFFINullCheck) DefaultSeverity() rules.Severity { return rules.High }
func (r RustFFINullCheck) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustFFINullCheck) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reExternCFn.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if rePtrRetUnwrap.MatchString(line) && strings.Contains(ctx.Content, "extern \"C\"") {
			// Check if there's a null check nearby
			start := i - 3
			if start < 0 {
				start = 0
			}
			hasNullCheck := false
			for j := start; j < i; j++ {
				if strings.Contains(lines[j], "is_null") || strings.Contains(lines[j], "as_ref") ||
					strings.Contains(lines[j], "NonNull") {
					hasNullCheck = true
					break
				}
			}
			if !hasNullCheck {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "FFI return value unwrapped without null check",
					Description:   "A value from an extern \"C\" FFI function is used with .unwrap() without a prior null pointer check. C functions commonly return null pointers on failure, and unwrapping without checking will panic, crashing the program.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Check for null before unwrapping: let ptr = unsafe { ffi_func() }; if ptr.is_null() { return Err(...); }. Or use NonNull::new(ptr).ok_or(\"null pointer\").",
					CWEID:         "CWE-476",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "ffi", "null-pointer", "unwrap"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-023: libc unsafe functions
// ---------------------------------------------------------------------------

type RustLibcUnsafe struct{}

func (r RustLibcUnsafe) ID() string                      { return "BATOU-RS-023" }
func (r RustLibcUnsafe) Name() string                    { return "RustLibcUnsafe" }
func (r RustLibcUnsafe) Description() string             { return "Detects usage of libc::memcpy, libc::strcpy, libc::strcat, and libc::sprintf, which are inherently unsafe C functions prone to buffer overflows." }
func (r RustLibcUnsafe) DefaultSeverity() rules.Severity { return rules.High }
func (r RustLibcUnsafe) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustLibcUnsafe) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reLibcUnsafe.MatchString(line) {
			funcName := "libc function"
			if strings.Contains(line, "memcpy") {
				funcName = "libc::memcpy"
			} else if strings.Contains(line, "strcpy") {
				funcName = "libc::strcpy"
			} else if strings.Contains(line, "strcat") {
				funcName = "libc::strcat"
			} else if strings.Contains(line, "sprintf") {
				funcName = "libc::sprintf"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe C function " + funcName + " used in Rust code",
				Description:   funcName + " is a C function with no bounds checking. Buffer overflows from incorrect length arguments or unbounded string copies can corrupt memory, overwrite return addresses, and enable arbitrary code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use Rust's safe alternatives: Vec::copy_from_slice instead of memcpy, String/CString instead of strcpy/strcat, and format! or write! instead of sprintf. These provide bounds checking and memory safety.",
				CWEID:         "CWE-120",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "libc", "buffer-overflow", "unsafe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-024: Tokio async race
// ---------------------------------------------------------------------------

type RustTokioAsyncRace struct{}

func (r RustTokioAsyncRace) ID() string                      { return "BATOU-RS-024" }
func (r RustTokioAsyncRace) Name() string                    { return "RustTokioAsyncRace" }
func (r RustTokioAsyncRace) Description() string             { return "Detects mutable references used across .await points in async code, which can lead to data races if the future is shared." }
func (r RustTokioAsyncRace) DefaultSeverity() rules.Severity { return rules.High }
func (r RustTokioAsyncRace) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustTokioAsyncRace) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, ".await") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reMutRefAwait.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Mutable reference held across .await point",
				Description:   "A mutable reference (&mut) appears on the same line as .await, suggesting it may be held across an await point. When a future yields at .await, another task could access the same data if shared via Arc<Mutex<>> with insufficient locking, leading to data races.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Drop the mutable reference before .await: { let val = &mut data; *val = compute(); } async_op().await;. Use tokio::sync::Mutex instead of std::sync::Mutex for locks held across .await.",
				CWEID:         "CWE-362",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "async", "tokio", "race-condition"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-025: Cargo wildcard dependency
// ---------------------------------------------------------------------------

type RustCargoWildcard struct{}

func (r RustCargoWildcard) ID() string                      { return "BATOU-RS-025" }
func (r RustCargoWildcard) Name() string                    { return "RustCargoWildcard" }
func (r RustCargoWildcard) Description() string             { return "Detects wildcard (\"*\") version specifications in Cargo.toml, which accept any version including those with known vulnerabilities." }
func (r RustCargoWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r RustCargoWildcard) Languages() []rules.Language     { return []rules.Language{rules.LangRust, rules.LangAny} }

func (r RustCargoWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	lower := strings.ToLower(ctx.FilePath)
	if !strings.HasSuffix(lower, "cargo.toml") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if reCargoWildcard.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Cargo.toml wildcard dependency version",
				Description:   "A dependency in Cargo.toml uses a wildcard version (\"*\"), which accepts any version including major versions with breaking changes or known security vulnerabilities. This makes builds non-reproducible and exposes the project to supply chain attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Pin dependencies to specific versions or use semver ranges: \"1.2\" (compatible with 1.2.x) or \"=1.2.3\" (exact). Run cargo audit regularly to check for known vulnerabilities.",
				CWEID:         "CWE-829",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "cargo", "dependency", "supply-chain"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-026: Diesel raw SQL injection
// ---------------------------------------------------------------------------

type RustDieselSQLi struct{}

func (r RustDieselSQLi) ID() string                      { return "BATOU-RS-026" }
func (r RustDieselSQLi) Name() string                    { return "RustDieselSQLi" }
func (r RustDieselSQLi) Description() string             { return "Detects diesel::sql_query with format! macro, which constructs SQL queries via string interpolation instead of parameterized queries." }
func (r RustDieselSQLi) DefaultSeverity() rules.Severity { return rules.Critical }
func (r RustDieselSQLi) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustDieselSQLi) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reDieselSQLFormat.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Diesel sql_query with format! macro (SQL injection)",
				Description:   "diesel::sql_query() receives a query string built with format!. User-controlled values interpolated via format! are not parameterized, enabling SQL injection. Diesel's type-safe query builder is bypassed entirely by sql_query.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use Diesel's type-safe query DSL instead of raw SQL. If raw SQL is needed, use .bind::<Text, _>(&user_input) for parameterized values: sql_query(\"SELECT * FROM users WHERE id = $1\").bind::<Integer, _>(&id).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rust", "diesel", "sql-injection", "format-string"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-027: Unsafe without safety comment
// ---------------------------------------------------------------------------

type RustUnsafeNoSafety struct{}

func (r RustUnsafeNoSafety) ID() string                      { return "BATOU-RS-027" }
func (r RustUnsafeNoSafety) Name() string                    { return "RustUnsafeNoSafety" }
func (r RustUnsafeNoSafety) Description() string             { return "Detects unsafe blocks without a preceding // SAFETY: comment documenting the safety invariants being upheld." }
func (r RustUnsafeNoSafety) DefaultSeverity() rules.Severity { return rules.Medium }
func (r RustUnsafeNoSafety) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustUnsafeNoSafety) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reUnsafeBrace.MatchString(line) {
			// Check if the preceding lines have a // SAFETY: comment
			hasSafetyComment := false
			start := i - 3
			if start < 0 {
				start = 0
			}
			for j := start; j < i; j++ {
				if reSafetyComment.MatchString(lines[j]) {
					hasSafetyComment = true
					break
				}
			}
			if !hasSafetyComment {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Unsafe block without // SAFETY: comment",
					Description:   "An unsafe block does not have a preceding // SAFETY: comment documenting which invariants are being upheld. Without documented safety justification, unsafe code is harder to audit and more likely to contain soundness bugs that lead to undefined behavior.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add a // SAFETY: comment before each unsafe block explaining why the operation is safe. This is a Rust community convention and is enforced by clippy::undocumented_unsafe_blocks.",
					CWEID:         "CWE-676",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"rust", "unsafe", "documentation", "safety"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RS-028: Missing deny unsafe_op_in_unsafe_fn
// ---------------------------------------------------------------------------

type RustMissingDenyUnsafeOp struct{}

func (r RustMissingDenyUnsafeOp) ID() string                      { return "BATOU-RS-028" }
func (r RustMissingDenyUnsafeOp) Name() string                    { return "RustMissingDenyUnsafeOp" }
func (r RustMissingDenyUnsafeOp) Description() string             { return "Detects pub unsafe fn declarations in crates that do not have #![deny(unsafe_op_in_unsafe_fn)], allowing unsafe operations inside unsafe fns without explicit unsafe blocks." }
func (r RustMissingDenyUnsafeOp) DefaultSeverity() rules.Severity { return rules.Medium }
func (r RustMissingDenyUnsafeOp) Languages() []rules.Language     { return []rules.Language{rules.LangRust} }

func (r RustMissingDenyUnsafeOp) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !rePubUnsafeFn.MatchString(ctx.Content) {
		return nil
	}

	hasDeny := reDenyUnsafeOp.MatchString(ctx.Content)
	if hasDeny {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if rePubUnsafeFn.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "pub unsafe fn without #![deny(unsafe_op_in_unsafe_fn)]",
				Description:   "A public unsafe function is declared without the crate-level #![deny(unsafe_op_in_unsafe_fn)] lint. Without this lint, the entire body of an unsafe fn is implicitly unsafe, making it easy to accidentally perform unsafe operations without explicit unsafe blocks and safety documentation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Add #![deny(unsafe_op_in_unsafe_fn)] at the crate root (lib.rs or main.rs). This requires explicit unsafe blocks inside unsafe fns, making each unsafe operation visible and documentable.",
				CWEID:         "CWE-676",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"rust", "unsafe", "lint", "unsafe-fn"},
			})
		}
	}
	return findings
}
