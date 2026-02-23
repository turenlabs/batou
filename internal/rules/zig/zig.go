package zig

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// ZIG-001: Unsafe @ptrCast
var rePtrCast = regexp.MustCompile(`@ptrCast\s*\(`)

// ZIG-002: Unsafe @intToPtr
var reIntToPtr = regexp.MustCompile(`@intToPtr\s*\(`)

// ZIG-003: Unsafe @alignCast
var reAlignCast = regexp.MustCompile(`@alignCast\s*\(`)

// ZIG-004: Command injection
var (
	reChildProcess = regexp.MustCompile(`std\.process\.Child|std\.ChildProcess`)
	reOsExecve     = regexp.MustCompile(`std\.os\.execve\s*\(`)
	reSpawn        = regexp.MustCompile(`\.spawn\s*\(\s*\)`)
)

// ZIG-005: Path traversal
var (
	reFsOpenFile  = regexp.MustCompile(`std\.fs\.(?:openFile|cwd\(\)\.openFile)\s*\(`)
	reDirOpenFile = regexp.MustCompile(`(?:std\.fs\.)?Dir\.openFile\s*\(`)
	rePathConcat  = regexp.MustCompile(`\+\+\s*(?:"/"|"\\\\")|\bstd\.fmt\.allocPrint`)
)

// ZIG-006: Unsafe error suppression
var (
	reCatchUnreachable = regexp.MustCompile(`catch\s+unreachable`)
	reCatchUndefined   = regexp.MustCompile(`catch\s*\|_\|\s*undefined`)
)

// ZIG-007: Unsafe @bitCast
var reBitCast = regexp.MustCompile(`@bitCast\s*\(`)

// ZIG-008: Weak crypto
var reWeakCrypto = regexp.MustCompile(`std\.crypto\.hash\.(?:Md5|Sha1)`)

// ---------------------------------------------------------------------------
// Comment detection
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*//`)

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
// ZIG-001: Unsafe @ptrCast
// ---------------------------------------------------------------------------

type UnsafePtrCast struct{}

func (r UnsafePtrCast) ID() string                      { return "BATOU-ZIG-001" }
func (r UnsafePtrCast) Name() string                    { return "Unsafe @ptrCast" }
func (r UnsafePtrCast) DefaultSeverity() rules.Severity { return rules.Critical }
func (r UnsafePtrCast) Description() string {
	return "Detects use of @ptrCast which performs unsafe pointer type coercion, bypassing Zig's type safety. Incorrect casts cause undefined behavior, memory corruption, and potential code execution."
}
func (r UnsafePtrCast) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r UnsafePtrCast) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if rePtrCast.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe @ptrCast usage",
				Description:   "@ptrCast performs unsafe pointer type coercion. If the pointed-to types have different sizes, alignments, or representations, this causes undefined behavior including memory corruption.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use @as for safe casts where possible. If @ptrCast is necessary, verify the pointer alignment and target type layout. Consider using @ptrCast only within well-documented unsafe boundaries.",
				CWEID:         "CWE-588",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"zig", "unsafe", "pointer-cast"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-002: Unsafe @intToPtr
// ---------------------------------------------------------------------------

type UnsafeIntToPtr struct{}

func (r UnsafeIntToPtr) ID() string                      { return "BATOU-ZIG-002" }
func (r UnsafeIntToPtr) Name() string                    { return "Unsafe @intToPtr" }
func (r UnsafeIntToPtr) DefaultSeverity() rules.Severity { return rules.Critical }
func (r UnsafeIntToPtr) Description() string {
	return "Detects use of @intToPtr which converts an integer to a pointer. This is inherently unsafe as there is no guarantee the integer represents a valid memory address."
}
func (r UnsafeIntToPtr) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r UnsafeIntToPtr) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reIntToPtr.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe @intToPtr usage",
				Description:   "@intToPtr converts an integer to a pointer type. The resulting pointer may be invalid, misaligned, or point to unmapped memory, causing undefined behavior on dereference.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Avoid @intToPtr unless interfacing with hardware or FFI. Validate the address is properly aligned and within mapped memory. Document the safety invariants.",
				CWEID:         "CWE-457",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"zig", "unsafe", "integer-to-pointer"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-003: Unsafe @alignCast
// ---------------------------------------------------------------------------

type UnsafeAlignCast struct{}

func (r UnsafeAlignCast) ID() string                      { return "BATOU-ZIG-003" }
func (r UnsafeAlignCast) Name() string                    { return "Unsafe @alignCast" }
func (r UnsafeAlignCast) DefaultSeverity() rules.Severity { return rules.High }
func (r UnsafeAlignCast) Description() string {
	return "Detects use of @alignCast which asserts pointer alignment at runtime. If the pointer is not properly aligned, this triggers undefined behavior."
}
func (r UnsafeAlignCast) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r UnsafeAlignCast) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reAlignCast.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe @alignCast usage",
				Description:   "@alignCast asserts that a pointer has a specific alignment. If the pointer is not actually aligned to the target alignment, this is undefined behavior and may cause crashes on architectures with strict alignment requirements.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Ensure the source pointer is properly aligned before using @alignCast. Use @alignOf to verify alignment requirements. Consider using std.mem.bytesAsSlice for safe reinterpretation.",
				CWEID:         "CWE-704",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"zig", "unsafe", "alignment"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-004: Command Injection
// ---------------------------------------------------------------------------

type CommandInjection struct{}

func (r CommandInjection) ID() string                      { return "BATOU-ZIG-004" }
func (r CommandInjection) Name() string                    { return "Command Injection" }
func (r CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r CommandInjection) Description() string {
	return "Detects use of std.process.Child, std.os.execve, or std.ChildProcess which can enable command injection if arguments include user-controlled data."
}
func (r CommandInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reOsExecve.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "Process execution via std.os.execve",
				Description:   "std.os.execve replaces the current process with a new program. If the program path or arguments include user-controlled data, an attacker can execute arbitrary commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Validate and sanitize all arguments passed to execve. Use an allowlist for permitted programs. Never pass unsanitized user input as the program path.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"zig", "command-injection", "execve"},
			})
			continue
		}

		if reChildProcess.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "Process spawning via std.process.Child",
				Description:   "std.process.Child spawns a child process. If the command or arguments are constructed from user input, this enables command injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Pass static command names and use separate arguments for user data. Validate user input against an allowlist before including it in process arguments.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"zig", "command-injection", "child-process"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-005: Path Traversal
// ---------------------------------------------------------------------------

type PathTraversal struct{}

func (r PathTraversal) ID() string                      { return "BATOU-ZIG-005" }
func (r PathTraversal) Name() string                    { return "Path Traversal" }
func (r PathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r PathTraversal) Description() string {
	return "Detects std.fs file operations with potentially user-controlled paths, especially when combined with string concatenation or formatting."
}
func (r PathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for path validation in the file
	hasRealPath := strings.Contains(ctx.Content, "realpathZ") || strings.Contains(ctx.Content, "realpath")
	hasPathGuard := hasRealPath

	if hasPathGuard {
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		hasFsOpen := reFsOpenFile.MatchString(line) || reDirOpenFile.MatchString(line)
		hasConcat := rePathConcat.MatchString(line)

		// File open with string concat/format on the same or adjacent lines
		if hasFsOpen {
			// Check current and nearby lines for path concatenation
			nearbyConcat := hasConcat
			if !nearbyConcat {
				start := i - 3
				if start < 0 {
					start = 0
				}
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				for j := start; j < end; j++ {
					if rePathConcat.MatchString(lines[j]) {
						nearbyConcat = true
						break
					}
				}
			}

			if nearbyConcat {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File operation with user-controlled path",
					Description:   "A file system operation uses a path constructed via concatenation or formatting. An attacker can use ../ sequences to access files outside the intended directory.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Resolve the path with std.fs.realpathZ and verify it starts with the allowed base directory. Never concatenate user input directly into file paths.",
					CWEID:         "CWE-22",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"zig", "path-traversal", "file-access"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-006: Unsafe Error Suppression
// ---------------------------------------------------------------------------

type UnsafeErrorSuppression struct{}

func (r UnsafeErrorSuppression) ID() string                      { return "BATOU-ZIG-006" }
func (r UnsafeErrorSuppression) Name() string                    { return "Unsafe Error Suppression" }
func (r UnsafeErrorSuppression) DefaultSeverity() rules.Severity { return rules.High }
func (r UnsafeErrorSuppression) Description() string {
	return "Detects 'catch unreachable' and 'catch |_| undefined' patterns that suppress errors by triggering undefined behavior or safety checks at runtime."
}
func (r UnsafeErrorSuppression) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r UnsafeErrorSuppression) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reCatchUnreachable.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Error suppressed with 'catch unreachable'",
				Description:   "'catch unreachable' tells the compiler the error can never occur. If it does occur at runtime, this triggers safety-checked undefined behavior (a panic in safe builds, true UB in ReleaseFast/ReleaseSmall).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Handle the error explicitly with 'catch |err| { ... }' or propagate it with 'try'. Only use 'catch unreachable' when you can prove the error is logically impossible.",
				CWEID:         "CWE-390",
				OWASPCategory: "A11:2021-Next",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"zig", "error-handling", "unreachable"},
			})
			continue
		}

		if reCatchUndefined.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Error suppressed with undefined behavior",
				Description:   "Catching an error and returning undefined triggers undefined behavior. The program state becomes unpredictable, which can lead to memory corruption or security bypasses.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Handle the error properly with 'catch |err| { ... }' or propagate it with 'try'. Never use undefined as an error recovery mechanism.",
				CWEID:         "CWE-390",
				OWASPCategory: "A11:2021-Next",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"zig", "error-handling", "undefined-behavior"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-007: Unsafe @bitCast
// ---------------------------------------------------------------------------

type UnsafeBitCast struct{}

func (r UnsafeBitCast) ID() string                      { return "BATOU-ZIG-007" }
func (r UnsafeBitCast) Name() string                    { return "Unsafe @bitCast" }
func (r UnsafeBitCast) DefaultSeverity() rules.Severity { return rules.High }
func (r UnsafeBitCast) Description() string {
	return "Detects use of @bitCast which reinterprets the bits of one type as another without any conversion. Incorrect usage can produce invalid values and undefined behavior."
}
func (r UnsafeBitCast) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r UnsafeBitCast) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reBitCast.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe @bitCast usage",
				Description:   "@bitCast reinterprets the bits of a value as a different type without any conversion. If the source and target types have different sizes or if the bit pattern is invalid for the target type, this causes undefined behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Verify that source and target types have the same size with @sizeOf. Consider using @as for safe conversions. Document why the bit reinterpretation is valid.",
				CWEID:         "CWE-681",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"zig", "unsafe", "bit-cast"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// ZIG-008: Weak Crypto
// ---------------------------------------------------------------------------

type WeakCrypto struct{}

func (r WeakCrypto) ID() string                      { return "BATOU-ZIG-008" }
func (r WeakCrypto) Name() string                    { return "Weak Cryptographic Hash" }
func (r WeakCrypto) DefaultSeverity() rules.Severity { return rules.Medium }
func (r WeakCrypto) Description() string {
	return "Detects use of weak cryptographic hash functions (MD5, SHA1) from the Zig standard library. These algorithms are cryptographically broken and vulnerable to collision attacks."
}
func (r WeakCrypto) Languages() []rules.Language {
	return []rules.Language{rules.LangZig}
}

func (r WeakCrypto) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reWeakCrypto.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Weak cryptographic hash function",
				Description:   "MD5 and SHA1 are cryptographically broken. MD5 has practical collision attacks and SHA1 has demonstrated collision attacks (SHAttered). Neither should be used for security-sensitive operations.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use std.crypto.hash.sha2.Sha256 or std.crypto.hash.blake3 for cryptographic hashing. For password hashing, use std.crypto.pwhash.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"zig", "crypto", "weak-hash"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(UnsafePtrCast{})
	rules.Register(UnsafeIntToPtr{})
	rules.Register(UnsafeAlignCast{})
	rules.Register(CommandInjection{})
	rules.Register(PathTraversal{})
	rules.Register(UnsafeErrorSuppression{})
	rules.Register(UnsafeBitCast{})
	rules.Register(WeakCrypto{})
}
