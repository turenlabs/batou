package zig

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ZIG-009
var reMemcpy = regexp.MustCompile(`@memcpy\s*\(`)
// ZIG-010
var reCSystem = regexp.MustCompile(`std\.c\.(?:system|popen)\s*\(`)
// ZIG-011
var reIntCast = regexp.MustCompile(`@intCast\s*\(`)
// ZIG-012
var reAllocFree = regexp.MustCompile(`(?:allocator\.free|\.deinit)\s*\(`)
// ZIG-013
var (
	reTryAlloc = regexp.MustCompile(`try\s+.*(?:alloc|create)\s*\(`)
	reErrdefer = regexp.MustCompile(`errdefer`)
)
// ZIG-014
var reEmbedFileSensitive = regexp.MustCompile(`@embedFile\s*\(\s*"[^"]*(?i)(?:key|secret|password|cert|private|token)`)
// ZIG-015
var reStdNetStream = regexp.MustCompile(`std\.net\.Stream\b`)
// ZIG-016
var reSentinelBypass = regexp.MustCompile(`@ptrCast\s*\(.*\.ptr\s*\)`)
// ZIG-017
var reCStringInterop = regexp.MustCompile(`@ptrCast\s*\(.*\.ptr\b`)
// ZIG-018
var reZigFmtRuntime = regexp.MustCompile(`std\.(?:fmt\.format|log\.(?:info|warn|err|debug))\s*\(`)

type MemcpyOverflow struct{}
func (r MemcpyOverflow) ID() string { return "BATOU-ZIG-009" }
func (r MemcpyOverflow) Name() string { return "Buffer Overflow via @memcpy" }
func (r MemcpyOverflow) DefaultSeverity() rules.Severity { return rules.Critical }
func (r MemcpyOverflow) Description() string { return "Detects @memcpy usage which can cause buffer overflow if length is not validated." }
func (r MemcpyOverflow) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r MemcpyOverflow) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reMemcpy.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "@memcpy without bounds validation", Description: "@memcpy copies memory without bounds checking. If the source length exceeds the destination buffer size, this causes a buffer overflow leading to memory corruption.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Validate that source length <= destination length before @memcpy. Use slice operations with bounds checking where possible.", CWEID: "CWE-120", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Language: ctx.Language, Confidence: "medium", Tags: []string{"zig","memory","buffer-overflow","memcpy"}})
		}
	}
	return findings
}

type CSystemInjection struct{}
func (r CSystemInjection) ID() string { return "BATOU-ZIG-010" }
func (r CSystemInjection) Name() string { return "C system() Command Injection" }
func (r CSystemInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r CSystemInjection) Description() string { return "Detects calls to std.c.system() or std.c.popen() which execute shell commands." }
func (r CSystemInjection) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r CSystemInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reCSystem.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Shell command execution via C interop", Description: "std.c.system() or std.c.popen() invokes a shell to execute commands. If the command string includes user input, this enables arbitrary command execution.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use std.process.Child with explicit argument arrays instead of shell execution. Validate all inputs against an allowlist.", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection", Language: ctx.Language, Confidence: "high", Tags: []string{"zig","command-injection","c-interop"}})
		}
	}
	return findings
}

type IntCastOverflow struct{}
func (r IntCastOverflow) ID() string { return "BATOU-ZIG-011" }
func (r IntCastOverflow) Name() string { return "Integer Overflow in @intCast" }
func (r IntCastOverflow) DefaultSeverity() rules.Severity { return rules.High }
func (r IntCastOverflow) Description() string { return "Detects @intCast which can panic on narrowing casts if the value exceeds the target type range." }
func (r IntCastOverflow) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r IntCastOverflow) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reIntCast.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Potential integer overflow in @intCast", Description: "@intCast performs a narrowing integer conversion that panics in safe mode or causes undefined behavior in release mode if the value exceeds the target type's range.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use std.math.cast() for safe narrowing that returns null on overflow, or validate the value is within range before casting.", CWEID: "CWE-190", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Language: ctx.Language, Confidence: "medium", Tags: []string{"zig","integer-overflow","intcast"}})
		}
	}
	return findings
}

type AllocatorUseAfterFree struct{}
func (r AllocatorUseAfterFree) ID() string { return "BATOU-ZIG-012" }
func (r AllocatorUseAfterFree) Name() string { return "Allocator Use-After-Free" }
func (r AllocatorUseAfterFree) DefaultSeverity() rules.Severity { return rules.Critical }
func (r AllocatorUseAfterFree) Description() string { return "Detects allocator.free() or .deinit() patterns that may lead to use-after-free." }
func (r AllocatorUseAfterFree) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r AllocatorUseAfterFree) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reAllocFree.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Memory deallocation - potential use-after-free", Description: "allocator.free() or .deinit() deallocates memory. Any subsequent use of the freed pointer causes undefined behavior. Verify the pointer is not used after this call.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Set the pointer to undefined after freeing: ptr = undefined. Use defer for cleanup to ensure proper ordering. Consider arena allocators for simpler lifetime management.", CWEID: "CWE-416", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Language: ctx.Language, Confidence: "low", Tags: []string{"zig","memory","use-after-free"}})
		}
	}
	return findings
}

type MissingErrdefer struct{}
func (r MissingErrdefer) ID() string { return "BATOU-ZIG-013" }
func (r MissingErrdefer) Name() string { return "Missing errdefer for Resource Cleanup" }
func (r MissingErrdefer) DefaultSeverity() rules.Severity { return rules.Medium }
func (r MissingErrdefer) Description() string { return "Detects allocations with try that lack a corresponding errdefer for cleanup on error paths." }
func (r MissingErrdefer) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r MissingErrdefer) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reTryAlloc.MatchString(ctx.Content) { return nil }
	if reErrdefer.MatchString(ctx.Content) { return nil }
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reTryAlloc.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Allocation without errdefer cleanup", Description: "A fallible allocation (try ...alloc/create) has no corresponding errdefer to free the resource on error paths. This causes memory leaks when subsequent operations fail.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Add errdefer allocator.free(ptr) or errdefer resource.deinit() immediately after the allocation.", CWEID: "CWE-401", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Language: ctx.Language, Confidence: "low", Tags: []string{"zig","memory","leak","errdefer"}})
		}
	}
	return findings
}

type EmbedFileSensitive struct{}
func (r EmbedFileSensitive) ID() string { return "BATOU-ZIG-014" }
func (r EmbedFileSensitive) Name() string { return "@embedFile Sensitive Data" }
func (r EmbedFileSensitive) DefaultSeverity() rules.Severity { return rules.High }
func (r EmbedFileSensitive) Description() string { return "Detects @embedFile embedding files with sensitive names (keys, secrets, certs) into the binary." }
func (r EmbedFileSensitive) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r EmbedFileSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reEmbedFileSensitive.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "@embedFile with sensitive data", Description: "@embedFile embeds a file's contents into the binary at compile time. Files containing keys, secrets, or certificates become extractable from the binary.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Load sensitive data at runtime from environment variables or a secrets manager. Never embed secrets in the binary.", CWEID: "CWE-798", OWASPCategory: "A07:2021-Identification and Authentication Failures", Language: ctx.Language, Confidence: "high", Tags: []string{"zig","secrets","embedfile"}})
		}
	}
	return findings
}

type StdNetNoTLS struct{}
func (r StdNetNoTLS) ID() string { return "BATOU-ZIG-015" }
func (r StdNetNoTLS) Name() string { return "std.net Without TLS" }
func (r StdNetNoTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r StdNetNoTLS) Description() string { return "Detects std.net.Stream usage without TLS context, transmitting data in plaintext." }
func (r StdNetNoTLS) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r StdNetNoTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reStdNetStream.MatchString(ctx.Content) { return nil }
	if strings.Contains(ctx.Content, "tls") || strings.Contains(ctx.Content, "TLS") || strings.Contains(ctx.Content, "ssl") { return nil }
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reStdNetStream.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Network stream without TLS", Description: "std.net.Stream is used without any TLS context. Network traffic will be transmitted in plaintext, exposing data to eavesdropping.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use std.crypto.tls to wrap the stream with TLS encryption, or use a TLS library for secure communication.", CWEID: "CWE-319", OWASPCategory: "A02:2021-Cryptographic Failures", Language: ctx.Language, Confidence: "medium", Tags: []string{"zig","tls","cleartext","network"}})
		}
	}
	return findings
}

type SentinelSliceBypass struct{}
func (r SentinelSliceBypass) ID() string { return "BATOU-ZIG-016" }
func (r SentinelSliceBypass) Name() string { return "Sentinel Slice Bypass" }
func (r SentinelSliceBypass) DefaultSeverity() rules.Severity { return rules.High }
func (r SentinelSliceBypass) Description() string { return "Detects @ptrCast on .ptr field which bypasses sentinel-terminated slice safety guarantees." }
func (r SentinelSliceBypass) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r SentinelSliceBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reSentinelBypass.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "@ptrCast on .ptr bypasses sentinel safety", Description: "Casting a slice's .ptr field with @ptrCast bypasses sentinel-terminated slice guarantees. When passed to C functions expecting null-terminated strings, this can cause buffer over-reads.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use sentinel-terminated slices [:0] directly. Convert with std.mem.sliceTo() for null-terminated conversions.", CWEID: "CWE-120", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Language: ctx.Language, Confidence: "medium", Tags: []string{"zig","sentinel","c-interop","buffer-overflow"}})
		}
	}
	return findings
}

type CStringInterop struct{}
func (r CStringInterop) ID() string { return "BATOU-ZIG-017" }
func (r CStringInterop) Name() string { return "C String Interop Without Null Termination" }
func (r CStringInterop) DefaultSeverity() rules.Severity { return rules.High }
func (r CStringInterop) Description() string { return "Detects Zig slice .ptr passed to C functions that may expect null-terminated strings." }
func (r CStringInterop) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r CStringInterop) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "@cImport") && !strings.Contains(ctx.Content, "std.c.") { return nil }
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reCStringInterop.MatchString(line) && !reSentinelBypass.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Zig slice passed to C without null termination", Description: "A Zig slice's .ptr is cast for C interop. Zig slices are not null-terminated, so C string functions (strlen, strcmp, etc.) will read past the buffer end.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use [:0] sentinel-terminated slices for C string interop, or allocate a null-terminated copy with std.mem.dupeZ().", CWEID: "CWE-170", OWASPCategory: "A06:2021-Vulnerable and Outdated Components", Language: ctx.Language, Confidence: "medium", Tags: []string{"zig","c-interop","null-termination"}})
		}
	}
	return findings
}

type ZigFormatString struct{}
func (r ZigFormatString) ID() string { return "BATOU-ZIG-018" }
func (r ZigFormatString) Name() string { return "Format String with Runtime Data" }
func (r ZigFormatString) DefaultSeverity() rules.Severity { return rules.Medium }
func (r ZigFormatString) Description() string { return "Detects std.fmt.format or std.log calls that may use runtime data in format position." }
func (r ZigFormatString) Languages() []rules.Language { return []rules.Language{rules.LangZig} }
func (r ZigFormatString) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isCommentLine(line) { continue }
		if reZigFmtRuntime.MatchString(line) && strings.Contains(line, "user") {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Format/log call with potential user data", Description: "std.fmt.format or std.log is called with data that may include user input. While Zig's format strings are comptime, logging unsanitized user data can enable log injection.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Sanitize user data before logging. Strip control characters and limit output length.", CWEID: "CWE-134", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures", Language: ctx.Language, Confidence: "low", Tags: []string{"zig","format-string","logging"}})
		}
	}
	return findings
}

func init() {
	rules.Register(MemcpyOverflow{})
	rules.Register(CSystemInjection{})
	rules.Register(IntCastOverflow{})
	rules.Register(AllocatorUseAfterFree{})
	rules.Register(MissingErrdefer{})
	rules.Register(EmbedFileSensitive{})
	rules.Register(StdNetNoTLS{})
	rules.Register(SentinelSliceBypass{})
	rules.Register(CStringInterop{})
	rules.Register(ZigFormatString{})
}
