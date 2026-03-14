package memory

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns (generated rules MEM-014 through MEM-023)
// ---------------------------------------------------------------------------

// MEM-014: sprintf buffer overflow
var (
	reGenSprintf  = regexp.MustCompile(`\bsprintf\s*\(`)
	reGenSnprintf = regexp.MustCompile(`\bsnprintf\s*\(`)
)

// MEM-015: gets() banned function
var reGenGets = regexp.MustCompile(`\bgets\s*\(`)

// MEM-016: Integer overflow before malloc
var reGenMallocMul = regexp.MustCompile(`\bmalloc\s*\(\s*[a-zA-Z_]\w*\s*\*\s*sizeof`)

// MEM-017: Format string vulnerability
var (
	reGenPrintfVar  = regexp.MustCompile(`\bprintf\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
	reGenFprintfVar = regexp.MustCompile(`\bfprintf\s*\(\s*[^,]+,\s*[a-zA-Z_]\w*\s*[,)]`)
)

// MEM-018: system()/popen() with variable
var reGenSystemVar = regexp.MustCompile(`\b(?:system|popen)\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)

// MEM-019: strncpy without null termination
var reGenStrncpy = regexp.MustCompile(`\bstrncpy\s*\(`)

// MEM-020: Use-after-free realloc
var reGenReallocSelf = regexp.MustCompile(`(\w+)\s*=\s*realloc\s*\(\s*\1\s*,`)

// MEM-021: OpenSSL deprecated API
var reGenDeprecatedSSL = regexp.MustCompile(`\b(?:SSLv23_method|TLSv1_method|TLSv1_1_method|SSL_library_init|SSLv2_method|SSLv3_method)\s*\(`)

// MEM-022: Container namespace breakout
var reGenNamespaceBreakout = regexp.MustCompile(`\b(?:setns|unshare)\s*\(.*(?:CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER)`)

// MEM-023: Deprecated RSA key size
var reGenRSAKeySize = regexp.MustCompile(`RSA_generate_key_ex\s*\([^,]*,\s*(?:1024|512)\b`)

// ---------------------------------------------------------------------------
// MEM-014: sprintf Buffer Overflow
// ---------------------------------------------------------------------------

type SprintfOverflow struct{}

func (r SprintfOverflow) ID() string                      { return "BATOU-MEM-014" }
func (r SprintfOverflow) Name() string                    { return "sprintf Buffer Overflow" }
func (r SprintfOverflow) DefaultSeverity() rules.Severity { return rules.Critical }
func (r SprintfOverflow) Description() string {
	return "Detects use of sprintf() which writes to a buffer without bounds checking, causing buffer overflows when the formatted output exceeds the buffer size."
}
func (r SprintfOverflow) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r SprintfOverflow) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenSprintf.MatchString(line) && !reGenSnprintf.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "sprintf() without bounds checking",
				Description:   "sprintf() writes formatted output to a buffer without any size limit. If the formatted string exceeds the buffer size, it overflows into adjacent memory, enabling code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Replace sprintf() with snprintf(buf, sizeof(buf), ...) to enforce buffer size limits.",
				CWEID:         "CWE-121",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "buffer-overflow", "sprintf"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-015: gets() Banned Function
// ---------------------------------------------------------------------------

type GetsBanned struct{}

func (r GetsBanned) ID() string                      { return "BATOU-MEM-015" }
func (r GetsBanned) Name() string                    { return "gets() Banned Function" }
func (r GetsBanned) DefaultSeverity() rules.Severity { return rules.Critical }
func (r GetsBanned) Description() string {
	return "Detects use of gets() which is always a buffer overflow vulnerability. It was removed from the C11 standard due to being inherently unsafe."
}
func (r GetsBanned) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r GetsBanned) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenGets.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "gets() is always a buffer overflow",
				Description:   "gets() reads input with no length limit, guaranteeing a buffer overflow on sufficiently long input. It was removed from C11 and should never be used.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Replace gets() with fgets(buf, sizeof(buf), stdin) which enforces a maximum read length.",
				CWEID:         "CWE-120",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "banned-function", "gets"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-016: Integer Overflow Before malloc
// ---------------------------------------------------------------------------

type IntegerOverflowMalloc struct{}

func (r IntegerOverflowMalloc) ID() string                      { return "BATOU-MEM-016" }
func (r IntegerOverflowMalloc) Name() string                    { return "Integer Overflow Before malloc" }
func (r IntegerOverflowMalloc) DefaultSeverity() rules.Severity { return rules.Critical }
func (r IntegerOverflowMalloc) Description() string {
	return "Detects malloc() with multiplication in the size argument (var * sizeof) without overflow protection, which can wrap around and allocate a tiny buffer."
}
func (r IntegerOverflowMalloc) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r IntegerOverflowMalloc) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenMallocMul.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Integer overflow in malloc size calculation",
				Description:   "malloc(n * sizeof(...)) can integer-overflow when n is large, wrapping to a small allocation. Subsequent writes overflow the undersized buffer.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use calloc(n, sizeof(...)) which checks for multiplication overflow internally. Alternatively, validate n before the multiplication or use safe_multiply helpers.",
				CWEID:         "CWE-190",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "integer-overflow", "malloc"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-017: Format String Vulnerability
// ---------------------------------------------------------------------------

type FormatStringGen struct{}

func (r FormatStringGen) ID() string                      { return "BATOU-MEM-017" }
func (r FormatStringGen) Name() string                    { return "Format String Vulnerability" }
func (r FormatStringGen) DefaultSeverity() rules.Severity { return rules.Critical }
func (r FormatStringGen) Description() string {
	return "Detects printf/fprintf called with a variable as the format string instead of a string literal, enabling format string attacks."
}
func (r FormatStringGen) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r FormatStringGen) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if loc := reGenPrintfVar.FindString(line); loc != "" {
			matched = loc
		} else if loc := reGenFprintfVar.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "printf-family function with variable format string",
				Description:   "Passing a variable as the format string to printf/fprintf allows attackers to read stack memory (%x), write to arbitrary addresses (%n), or crash the program.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Always use a string literal as the format string: printf(\"%s\", variable) instead of printf(variable).",
				CWEID:         "CWE-134",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "format-string", "printf"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-018: system()/popen() with Variable
// ---------------------------------------------------------------------------

type SystemPopenVariable struct{}

func (r SystemPopenVariable) ID() string                      { return "BATOU-MEM-018" }
func (r SystemPopenVariable) Name() string                    { return "system/popen with Variable" }
func (r SystemPopenVariable) DefaultSeverity() rules.Severity { return rules.Critical }
func (r SystemPopenVariable) Description() string {
	return "Detects system() or popen() called with a variable argument, enabling command injection via shell metacharacters."
}
func (r SystemPopenVariable) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r SystemPopenVariable) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenSystemVar.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "system()/popen() with variable argument",
				Description:   "system() and popen() pass their argument to a shell. If the argument contains user-controlled data, attackers can inject arbitrary commands via shell metacharacters (;, |, $(), etc.).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use exec-family functions (execve, execvp) with an explicit argument array to avoid shell interpretation. If system() is required, sanitize and validate all input components.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "command-injection", "system-popen"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-019: strncpy Without Null Termination
// ---------------------------------------------------------------------------

type StrncpyNullTerm struct{}

func (r StrncpyNullTerm) ID() string                      { return "BATOU-MEM-019" }
func (r StrncpyNullTerm) Name() string                    { return "strncpy Without Null Termination" }
func (r StrncpyNullTerm) DefaultSeverity() rules.Severity { return rules.High }
func (r StrncpyNullTerm) Description() string {
	return "Detects strncpy() usage which does not guarantee null termination when the source is longer than or equal to the size limit."
}
func (r StrncpyNullTerm) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r StrncpyNullTerm) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenStrncpy.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "strncpy() does not guarantee null termination",
				Description:   "strncpy() does not null-terminate the destination if the source length >= n. Subsequent string operations on the non-terminated buffer cause buffer overreads.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use strlcpy() or snprintf() which always null-terminate. If strncpy() is used, manually set dest[n-1] = '\\0' after the call.",
				CWEID:         "CWE-170",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"memory", "null-termination", "strncpy"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-020: Use-After-Free realloc
// ---------------------------------------------------------------------------

type ReallocUseAfterFree struct{}

func (r ReallocUseAfterFree) ID() string                      { return "BATOU-MEM-020" }
func (r ReallocUseAfterFree) Name() string                    { return "Use-After-Free realloc" }
func (r ReallocUseAfterFree) DefaultSeverity() rules.Severity { return rules.Critical }
func (r ReallocUseAfterFree) Description() string {
	return "Detects ptr = realloc(ptr, ...) pattern where failure leaves the original pointer freed and the variable set to NULL, losing the original allocation."
}
func (r ReallocUseAfterFree) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r ReallocUseAfterFree) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenReallocSelf.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe realloc pattern: ptr = realloc(ptr, ...)",
				Description:   "When realloc() fails, it returns NULL but does not free the original block. Assigning the result directly back to the same pointer loses the original allocation, causing a memory leak and potential use-after-free.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use a temporary pointer: void *tmp = realloc(ptr, new_size); if (tmp) { ptr = tmp; } else { /* handle error, ptr is still valid */ }.",
				CWEID:         "CWE-416",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "realloc", "use-after-free"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-021: OpenSSL Deprecated API
// ---------------------------------------------------------------------------

type DeprecatedSSLAPI struct{}

func (r DeprecatedSSLAPI) ID() string                      { return "BATOU-MEM-021" }
func (r DeprecatedSSLAPI) Name() string                    { return "OpenSSL Deprecated API" }
func (r DeprecatedSSLAPI) DefaultSeverity() rules.Severity { return rules.High }
func (r DeprecatedSSLAPI) Description() string {
	return "Detects use of deprecated OpenSSL functions (SSLv23_method, TLSv1_method, SSL_library_init) that enable insecure protocol versions."
}
func (r DeprecatedSSLAPI) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r DeprecatedSSLAPI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenDeprecatedSSL.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Deprecated OpenSSL API usage",
				Description:   "SSLv23_method, TLSv1_method, SSL_library_init, and similar APIs are deprecated and may enable insecure protocol versions (SSLv3, TLS 1.0/1.1) that have known vulnerabilities.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use TLS_method() with SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) for modern OpenSSL. Remove calls to SSL_library_init() in OpenSSL 1.1.0+.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "openssl", "deprecated-crypto"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-022: Container Namespace Breakout
// ---------------------------------------------------------------------------

type NamespaceBreakout struct{}

func (r NamespaceBreakout) ID() string                      { return "BATOU-MEM-022" }
func (r NamespaceBreakout) Name() string                    { return "Container Namespace Breakout" }
func (r NamespaceBreakout) DefaultSeverity() rules.Severity { return rules.Critical }
func (r NamespaceBreakout) Description() string {
	return "Detects setns/unshare calls with CLONE_NEW* flags that can be used to break out of container namespaces and escalate privileges."
}
func (r NamespaceBreakout) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r NamespaceBreakout) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenNamespaceBreakout.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Container namespace manipulation via setns/unshare",
				Description:   "setns() and unshare() with CLONE_NEW* flags can join or create new namespaces, potentially escaping container isolation. If this code runs inside a container with elevated privileges, it enables breakout.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Ensure containers run without CAP_SYS_ADMIN. Use seccomp profiles to block setns/unshare syscalls. Drop all unnecessary capabilities.",
				CWEID:         "CWE-269",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "container", "namespace-breakout"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// MEM-023: Deprecated RSA Key Size
// ---------------------------------------------------------------------------

type DeprecatedRSAKeySize struct{}

func (r DeprecatedRSAKeySize) ID() string                      { return "BATOU-MEM-023" }
func (r DeprecatedRSAKeySize) Name() string                    { return "Deprecated RSA Key Size" }
func (r DeprecatedRSAKeySize) DefaultSeverity() rules.Severity { return rules.Medium }
func (r DeprecatedRSAKeySize) Description() string {
	return "Detects RSA_generate_key_ex with 1024-bit or 512-bit key sizes, which are considered cryptographically weak."
}
func (r DeprecatedRSAKeySize) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r DeprecatedRSAKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenRSAKeySize.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "RSA key generation with weak key size",
				Description:   "RSA keys of 1024 bits or less are considered cryptographically broken and can be factored with modern hardware. NIST deprecated 1024-bit RSA in 2013.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use at least 2048-bit RSA keys, or preferably 3072+ bits for long-term security. Consider migrating to ECDSA (P-256 or P-384) or Ed25519 for better performance.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "crypto", "weak-key-size"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(SprintfOverflow{})
	rules.Register(GetsBanned{})
	rules.Register(IntegerOverflowMalloc{})
	rules.Register(FormatStringGen{})
	rules.Register(SystemPopenVariable{})
	rules.Register(StrncpyNullTerm{})
	rules.Register(ReallocUseAfterFree{})
	rules.Register(DeprecatedSSLAPI{})
	rules.Register(NamespaceBreakout{})
	rules.Register(DeprecatedRSAKeySize{})
}
