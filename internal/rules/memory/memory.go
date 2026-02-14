package memory

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// Banned/dangerous functions (GTSS-MEM-001)
var (
	// gets() — always a buffer overflow, banned in C11
	reGets = regexp.MustCompile(`\bgets\s*\(`)
	// strcpy without bounds
	reStrcpy = regexp.MustCompile(`\bstrcpy\s*\(`)
	// strcat without bounds
	reStrcat = regexp.MustCompile(`\bstrcat\s*\(`)
	// sprintf — use snprintf
	reSprintf = regexp.MustCompile(`\bsprintf\s*\(`)
	// vsprintf — use vsnprintf
	reVsprintf = regexp.MustCompile(`\bvsprintf\s*\(`)
	// scanf/sscanf/fscanf with %s — unbounded string read
	reScanfS = regexp.MustCompile(`\b(?:scanf|sscanf|fscanf)\s*\([^)]*"[^"]*%s`)
	// atoi/atol — no error checking
	reAtoi = regexp.MustCompile(`\b(?:atoi|atol|atoll|atof)\s*\(`)
)

// Format string vulnerabilities (GTSS-MEM-002)
var (
	// printf(variable) — first arg is a variable, not a string literal
	rePrintfVar = regexp.MustCompile(`\bprintf\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
	// fprintf(file, variable)
	reFprintfVar = regexp.MustCompile(`\bfprintf\s*\(\s*[^,]+,\s*[a-zA-Z_]\w*\s*[,)]`)
	// syslog(priority, variable)
	reSyslogVar = regexp.MustCompile(`\bsyslog\s*\(\s*[^,]+,\s*[a-zA-Z_]\w*\s*[,)]`)
	// snprintf(buf, size, variable)
	reSnprintfVar = regexp.MustCompile(`\bsnprintf\s*\(\s*[^,]+,\s*[^,]+,\s*[a-zA-Z_]\w*\s*[,)]`)
)

// Buffer overflow patterns (GTSS-MEM-003)
var (
	// memcpy/memmove with variable size (potential overflow)
	reMemcpyVar = regexp.MustCompile(`\b(?:memcpy|memmove)\s*\(\s*[^,]+,\s*[^,]+,\s*[a-zA-Z_]\w*\s*\)`)
	// strncpy where size comes from strlen of source (defeats purpose)
	reStrncpyStrlen = regexp.MustCompile(`\bstrncpy\s*\([^,]+,[^,]+,\s*strlen\s*\(`)
	// read/recv directly into fixed buffer without size check
	reReadBuf = regexp.MustCompile(`\b(?:read|recv|recvfrom)\s*\([^,]+,\s*[a-zA-Z_]\w*\s*,\s*sizeof\s*\(\s*[a-zA-Z_]\w*\s*\)`)
)

// Memory management issues (GTSS-MEM-004)
var (
	// free() called — we track these across lines in Scan
	reFreeCall = regexp.MustCompile(`\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)`)
	// delete / delete[]
	reDeleteCall = regexp.MustCompile(`\bdelete\s*(?:\[\])?\s+([a-zA-Z_]\w*)`)
	// Use of pointer after free on same pointer (simplified: free(x) then x-> or *x or x[)
	reUseAfterFreeDeref = regexp.MustCompile(`(?:->|\*\s*[a-zA-Z_]\w*|\[\s*\d*\s*\])`)
	// new without delete (C++ raw allocation)
	reNewAlloc = regexp.MustCompile(`\bnew\s+[a-zA-Z_]\w*(?:\s*\[|\s*\()`)
)

// Integer overflow in allocation (GTSS-MEM-005)
var (
	// malloc(n * sizeof(...)) — multiplication may overflow
	reMallocMul = regexp.MustCompile(`\bmalloc\s*\(\s*[a-zA-Z_]\w*\s*\*\s*(?:sizeof\s*\([^)]*\)|sizeof\b|[a-zA-Z_]\w*)\s*\)`)
	// calloc with variable arguments
	reCallocVar = regexp.MustCompile(`\bcalloc\s*\(\s*[a-zA-Z_]\w*\s*,`)
	// realloc with arithmetic in size argument
	reReallocArith = regexp.MustCompile(`\brealloc\s*\(\s*[^,]+,\s*[a-zA-Z_]\w*\s*[+*]\s*`)
)

// Null pointer dereference (GTSS-MEM-006)
var (
	// malloc/calloc/realloc call — tracked in Scan to detect missing null checks
	reAllocCall = regexp.MustCompile(`\b(malloc|calloc|realloc)\s*\(`)
	// Assignment from malloc/calloc/realloc (ptr = malloc(...))
	reAllocAssign = regexp.MustCompile(`([a-zA-Z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?\b(?:malloc|calloc|realloc)\s*\(`)
)

// ---------------------------------------------------------------------------
// Comment / string detection (false positive reduction)
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|#|/\*|\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

// truncate ensures matched text doesn't exceed maxLen characters.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// GTSS-MEM-001: Use of Banned/Dangerous Functions
// ---------------------------------------------------------------------------

type BannedFunctions struct{}

func (r BannedFunctions) ID() string              { return "GTSS-MEM-001" }
func (r BannedFunctions) Name() string            { return "Use of Banned/Dangerous Functions" }
func (r BannedFunctions) DefaultSeverity() rules.Severity { return rules.Critical }
func (r BannedFunctions) Description() string {
	return "Detects use of C/C++ functions that are inherently unsafe and have been banned or deprecated due to buffer overflow and input validation vulnerabilities."
}
func (r BannedFunctions) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r BannedFunctions) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re         *regexp.Regexp
		conf       string
		desc       string
		suggestion string
	}

	patterns := []pattern{
		{reGets, "high", "gets() is always a buffer overflow — banned in C11", "Replace gets() with fgets(buf, sizeof(buf), stdin)."},
		{reStrcpy, "high", "strcpy() has no bounds checking", "Use strlcpy(), strncpy(), or snprintf() instead of strcpy()."},
		{reStrcat, "high", "strcat() has no bounds checking", "Use strlcat() or strncat() with explicit size limits."},
		{reSprintf, "high", "sprintf() has no bounds checking", "Use snprintf(buf, sizeof(buf), ...) instead of sprintf()."},
		{reVsprintf, "high", "vsprintf() has no bounds checking", "Use vsnprintf(buf, sizeof(buf), ...) instead of vsprintf()."},
		{reScanfS, "high", "scanf/sscanf/fscanf with %s reads unbounded input", "Use scanf(\"%255s\", buf) with explicit width or fgets() instead."},
		{reAtoi, "medium", "atoi/atol has no error checking on invalid input", "Use strtol() or strtoul() with error checking via errno and endptr."},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Banned Function: " + p.desc,
					Description:   "This function is inherently unsafe and has well-known alternatives. Using it risks buffer overflows and undefined behavior.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    p.suggestion,
					CWEID:         "CWE-676",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"memory", "banned-function", "c-cpp"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MEM-002: Format String Vulnerabilities
// ---------------------------------------------------------------------------

type FormatString struct{}

func (r FormatString) ID() string              { return "GTSS-MEM-002" }
func (r FormatString) Name() string            { return "Format String Vulnerability" }
func (r FormatString) DefaultSeverity() rules.Severity { return rules.Critical }
func (r FormatString) Description() string {
	return "Detects printf-family functions called with a variable as the format string, enabling format string attacks that can read/write arbitrary memory."
}
func (r FormatString) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r FormatString) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{rePrintfVar, "high", "printf() with variable format string"},
		{reFprintfVar, "high", "fprintf() with variable format string"},
		{reSyslogVar, "high", "syslog() with variable format string"},
		{reSnprintfVar, "medium", "snprintf() with variable format string"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Format String: " + p.desc,
					Description:   "Using a variable as the format string allows attackers to read stack memory (%x), crash the program (%n), or write to arbitrary memory addresses.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Always use a string literal as the format string: printf(\"%s\", variable) instead of printf(variable).",
					CWEID:         "CWE-134",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"memory", "format-string", "c-cpp"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MEM-003: Buffer Overflow Patterns
// ---------------------------------------------------------------------------

type BufferOverflow struct{}

func (r BufferOverflow) ID() string              { return "GTSS-MEM-003" }
func (r BufferOverflow) Name() string            { return "Buffer Overflow" }
func (r BufferOverflow) DefaultSeverity() rules.Severity { return rules.High }
func (r BufferOverflow) Description() string {
	return "Detects common buffer overflow patterns including unchecked memcpy with variable size, strncpy with strlen of source, and unsafe read/recv into fixed buffers."
}
func (r BufferOverflow) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r BufferOverflow) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re         *regexp.Regexp
		conf       string
		desc       string
		suggestion string
	}

	patterns := []pattern{
		{reMemcpyVar, "medium", "memcpy/memmove with variable size — verify bounds", "Validate that the size argument does not exceed the destination buffer size before calling memcpy/memmove."},
		{reStrncpyStrlen, "high", "strncpy with strlen(src) defeats bounds checking", "Use the destination buffer size as the length argument: strncpy(dst, src, sizeof(dst) - 1)."},
		{reReadBuf, "medium", "read/recv into buffer — ensure size matches buffer capacity", "Verify the size argument matches the actual buffer capacity and check the return value."},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Buffer Overflow: " + p.desc,
					Description:   "Writing beyond buffer boundaries can corrupt adjacent memory, leading to crashes, data corruption, or arbitrary code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    p.suggestion,
					CWEID:         "CWE-120",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"memory", "buffer-overflow", "c-cpp"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MEM-004: Memory Management Issues (double free, use after free)
// ---------------------------------------------------------------------------

type MemoryManagement struct{}

func (r MemoryManagement) ID() string              { return "GTSS-MEM-004" }
func (r MemoryManagement) Name() string            { return "Memory Management Issue" }
func (r MemoryManagement) DefaultSeverity() rules.Severity { return rules.High }
func (r MemoryManagement) Description() string {
	return "Detects double free and use-after-free patterns where a pointer is freed and then freed again or dereferenced."
}
func (r MemoryManagement) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r MemoryManagement) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track freed variables and the line where they were freed.
	// This is a simple per-function heuristic — it resets on blank lines
	// or function boundaries to limit false positives.
	freedVars := make(map[string]int) // varName -> line number of free

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Reset tracking on function boundaries (opening brace at column 0)
		if trimmed == "}" || trimmed == "{" {
			freedVars = make(map[string]int)
			continue
		}

		// Detect free(ptr) or delete ptr
		if m := reFreeCall.FindStringSubmatch(line); m != nil {
			varName := m[1]
			if freeLine, ok := freedVars[varName]; ok {
				// Double free detected
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Double Free: " + varName + " freed again",
					Description:   fmt.Sprintf("Pointer '%s' was already freed at line %d. Double free can corrupt the heap allocator and lead to arbitrary code execution.", varName, freeLine),
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Set pointer to NULL after free: free(" + varName + "); " + varName + " = NULL;",
					CWEID:         "CWE-415",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "double-free", "c-cpp"},
				})
			}
			freedVars[varName] = i + 1
			continue
		}

		if m := reDeleteCall.FindStringSubmatch(line); m != nil {
			varName := m[1]
			if _, ok := freedVars[varName]; ok {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Double Free: " + varName + " deleted again",
					Description:   "Pointer '" + varName + "' was already freed/deleted. Double delete causes undefined behavior.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Set pointer to nullptr after delete: delete " + varName + "; " + varName + " = nullptr;",
					CWEID:         "CWE-415",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "double-free", "c-cpp"},
				})
			}
			freedVars[varName] = i + 1
			continue
		}

		// Check for use-after-free: any freed variable used on this line
		for varName, freeLine := range freedVars {
			// Check if variable is used (not in a free/delete or NULL assignment)
			if strings.Contains(line, varName) {
				// Exclude lines that are setting the pointer to NULL
				nullPat := varName + `\s*=\s*(?:NULL|nullptr|0)\s*;`
				if matched, _ := regexp.MatchString(nullPat, line); matched {
					delete(freedVars, varName)
					continue
				}
				// Exclude if this line is just another free (handled above)
				if reFreeCall.MatchString(line) || reDeleteCall.MatchString(line) {
					continue
				}
				_ = freeLine
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Use After Free: " + varName + " used after being freed",
					Description:   "Pointer '" + varName + "' is used after being freed. Dereferencing freed memory leads to undefined behavior and potential code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Set pointer to NULL immediately after free and check for NULL before use. Consider using smart pointers in C++.",
					CWEID:         "CWE-416",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "use-after-free", "c-cpp"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MEM-005: Integer Overflow in Allocation
// ---------------------------------------------------------------------------

type IntegerOverflow struct{}

func (r IntegerOverflow) ID() string              { return "GTSS-MEM-005" }
func (r IntegerOverflow) Name() string            { return "Integer Overflow in Allocation" }
func (r IntegerOverflow) DefaultSeverity() rules.Severity { return rules.High }
func (r IntegerOverflow) Description() string {
	return "Detects arithmetic in memory allocation size arguments (malloc, calloc, realloc) that may overflow, leading to undersized allocations and heap buffer overflows."
}
func (r IntegerOverflow) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r IntegerOverflow) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re         *regexp.Regexp
		conf       string
		desc       string
		suggestion string
	}

	patterns := []pattern{
		{reMallocMul, "medium", "malloc() with multiplication in size — potential integer overflow", "Check for overflow before allocation: if (n > SIZE_MAX / sizeof(T)) handle_error(); Or use calloc(n, sizeof(T)) which checks internally."},
		{reCallocVar, "low", "calloc() with variable count — verify no overflow in count * size", "Ensure the count argument is validated against a maximum before calling calloc()."},
		{reReallocArith, "medium", "realloc() with arithmetic in size — potential integer overflow", "Validate the new size does not overflow before calling realloc(). Use safe arithmetic: if (a > SIZE_MAX - b) error();"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Integer Overflow: " + p.desc,
					Description:   "Integer overflow in allocation size can wrap around to a small value, causing an undersized buffer and subsequent heap overflow when data is written.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    p.suggestion,
					CWEID:         "CWE-190",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"memory", "integer-overflow", "allocation", "c-cpp"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-MEM-006: Null Pointer Dereference (unchecked malloc/calloc return)
// ---------------------------------------------------------------------------

type NullDeref struct{}

func (r NullDeref) ID() string              { return "GTSS-MEM-006" }
func (r NullDeref) Name() string            { return "Null Pointer Dereference" }
func (r NullDeref) DefaultSeverity() rules.Severity { return rules.Medium }
func (r NullDeref) Description() string {
	return "Detects use of malloc/calloc/realloc return values without checking for NULL, which can lead to null pointer dereference and crashes."
}
func (r NullDeref) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r NullDeref) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Find allocation assignments: ptr = (type*)malloc(...)
		m := reAllocAssign.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		varName := m[1]

		// Look at the next few lines (up to 5) for a NULL check
		hasNullCheck := false
		scanEnd := i + 6
		if scanEnd > len(lines) {
			scanEnd = len(lines)
		}
		for j := i + 1; j < scanEnd; j++ {
			nextLine := lines[j]
			// Check for common null-check patterns:
			// if (ptr == NULL), if (!ptr), if (ptr == 0), if (ptr != NULL)
			if strings.Contains(nextLine, varName) {
				if strings.Contains(nextLine, "NULL") ||
					strings.Contains(nextLine, "nullptr") ||
					strings.Contains(nextLine, "!"+varName) ||
					strings.Contains(nextLine, "! "+varName) {
					hasNullCheck = true
					break
				}
				// Pattern: if (ptr) or if (!ptr)
				ifCheck := regexp.MustCompile(`\bif\s*\(\s*!?\s*` + regexp.QuoteMeta(varName) + `\s*\)`)
				if ifCheck.MatchString(nextLine) {
					hasNullCheck = true
					break
				}
			}
		}

		if !hasNullCheck {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Null Dereference: unchecked return from " + reAllocCall.FindString(line),
				Description:   "The return value of malloc/calloc/realloc is used without checking for NULL. On allocation failure, dereferencing the pointer causes undefined behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Always check the return value: " + varName + " = malloc(...); if (" + varName + " == NULL) { /* handle error */ }",
				CWEID:         "CWE-476",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"memory", "null-dereference", "c-cpp"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(BannedFunctions{})
	rules.Register(FormatString{})
	rules.Register(BufferOverflow{})
	rules.Register(MemoryManagement{})
	rules.Register(IntegerOverflow{})
	rules.Register(NullDeref{})
}
