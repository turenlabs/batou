package memory

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended memory safety detection
// ---------------------------------------------------------------------------

var (
	// GTSS-MEM-007: Use after free pattern
	reExtFreePtr       = regexp.MustCompile(`\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)`)
	reExtDeletePtr     = regexp.MustCompile(`\bdelete\s*(?:\[\])?\s+([a-zA-Z_]\w*)`)
	reExtPtrDeref      = regexp.MustCompile(`([a-zA-Z_]\w*)\s*->`)
	reExtPtrArrayAccess = regexp.MustCompile(`([a-zA-Z_]\w*)\s*\[`)
	reExtPtrStarDeref  = regexp.MustCompile(`\*\s*([a-zA-Z_]\w*)`)
	reExtNullAssign    = regexp.MustCompile(`([a-zA-Z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;`)

	// GTSS-MEM-008: Double free
	// Uses reExtFreePtr and reExtDeletePtr above

	// GTSS-MEM-009: Integer overflow in allocation size
	reExtMallocArith  = regexp.MustCompile(`\bmalloc\s*\(\s*[^)]*[+*]\s*[^)]*\)`)
	reExtCallocMul    = regexp.MustCompile(`\bcalloc\s*\(\s*[a-zA-Z_]\w*\s*,\s*[a-zA-Z_]\w*\s*\)`)
	reExtReallocAdd   = regexp.MustCompile(`\brealloc\s*\(\s*[^,]+,\s*[^)]*[+*]\s*[^)]*\)`)
	reExtOverflowCheck = regexp.MustCompile(`(?:SIZE_MAX|UINT_MAX|INT_MAX|__builtin_mul_overflow|__builtin_add_overflow|safe_mul|safe_add|checked_mul|overflow_check)`)

	// GTSS-MEM-010: Stack buffer overflow
	reExtFixedBuf     = regexp.MustCompile(`\bchar\s+([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]`)
	reExtUnsafeCopy   = regexp.MustCompile(`\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\(\s*([a-zA-Z_]\w*)`)
	reExtStackSizeVar = regexp.MustCompile(`\b(?:int|unsigned|size_t|long)\s+[a-zA-Z_]\w*\s*\[\s*[a-zA-Z_]\w*\s*\]`)

	// GTSS-MEM-011: Format string vulnerability
	reExtFmtStrFunc   = regexp.MustCompile(`\b(printf|fprintf|sprintf|snprintf|syslog|err|warn|vprintf|vfprintf|vsprintf|vsnprintf)\s*\(`)
	reExtFmtStrVar    = regexp.MustCompile(`\b(?:printf|fprintf|sprintf|snprintf|syslog|err|warn)\s*\([^"]*[a-zA-Z_]\w*\s*[,)]`)
	reExtFmtStrLiteral = regexp.MustCompile(`\b(?:printf|syslog|err|warn)\s*\(\s*"`)

	// GTSS-MEM-012: Uninitialized variable use
	reExtLocalDecl     = regexp.MustCompile(`^\s*(?:int|char|unsigned|long|short|float|double|size_t|ssize_t|off_t|pid_t|void\s*\*|[A-Z][a-zA-Z_]*\s*\*?)\s+([a-zA-Z_]\w*)\s*;`)
	reExtPtrDecl       = regexp.MustCompile(`^\s*(?:[a-zA-Z_]\w*\s*\*)\s*([a-zA-Z_]\w*)\s*;`)

	// GTSS-MEM-013: Off-by-one buffer error
	reExtLoopBound    = regexp.MustCompile(`for\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<=\s*(?:sizeof|strlen|len|size|count|length|n|num|max)\s*\(?\s*([a-zA-Z_]\w*)?\s*\)?\s*;`)
	reExtArrayWrite   = regexp.MustCompile(`([a-zA-Z_]\w*)\s*\[\s*([a-zA-Z_]\w*)\s*\]\s*=`)
	reExtFencePost    = regexp.MustCompile(`\[\s*(?:sizeof|strlen|len|size|count|length)\s*\(\s*[a-zA-Z_]\w*\s*\)\s*\]`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&UseAfterFreeExt{})
	rules.Register(&DoubleFreeExt{})
	rules.Register(&IntOverflowAllocExt{})
	rules.Register(&StackBufferOverflow{})
	rules.Register(&FormatStringExt{})
	rules.Register(&UninitVarUse{})
	rules.Register(&OffByOneError{})
}

// ========================================================================
// GTSS-MEM-007: Use After Free Pattern
// ========================================================================

type UseAfterFreeExt struct{}

func (r *UseAfterFreeExt) ID() string                     { return "GTSS-MEM-007" }
func (r *UseAfterFreeExt) Name() string                   { return "UseAfterFreeExt" }
func (r *UseAfterFreeExt) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UseAfterFreeExt) Description() string {
	return "Detects use-after-free patterns where a pointer is dereferenced after being freed without being reassigned."
}
func (r *UseAfterFreeExt) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *UseAfterFreeExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track freed pointers per scope (reset on function boundaries)
	freedPtrs := make(map[string]int)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "}" || trimmed == "{" {
			freedPtrs = make(map[string]int)
			continue
		}

		// Detect free(ptr) or delete ptr
		if m := reExtFreePtr.FindStringSubmatch(line); m != nil {
			freedPtrs[m[1]] = i + 1
			continue
		}
		if m := reExtDeletePtr.FindStringSubmatch(line); m != nil {
			freedPtrs[m[1]] = i + 1
			continue
		}

		// Check if nullified
		if m := reExtNullAssign.FindStringSubmatch(line); m != nil {
			delete(freedPtrs, m[1])
			continue
		}

		// Check for dereference of freed pointer
		for ptrName, freeLine := range freedPtrs {
			if !strings.Contains(line, ptrName) {
				continue
			}
			// Check for dereference patterns: ptr->, *ptr, ptr[
			isDeref := false
			if m := reExtPtrDeref.FindStringSubmatch(line); m != nil && m[1] == ptrName {
				isDeref = true
			}
			if !isDeref {
				if m := reExtPtrArrayAccess.FindStringSubmatch(line); m != nil && m[1] == ptrName {
					isDeref = true
				}
			}
			if !isDeref {
				if m := reExtPtrStarDeref.FindStringSubmatch(line); m != nil && m[1] == ptrName {
					isDeref = true
				}
			}
			if isDeref {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         fmt.Sprintf("Use-after-free: '%s' dereferenced after free at line %d", ptrName, freeLine),
					Description:   fmt.Sprintf("Pointer '%s' was freed at line %d and is dereferenced here without being reassigned. Use-after-free can lead to crashes, data corruption, or arbitrary code execution.", ptrName, freeLine),
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Set pointer to NULL immediately after free: free(" + ptrName + "); " + ptrName + " = NULL; In C++, use smart pointers (std::unique_ptr, std::shared_ptr).",
					CWEID:         "CWE-416",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "use-after-free", "c-cpp"},
				})
				break
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-MEM-008: Double Free
// ========================================================================

type DoubleFreeExt struct{}

func (r *DoubleFreeExt) ID() string                     { return "GTSS-MEM-008" }
func (r *DoubleFreeExt) Name() string                   { return "DoubleFreeExt" }
func (r *DoubleFreeExt) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DoubleFreeExt) Description() string {
	return "Detects double-free patterns where the same pointer is freed twice without being reassigned."
}
func (r *DoubleFreeExt) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *DoubleFreeExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	freedPtrs := make(map[string]int)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "}" || trimmed == "{" {
			freedPtrs = make(map[string]int)
			continue
		}

		// Detect null assignment (clears tracking)
		if m := reExtNullAssign.FindStringSubmatch(line); m != nil {
			delete(freedPtrs, m[1])
			continue
		}

		// Check for free
		if m := reExtFreePtr.FindStringSubmatch(line); m != nil {
			ptrName := m[1]
			if prevLine, ok := freedPtrs[ptrName]; ok {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         fmt.Sprintf("Double free: '%s' freed again (first freed at line %d)", ptrName, prevLine),
					Description:   fmt.Sprintf("Pointer '%s' was already freed at line %d and is freed again. Double free corrupts the heap allocator and can be exploited for arbitrary code execution.", ptrName, prevLine),
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Set pointer to NULL after free to prevent double-free: free(" + ptrName + "); " + ptrName + " = NULL; In C++, use smart pointers.",
					CWEID:         "CWE-415",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "double-free", "c-cpp"},
				})
			}
			freedPtrs[ptrName] = i + 1
			continue
		}

		// Check for delete
		if m := reExtDeletePtr.FindStringSubmatch(line); m != nil {
			ptrName := m[1]
			if prevLine, ok := freedPtrs[ptrName]; ok {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         fmt.Sprintf("Double delete: '%s' deleted again (first deleted at line %d)", ptrName, prevLine),
					Description:   fmt.Sprintf("Pointer '%s' was already deleted at line %d. Double delete causes undefined behavior and potential code execution.", ptrName, prevLine),
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Set pointer to nullptr after delete: delete " + ptrName + "; " + ptrName + " = nullptr; Use std::unique_ptr for automatic memory management.",
					CWEID:         "CWE-415",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "double-free", "c-cpp"},
				})
			}
			freedPtrs[ptrName] = i + 1
		}
	}
	return findings
}

// ========================================================================
// GTSS-MEM-009: Integer Overflow in Allocation Size
// ========================================================================

type IntOverflowAllocExt struct{}

func (r *IntOverflowAllocExt) ID() string                     { return "GTSS-MEM-009" }
func (r *IntOverflowAllocExt) Name() string                   { return "IntOverflowAllocExt" }
func (r *IntOverflowAllocExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *IntOverflowAllocExt) Description() string {
	return "Detects arithmetic in memory allocation size arguments that may overflow, leading to undersized allocations."
}
func (r *IntOverflowAllocExt) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *IntOverflowAllocExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if reExtOverflowCheck.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		var detail string
		if m := reExtMallocArith.FindString(line); m != "" {
			matched = m
			detail = "malloc() with arithmetic in size argument"
		} else if m := reExtReallocAdd.FindString(line); m != "" {
			matched = m
			detail = "realloc() with arithmetic in size argument"
		} else if m := reExtCallocMul.FindString(line); m != "" {
			matched = m
			detail = "calloc() with variable count and size (verify no overflow)"
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Integer overflow risk: " + detail,
				Description:   "Arithmetic in allocation size arguments can overflow, wrapping around to a small value. The resulting undersized buffer causes heap buffer overflow when data is written.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Check for overflow before allocation. Use __builtin_mul_overflow (GCC/Clang) or check: if (n > SIZE_MAX / elem_size) return error. Or use calloc() which checks internally.",
				CWEID:         "CWE-190",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"memory", "integer-overflow", "allocation", "c-cpp"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-MEM-010: Stack Buffer Overflow
// ========================================================================

type StackBufferOverflow struct{}

func (r *StackBufferOverflow) ID() string                     { return "GTSS-MEM-010" }
func (r *StackBufferOverflow) Name() string                   { return "StackBufferOverflow" }
func (r *StackBufferOverflow) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *StackBufferOverflow) Description() string {
	return "Detects stack buffer overflow patterns where fixed-size buffers are used with unbounded copy functions."
}
func (r *StackBufferOverflow) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *StackBufferOverflow) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track fixed-size buffers declared in the current scope
	stackBufs := make(map[string]bool)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "}" || trimmed == "{" {
			stackBufs = make(map[string]bool)
			continue
		}

		// Track fixed-size buffer declarations
		if m := reExtFixedBuf.FindStringSubmatch(line); m != nil {
			stackBufs[m[1]] = true
		}

		// Variable-length arrays on the stack
		if m := reExtStackSizeVar.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Variable-length array on stack (potential overflow)",
				Description:   "A variable-length array is allocated on the stack. If the size is user-controlled, it can cause stack overflow or be used to overwrite the return address.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use heap allocation (malloc/calloc) instead of VLAs. Validate the size against a reasonable maximum. VLAs are optional in C11 and disallowed in C++.",
				CWEID:         "CWE-121",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"memory", "stack-overflow", "vla", "c-cpp"},
			})
		}

		// Check if unsafe copy targets a known stack buffer
		if m := reExtUnsafeCopy.FindStringSubmatch(line); m != nil {
			if stackBufs[m[1]] {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         fmt.Sprintf("Stack buffer overflow: unbounded copy to stack buffer '%s'", m[1]),
					Description:   fmt.Sprintf("An unbounded copy function writes to the stack buffer '%s'. Overflowing a stack buffer overwrites the return address, enabling arbitrary code execution.", m[1]),
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Use bounded alternatives: strncpy, strncat, snprintf. Always pass sizeof(buffer) as the limit. Better yet, use strlcpy/strlcat which null-terminate correctly.",
					CWEID:         "CWE-121",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"memory", "stack-overflow", "buffer-overflow", "c-cpp"},
				})
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-MEM-011: Format String Vulnerability
// ========================================================================

type FormatStringExt struct{}

func (r *FormatStringExt) ID() string                     { return "GTSS-MEM-011" }
func (r *FormatStringExt) Name() string                   { return "FormatStringExt" }
func (r *FormatStringExt) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *FormatStringExt) Description() string {
	return "Detects printf-family function calls where the format string is a variable instead of a string literal."
}
func (r *FormatStringExt) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *FormatStringExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		// Skip if the format string is a literal
		if reExtFmtStrLiteral.MatchString(line) {
			continue
		}
		if m := reExtFmtStrVar.FindString(line); m != "" {
			funcMatch := reExtFmtStrFunc.FindStringSubmatch(line)
			funcName := "printf-family"
			if funcMatch != nil {
				funcName = funcMatch[1]
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         fmt.Sprintf("Format string vulnerability in %s()", funcName),
				Description:   fmt.Sprintf("%s() is called with a variable as the format string. An attacker who controls this variable can use format specifiers (%%x, %%n, %%s) to read/write arbitrary memory.", funcName),
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    fmt.Sprintf("Use a string literal as the format string: %s(\"%%s\", variable) instead of %s(variable).", funcName, funcName),
				CWEID:         "CWE-134",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"memory", "format-string", "c-cpp"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-MEM-012: Uninitialized Variable Use
// ========================================================================

type UninitVarUse struct{}

func (r *UninitVarUse) ID() string                     { return "GTSS-MEM-012" }
func (r *UninitVarUse) Name() string                   { return "UninitVarUse" }
func (r *UninitVarUse) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UninitVarUse) Description() string {
	return "Detects local variables declared without initialization that may be used before being assigned."
}
func (r *UninitVarUse) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *UninitVarUse) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track uninitialized variables
	uninitVars := make(map[string]int) // varName -> declaration line

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "}" || trimmed == "{" {
			uninitVars = make(map[string]int)
			continue
		}

		// Detect uninitialized local variable declarations
		if m := reExtLocalDecl.FindStringSubmatch(line); m != nil {
			uninitVars[m[1]] = i + 1
			continue
		}
		if m := reExtPtrDecl.FindStringSubmatch(line); m != nil {
			uninitVars[m[1]] = i + 1
			continue
		}

		// Check if any uninitialized variable is used (assigned or dereferenced)
		for varName := range uninitVars {
			if !strings.Contains(line, varName) {
				continue
			}
			// If it's being assigned, remove from tracking
			assignPat := varName + `\s*=`
			if matched, _ := regexp.MatchString(assignPat, line); matched {
				delete(uninitVars, varName)
				continue
			}
			// If used in a function call or expression, flag it
			if strings.Contains(line, "(") || strings.Contains(line, "->") ||
				strings.Contains(line, "[") || strings.Contains(line, "return") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         fmt.Sprintf("Uninitialized variable '%s' used", varName),
					Description:   fmt.Sprintf("Variable '%s' was declared without initialization and may be used before being assigned a value. Uninitialized variables contain indeterminate values from the stack.", varName),
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    fmt.Sprintf("Initialize the variable at declaration: int %s = 0; or ensure all code paths assign a value before use.", varName),
					CWEID:         "CWE-457",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"memory", "uninitialized", "c-cpp"},
				})
				delete(uninitVars, varName)
				break
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-MEM-013: Off-by-One Buffer Error
// ========================================================================

type OffByOneError struct{}

func (r *OffByOneError) ID() string                     { return "GTSS-MEM-013" }
func (r *OffByOneError) Name() string                   { return "OffByOneError" }
func (r *OffByOneError) DefaultSeverity() rules.Severity { return rules.High }
func (r *OffByOneError) Description() string {
	return "Detects off-by-one errors in loop bounds and array access patterns that can cause buffer overflow by one byte."
}
func (r *OffByOneError) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *OffByOneError) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		// Pattern 1: for loop with <= instead of < (common off-by-one)
		if m := reExtLoopBound.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Off-by-one: loop bound uses <= with size/length",
				Description:   "A for loop uses <= with a size or length value as the upper bound. Since arrays are zero-indexed, this iterates one element beyond the buffer boundary, causing a one-byte overflow.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use < instead of <= for array bounds: for (i = 0; i < size; i++). The valid indices are [0, size-1].",
				CWEID:         "CWE-193",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"memory", "off-by-one", "buffer-overflow", "c-cpp"},
			})
		}

		// Pattern 2: array access at buffer[sizeof(buffer)] or buffer[strlen(str)]
		if m := reExtFencePost.FindString(line); m != "" {
			// Check if it's a write operation
			if reExtArrayWrite.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Off-by-one: write at buffer[sizeof/strlen] (past end of buffer)",
					Description:   "Writing to buffer[sizeof(buffer)] or buffer[strlen(str)] writes one byte past the end of the buffer. For null-terminated strings, use sizeof(buffer) - 1.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use sizeof(buffer) - 1 for the last valid index. For null-terminated strings: buffer[sizeof(buffer) - 1] = '\\0'.",
					CWEID:         "CWE-193",
					OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"memory", "off-by-one", "buffer-overflow", "c-cpp"},
				})
			}
		}
	}
	return findings
}
