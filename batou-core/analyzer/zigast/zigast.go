// Package zigast implements a dedicated structural security analyzer for the
// Zig language, focused on memory-safety / undefined-behaviour classes that the
// coarse regex + taint tiers cannot reason about on their own:
//
//   - Pointer-provenance hazards: @ptrCast / @bitCast that reinterpret a
//     pointer or slice as an unrelated (often wider) type, and
//     @intToPtr / @ptrFromInt that forge a pointer from an integer. These are
//     classic type-confusion / out-of-bounds-read primitives.
//   - @memcpy with a non-comptime (runtime / variable) length. Zig's @memcpy is
//     memory-unsafe when the destination and source lengths disagree; a runtime
//     length derived from input is a textbook bounds bug.
//   - Allocator use-after-free shapes: a slice/pointer is freed via
//     `allocator.free(x)` / `allocator.destroy(x)` and then read or written
//     later in the same function.
//
// EXTERNAL-ORIGIN GATING (why this analyzer is taint-gated, not purely
// structural). Memory-safety hazards are a provenance/bounds problem, and the
// dangerous builtins (@ptrCast / @bitCast / @memcpy) are PERVASIVE in normal,
// safe Zig — the standard library alone applies them thousands of times to
// purely local / comptime / internally-constructed data. Flagging the shape
// itself drowns the user in false positives (1800+ on the Zig stdlib). So this
// analyzer fires ONLY when the dangerous operand can be shown — by a bounded
// intra-function backward scan — to derive from EXTERNAL / untrusted input:
//
//   - a value returned by a recognised external-source call: std.http /
//     std.net / std.posix.read / os.read / readToEndAlloc / reader.read* /
//     recv / process.args / std.io stdin reads, etc. (zigExternalSourceRE), or
//   - a []u8 / []const u8 / [*]u8 slice that is a FUNCTION PARAMETER of a
//     handler-shaped fn (one that takes a byte slice or a reader/connection/
//     request and is named/shaped like a request handler — zigHandlerParam), or
//   - a value transitively assigned/sliced/length-derived from one of the above
//     within the same function body.
//
// Operands that trace to a local var, a comptime constant, a literal address,
// an internally-built buffer, or a `.len` of a trusted slice are NOT emitted.
// This mirrors how analyzer/pyast reasons about a sink variable's last
// assignment before emitting (PR-PATHpy): the blind structural signal is
// silenced unless an external origin is established. Findings carry AST-tier
// rule IDs (BATOU-ZIG-AST-###) so the scanner treats them as Layer-2 findings.
//
// Why a lexical (not tree-sitter) analyzer? The vendored go-tree-sitter
// distribution ships NO Zig grammar, so `ast.Parse(..., LangZig)` returns nil
// and there is no parse tree to walk. This analyzer performs its own structural
// scan: it strips comments and string/char literals, then extracts
// balanced-parenthesis builtin-call argument lists and reasons about their
// structure and data provenance.
//
// Strictly gated to rules.LangZig — emits nothing for any other language.
package zigast

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ZigASTAnalyzer performs structural memory-safety analysis of Zig source.
type ZigASTAnalyzer struct{}

func init() {
	rules.Register(&ZigASTAnalyzer{})
}

func (z *ZigASTAnalyzer) ID() string                      { return "BATOU-ZIG-AST" }
func (z *ZigASTAnalyzer) Name() string                    { return "Zig AST Security Analyzer" }
func (z *ZigASTAnalyzer) DefaultSeverity() rules.Severity { return rules.High }
func (z *ZigASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangZig} }
func (z *ZigASTAnalyzer) Description() string {
	return "Structural analysis of Zig for memory-safety/undefined-behaviour: pointer-provenance hazards (@ptrCast/@bitCast/@intToPtr/@ptrFromInt), @memcpy with runtime length (bounds), and allocator use-after-free shapes."
}

func (z *ZigASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangZig {
		return nil
	}
	if strings.TrimSpace(ctx.Content) == "" {
		return nil
	}
	c := &zigChecker{
		filePath: ctx.FilePath,
		// Mask comments and literals so structural detection never trips on
		// patterns inside strings or commented-out code. Line/column geometry
		// is preserved by the mask (it replaces only inner bytes).
		masked: maskCommentsAndStrings(ctx.Content),
	}
	c.lines = splitLinesKeepIndex(c.masked)
	c.fnSpans = zigFunctionSpans(c.masked)
	c.checkBuiltinCasts()
	c.checkMemcpyLength()
	c.checkUseAfterFree()
	return c.findings
}

type zigChecker struct {
	filePath string
	masked   string   // source with comments/literals neutralised
	lines    []string // masked source split by line (index 0 == line 1)
	fnSpans  []fnSpan // enclosing-function spans for external-origin gating
	findings []rules.Finding
}

// ---------------------------------------------------------------------------
// Pointer-provenance / pointer-forging builtins (CWE-704 / CWE-787 / CWE-843)
// ---------------------------------------------------------------------------

type castSpec struct {
	builtin  string
	ruleID   string
	cwe      string
	owasp    string
	severity rules.Severity
	title    string
	desc     string
	fix      string
	tags     []string
	// requiresPointer restricts the rule to casts that actually involve a
	// pointer/slice (either the destination type or the operand). @bitCast of
	// scalar↔scalar bit patterns is a benign, pervasive idiom even on external
	// data; only pointer/slice transmutes are a provenance hazard, matching this
	// rule's own description.
	requiresPointer bool
}

var provenanceCasts = []castSpec{
	{
		builtin:  "@ptrCast",
		ruleID:   "BATOU-ZIG-AST-001",
		cwe:      "CWE-843",
		owasp:    "A06:2021-Vulnerable and Outdated Components",
		severity: rules.High,
		title:    "Pointer-provenance hazard: @ptrCast reinterprets a pointer",
		desc:     "@ptrCast reinterprets a pointer/slice as an unrelated pointee type. If the destination type is wider than the underlying buffer, dereferencing the result reads past the allocation (out-of-bounds read / type confusion). This is undefined behaviour even in safe build modes.",
		fix:      "Avoid reinterpreting buffers via @ptrCast. Parse bytes explicitly (std.mem.readInt / a bounds-checked reader), or validate that the source slice is at least @sizeOf(Dest) before casting.",
		tags:     []string{"memory-safety", "provenance", "type-confusion", "undefined-behavior"},
	},
	{
		builtin:         "@bitCast",
		ruleID:          "BATOU-ZIG-AST-002",
		cwe:             "CWE-704",
		owasp:           "A06:2021-Vulnerable and Outdated Components",
		severity:        rules.Medium,
		title:           "Provenance hazard: @bitCast reinterprets pointer-bearing value",
		desc:            "@bitCast reinterprets the bit pattern of a value as another type. When used to forge or transmute pointers/slices it bypasses the type system and can fabricate dangling or out-of-bounds pointers (undefined behaviour).",
		fix:             "Only @bitCast between plain integer/float scalar types of equal size. Never @bitCast to or from pointer/slice types.",
		tags:            []string{"memory-safety", "provenance", "undefined-behavior"},
		requiresPointer: true,
	},
	{
		builtin:  "@intToPtr",
		ruleID:   "BATOU-ZIG-AST-003",
		cwe:      "CWE-787",
		owasp:    "A06:2021-Vulnerable and Outdated Components",
		severity: rules.High,
		title:    "Pointer forged from integer: @intToPtr",
		desc:     "@intToPtr fabricates a pointer from an integer address with no provenance. Dereferencing it is undefined behaviour and, when the integer is attacker-influenced, an arbitrary-memory read/write primitive.",
		fix:      "Do not synthesise pointers from integers. Keep real pointer provenance; if interfacing with hardware/FFI, isolate and audit the conversion and never derive the address from untrusted input.",
		tags:     []string{"memory-safety", "provenance", "arbitrary-write", "undefined-behavior"},
	},
	{
		builtin:  "@ptrFromInt",
		ruleID:   "BATOU-ZIG-AST-003", // same class as @intToPtr (Zig 0.12+ rename)
		cwe:      "CWE-787",
		owasp:    "A06:2021-Vulnerable and Outdated Components",
		severity: rules.High,
		title:    "Pointer forged from integer: @ptrFromInt",
		desc:     "@ptrFromInt (Zig 0.12+) fabricates a pointer from an integer address with no provenance. Dereferencing it is undefined behaviour and, when the integer is attacker-influenced, an arbitrary-memory read/write primitive.",
		fix:      "Do not synthesise pointers from integers. Keep real pointer provenance; if interfacing with hardware/FFI, isolate and audit the conversion and never derive the address from untrusted input.",
		tags:     []string{"memory-safety", "provenance", "arbitrary-write", "undefined-behavior"},
	},
}

// checkBuiltinCasts flags provenance-hazard builtin calls whose reinterpreted
// operand can be shown to derive from EXTERNAL/untrusted input by a bounded
// intra-function backward scan. A cast applied to a local var, a comptime
// constant, a literal address, or an internally-built buffer is NOT emitted —
// that is the overwhelmingly-common safe case that floods on real code.
func (c *zigChecker) checkBuiltinCasts() {
	for _, spec := range provenanceCasts {
		for _, off := range findBuiltinCalls(c.masked, spec.builtin) {
			// Extract the cast's operand expression(s) and require at least one
			// to trace to an external source within the enclosing function.
			args, ok := extractCallArgs(c.masked, off+len(spec.builtin))
			if !ok || len(args) == 0 {
				continue
			}
			fn := c.enclosingFn(off)
			if fn == nil {
				continue // outside any fn → can't establish provenance → skip
			}
			line, col := lineColOf(c.masked, off)
			// @bitCast is only a provenance hazard when a pointer/slice is
			// involved. A scalar↔scalar bit reinterpret (the dominant idiom,
			// even on external bytes) is benign and must not fire.
			if spec.requiresPointer && !castInvolvesPointer(args, c.lineTextAt(off)) {
				continue
			}
			declOff := c.declStartOff(off)
			external := false
			for _, a := range args {
				if c.operandIsExternal(fn, a, declOff) {
					external = true
					break
				}
			}
			if !external {
				continue
			}
			c.findings = append(c.findings, rules.Finding{
				RuleID:        spec.ruleID,
				Severity:      spec.severity,
				SeverityLabel: spec.severity.String(),
				Title:         spec.title,
				Description:   spec.desc,
				FilePath:      c.filePath,
				LineNumber:    line,
				Column:        col,
				MatchedText:   excerpt(c.lines, line),
				Suggestion:    spec.fix,
				CWEID:         spec.cwe,
				OWASPCategory: spec.owasp,
				Language:      rules.LangZig,
				Confidence:    "high",
				Tags:          spec.tags,
			})
		}
	}
}

// lineTextAt returns the full masked text of the line containing offset off
// (used to inspect the destination type annotation of a cast statement).
func (c *zigChecker) lineTextAt(off int) string {
	if off > len(c.masked) {
		off = len(c.masked)
	}
	start := strings.LastIndexByte(c.masked[:off], '\n') + 1
	end := strings.IndexByte(c.masked[off:], '\n')
	if end < 0 {
		return c.masked[start:]
	}
	return c.masked[start : off+end]
}

// castInvolvesPointer reports whether a cast's operand expression(s) or the
// destination type annotation on the statement line denotes a pointer / slice /
// many-item-pointer. This is what distinguishes a hazardous pointer transmute
// from a benign scalar bit-reinterpret.
func castInvolvesPointer(args []string, lineText string) bool {
	if ptrShaped(lineText) {
		return true
	}
	for _, a := range args {
		if ptrShaped(a) {
			return true
		}
	}
	return false
}

// ptrShaped reports whether s contains a pointer/slice type marker: a `*T`
// single pointer, `[*]`/`[*c]` many-item pointer, `[]T` slice, `.ptr` field
// access, or an `&expr` address-of.
func ptrShaped(s string) bool {
	if strings.Contains(s, ".ptr") || strings.Contains(s, "[*") ||
		strings.Contains(s, "&") {
		return true
	}
	// `: *T` / `: []T` / `:*T` destination annotations
	if zigPtrTypeRE.MatchString(s) {
		return true
	}
	return false
}

// zigPtrTypeRE matches a pointer or slice type annotation in TYPE position: a
// `:` followed by `*` / `[]` / `[*]`, or a `[]`/`[:N]` slice type, or an
// `@as(*T, ...)` / `@as([]T, ...)` coercion. It anchors on a type-position
// colon or a slice bracket so a bare `*` used as multiplication is not matched.
var zigPtrTypeRE = regexp.MustCompile(`:\s*(?:\*|\[\]|\[\*|\[:\d)|@as\(\s*(?:\*|\[\]|\[\*)|\bptrCast\b`)

// ---------------------------------------------------------------------------
// @memcpy with a runtime / variable length (CWE-120 / CWE-787)
// ---------------------------------------------------------------------------

// checkMemcpyLength flags @memcpy(dst, src) calls whose copied length is a
// runtime value rather than a comptime-known literal. Zig's @memcpy requires
// dst.len == src.len; when the length is sliced with a runtime expression
// (dst[0..n], src[0..len]) a size mismatch is a buffer overflow. A copy
// between two named whole slices (no [..] subslicing, no literal length) is
// likewise unverifiable structurally, so it is reported at lower confidence.
func (c *zigChecker) checkMemcpyLength() {
	for _, off := range findBuiltinCalls(c.masked, "@memcpy") {
		args, ok := extractCallArgs(c.masked, off+len("@memcpy"))
		if !ok || len(args) == 0 {
			continue
		}
		fn := c.enclosingFn(off)
		if fn == nil {
			continue
		}
		declOff := c.declStartOff(off)
		// Highest-signal bounds shape (the lever's narrow target): @memcpy whose
		// copied length is a runtime, EXTERNALLY-derived value copied INTO A
		// FIXED-SIZE DESTINATION, with no @min/bounds-clamp on the length. We
		// require:
		//   (a) the destination (first arg) base is a fixed-size array
		//       (`[N]u8`-style) — a caller-sized slice/many-ptr param cannot be
		//       structurally faulted and is the dominant safe idiom; AND
		//   (b) a runtime-bounded slice arg whose length expression traces to an
		//       external source; AND
		//   (c) the length is NOT @min(...)-clamped (an explicit bounds check)
		//       and the @memcpy line carries no such clamp.
		dstBase := memcpyDestBase(args)
		if dstBase == "" || !c.destIsFixedArray(fn, dstBase, declOff) {
			continue
		}
		lineText := c.lineTextAt(off)
		if strings.Contains(lineText, "@min(") {
			continue // length explicitly clamped on this line → bounded
		}
		// Only the DESTINATION slice's runtime upper bound can overflow the
		// fixed array; the source slice's length is irrelevant to dest overflow
		// (Zig requires equal lengths). Evaluate the hazard on args[0] only.
		hazard := false
		if lenExpr, has := runtimeBoundExpr(args[0]); has {
			if !c.lengthIsClamped(fn, lenExpr, declOff) &&
				// The dangerous shape is a RAW external length copied verbatim
				// into a fixed array (e.g. `result[0..msg.len]`). A length built
				// by additive/subtractive OFFSET arithmetic (`adrem - 8`,
				// `end - start`) is, in practice, an internally-bounded remainder
				// within a loop and cannot be structurally faulted — the
				// surrounding invariant (which we do not model) keeps it below
				// the destination size. Exclude such offset lengths.
				!c.lengthIsOffsetArithmetic(fn, lenExpr, declOff) &&
				c.operandIsExternal(fn, lenExpr, declOff) {
				hazard = true
			}
		}
		if !hazard {
			continue
		}
		line, col := lineColOf(c.masked, off)
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-ZIG-AST-004",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "@memcpy with runtime length (bounds / overflow risk)",
			Description:   "@memcpy is invoked with a runtime-computed slice length. Zig requires the destination and source lengths to match exactly; a length derived from a variable (especially one influenced by input) can exceed the destination capacity, corrupting adjacent memory. Safe-mode bounds checks do not cover raw @memcpy.",
			FilePath:      c.filePath,
			LineNumber:    line,
			Column:        col,
			MatchedText:   excerpt(c.lines, line),
			Suggestion:    "Validate the copied length against @min(dst.len, src.len) before the copy, or use std.mem.copyForwards with explicitly bounded slices. Never derive the length from untrusted input without a bounds check.",
			CWEID:         "CWE-120",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
			Language:      rules.LangZig,
			Confidence:    "high",
			Tags:          []string{"memory-safety", "bounds", "buffer-overflow"},
		})
	}
}

// ---------------------------------------------------------------------------
// Allocator use-after-free (CWE-416)
// ---------------------------------------------------------------------------

// checkUseAfterFree flags a slice/pointer that is freed via
// `<x>.free(<v>)` / `<x>.destroy(<v>)` and then referenced again later in the
// same function body. Structural, intra-function heuristic: it scans each
// function body, records the line a value is freed, and reports a subsequent
// use of that identifier (index, field access, or pass-by-value) within the
// same body.
func (c *zigChecker) checkUseAfterFree() {
	for _, span := range c.fnSpans {
		body := funcBody{lines: bodyLinesIn(c.masked, span.bodyOpen+1, span.end)}
		freed := map[string]int{} // freed expression (field-sensitive) -> free offset
		for _, ln := range body.lines {
			text := ln.text

			// Record frees: alloc.free(x) / allocator.destroy(x) / gpa.free(x).
			// We record the FULL freed expression (field-sensitive), e.g.
			// "tree.source" or "entry.key_ptr.*", so a later access to a
			// SIBLING field/member of the same root is not mistaken for a use
			// of the freed allocation.
			if v, ok := freedExpr(text); ok {
				// External-origin gate: only treat the free/use as a reportable
				// hazard when the freed allocation traces to EXTERNAL input
				// within this function. Internal-allocator lifetimes (the
				// overwhelmingly-common case) are a local-ownership concern that
				// floods structurally; they are out of scope for this taint-
				// gated analyzer.
				declOff := c.declStartOff(ln.startOff)
				root := leadingIdent(v)
				if c.operandIsExternal(&span, root, declOff) {
					if prevOff, seen := freed[v]; seen {
						// Double-free: the same externally-derived allocation is
						// freed again with no intervening rebind (a rebind would
						// have deleted v from `freed` in the use loop below).
						absLine, col := lineColOf(c.masked, ln.startOff)
						prevLine, _ := lineColOf(c.masked, prevOff)
						c.findings = append(c.findings, rules.Finding{
							RuleID:        "BATOU-ZIG-AST-006",
							Severity:      rules.Critical,
							SeverityLabel: rules.Critical.String(),
							Title:         "Double-free: '" + v + "' freed twice",
							Description:   "The externally-derived allocation '" + v + "' is freed again here after being freed on line " + strconv.Itoa(prevLine) + " with no intervening reassignment. Freeing the same allocation twice corrupts the allocator's metadata (double-free) and is a common exploitation primitive.",
							FilePath:      c.filePath,
							LineNumber:    absLine,
							Column:        col,
							MatchedText:   excerpt(c.lines, absLine),
							Suggestion:    "Free each allocation exactly once. Use a single `defer allocator.free(x)` at the allocation site, or set the pointer to undefined after freeing so a second free is caught.",
							CWEID:         "CWE-415",
							OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
							Language:      rules.LangZig,
							Confidence:    "high",
							Tags:          []string{"memory-safety", "double-free", "undefined-behavior"},
						})
						// keep tracking (still freed)
					} else {
						freed[v] = ln.startOff
					}
				}
				continue // the free line itself is not a use-after-free
			}

			// Detect a use of a previously-freed (field-sensitive) expression.
			for v, freeOff := range freed {
				if ln.startOff <= freeOff {
					continue
				}
				// A bare reassignment `v = ...` whose RHS does not read v rebinds
				// the variable to a fresh value and ends the freed lifetime.
				if isRebindOf(text, v) {
					delete(freed, v)
					continue
				}
				if usesExpr(text, v) {
					absLine, col := lineColOf(c.masked, ln.startOff)
					c.findings = append(c.findings, rules.Finding{
						RuleID:        "BATOU-ZIG-AST-005",
						Severity:      rules.High,
						SeverityLabel: rules.High.String(),
						Title:         "Use-after-free: '" + v + "' used after free",
						Description:   "The externally-derived allocation '" + v + "' is freed (allocator.free/destroy) and then read or written later in the same function. Accessing freed memory is undefined behaviour and a common exploitation primitive.",
						FilePath:      c.filePath,
						LineNumber:    absLine,
						Column:        col,
						MatchedText:   excerpt(c.lines, absLine),
						Suggestion:    "Do not access an allocation after freeing it. Set the pointer to undefined/null after free, or restructure so the free happens at the end of the value's lifetime (defer allocator.free(x) at allocation site).",
						CWEID:         "CWE-416",
						OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
						Language:      rules.LangZig,
						Confidence:    "high",
						Tags:          []string{"memory-safety", "use-after-free", "undefined-behavior"},
					})
					delete(freed, v) // one report per freed expression
				}
			}
		}
	}
}

// ===========================================================================
// Structural helpers (lexical Zig parsing — no tree-sitter grammar available)
// ===========================================================================

// maskCommentsAndStrings replaces the inner bytes of // line comments and
// "..." / '...' literals with spaces, preserving newlines and overall length
// so byte offsets and line/column geometry stay identical to the original.
func maskCommentsAndStrings(src string) string {
	b := []byte(src)
	out := make([]byte, len(b))
	copy(out, b)
	i := 0
	n := len(b)
	for i < n {
		ch := b[i]
		switch {
		case ch == '/' && i+1 < n && b[i+1] == '/':
			// line comment until newline
			j := i
			for j < n && b[j] != '\n' {
				out[j] = ' '
				j++
			}
			i = j
		case ch == '"':
			out[i] = ' '
			j := i + 1
			for j < n && b[j] != '\n' {
				if b[j] == '\\' && j+1 < n {
					out[j] = ' '
					out[j+1] = ' '
					j += 2
					continue
				}
				if b[j] == '"' {
					out[j] = ' '
					j++
					break
				}
				out[j] = ' '
				j++
			}
			i = j
		case ch == '\'':
			out[i] = ' '
			j := i + 1
			for j < n && b[j] != '\n' {
				if b[j] == '\\' && j+1 < n {
					out[j] = ' '
					out[j+1] = ' '
					j += 2
					continue
				}
				if b[j] == '\'' {
					out[j] = ' '
					j++
					break
				}
				out[j] = ' '
				j++
			}
			i = j
		default:
			i++
		}
	}
	return string(out)
}

// findBuiltinCalls returns the byte offsets of each occurrence of `builtin`
// (e.g. "@ptrCast") that is immediately followed (modulo whitespace) by '('.
// The builtin must not be preceded by an identifier character so "@@x" or a
// longer builtin name doesn't false-match.
func findBuiltinCalls(masked, builtin string) []int {
	var offsets []int
	from := 0
	for {
		idx := strings.Index(masked[from:], builtin)
		if idx < 0 {
			break
		}
		abs := from + idx
		from = abs + len(builtin)
		// Ensure the char after the builtin is not an identifier char
		// (avoid @ptrCastFoo matching @ptrCast) — next non-space must be '('.
		j := abs + len(builtin)
		if j < len(masked) && isIdentByte(masked[j]) {
			continue
		}
		for j < len(masked) && (masked[j] == ' ' || masked[j] == '\t' || masked[j] == '\n' || masked[j] == '\r') {
			j++
		}
		if j < len(masked) && masked[j] == '(' {
			offsets = append(offsets, abs)
		}
	}
	return offsets
}

// extractCallArgs parses a balanced-parenthesis argument list that begins at or
// after `from` (the first '(' encountered). Returns top-level comma-separated
// argument strings (trimmed). ok=false if no balanced list is found.
func extractCallArgs(masked string, from int) ([]string, bool) {
	n := len(masked)
	i := from
	// Advance to the opening '(' of the call. Only whitespace is expected in
	// between; any other leading characters are skipped.
	for i < n && masked[i] != '(' {
		i++
	}
	if i >= n || masked[i] != '(' {
		return nil, false
	}
	depth := 0
	start := i + 1
	var args []string
	argStart := start
	for ; i < n; i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if masked[i] == ')' && depth == 0 {
				args = append(args, strings.TrimSpace(masked[argStart:i]))
				return cleanArgs(args), true
			}
		case ',':
			if depth == 1 {
				args = append(args, strings.TrimSpace(masked[argStart:i]))
				argStart = i + 1
			}
		}
	}
	return nil, false
}

func cleanArgs(args []string) []string {
	out := args[:0]
	for _, a := range args {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// ---- function-body extraction for the UAF pass ----

type bodyLine struct {
	text     string
	startOff int // masked offset of the line start
}

// funcBody is the per-function view used by the UAF pass; spans come from
// zigFunctionSpans and bodyLinesIn slices the body into offset-tagged lines.
type funcBody struct {
	lines []bodyLine
}

// indexFnKeyword finds the next `fn` token (word-boundaried) at or after `from`.
func indexFnKeyword(masked string, from int) int {
	off := from
	for {
		idx := strings.Index(masked[off:], "fn")
		if idx < 0 {
			return -1
		}
		abs := off + idx
		before := byte(' ')
		if abs > 0 {
			before = masked[abs-1]
		}
		after := byte(' ')
		if abs+2 < len(masked) {
			after = masked[abs+2]
		}
		if !isIdentByte(before) && !isIdentByte(after) {
			return abs
		}
		off = abs + 2
	}
}

func bodyLinesIn(masked string, start, end int) []bodyLine {
	var out []bodyLine
	lineStart := start
	for i := start; i < end; i++ {
		if masked[i] == '\n' {
			out = append(out, bodyLine{text: masked[lineStart:i], startOff: lineStart})
			lineStart = i + 1
		}
	}
	if lineStart < end {
		out = append(out, bodyLine{text: masked[lineStart:end], startOff: lineStart})
	}
	return out
}

// freedExpr detects an IMMEDIATE `<recv>.free(<v>)` or `<recv>.destroy(<v>)`
// and returns the FULL freed expression <v> (field-sensitive, e.g. "tree.source"
// or "entry.key_ptr.*"). A free guarded by `defer` / `errdefer` runs at scope
// exit, NOT at this line, so it is intentionally NOT treated as a free here —
// any subsequent use of the value before scope exit is well-defined. Treating
// a deferred free as immediate would false-positive on the canonical
// `const x = try alloc(...); defer alloc.free(x); ... use x ...` idiom.
//
// Capturing the full path (rather than just the root identifier) is what makes
// the UAF pass field-sensitive: freeing `tree.source` must not flag a later
// `tree.deinit()` (a sibling member), and freeing `entry.key_ptr.*` must not
// flag a later `entry.value_ptr` access.
func freedExpr(line string) (string, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "defer") || strings.HasPrefix(trimmed, "errdefer") {
		// Make sure it's the keyword, not an identifier like `deferred`.
		rest := trimmed[len("defer"):]
		if strings.HasPrefix(trimmed, "errdefer") {
			rest = trimmed[len("errdefer"):]
		}
		if rest == "" || !isIdentByte(rest[0]) {
			return "", false
		}
	}
	for _, kw := range []string{".free(", ".destroy("} {
		idx := strings.Index(line, kw)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(kw):]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			continue
		}
		arg := strings.TrimSpace(rest[:end])
		// Keep only the first comma-separated operand and its full member/deref
		// path (identifier, .field, .*, [..] suffixes).
		if comma := strings.IndexByte(arg, ','); comma >= 0 {
			arg = strings.TrimSpace(arg[:comma])
		}
		path := leadingPath(arg)
		if path != "" && isIdentByte(path[0]) {
			return path, true
		}
	}
	return "", false
}

// leadingPath returns the leading member/deref/index access path of s, e.g.
// "tree.source", "entry.key_ptr.*", "buf.items[0]". It stops at the first byte
// that is not part of an access chain.
func leadingPath(s string) string {
	s = strings.TrimSpace(s)
	end := 0
	depth := 0
	for end < len(s) {
		ch := s[end]
		switch {
		case isIdentByte(ch) || ch == '.' || ch == '*':
			end++
		case ch == '[':
			depth++
			end++
		case ch == ']':
			if depth == 0 {
				return s[:end]
			}
			depth--
			end++
		default:
			if depth > 0 {
				end++
				continue
			}
			return s[:end]
		}
	}
	return s[:end]
}

// usesExpr reports whether the field-sensitive freed path `expr` is read or
// written on `line`. It matches the full path (`tree.source`) at a token
// boundary, so a sibling access (`tree.deinit`) does NOT count as a use.
func usesExpr(line, expr string) bool {
	from := 0
	for {
		idx := strings.Index(line[from:], expr)
		if idx < 0 {
			return false
		}
		abs := from + idx
		from = abs + len(expr)
		before := byte(' ')
		if abs > 0 {
			before = line[abs-1]
		}
		after := byte(' ')
		if abs+len(expr) < len(line) {
			after = line[abs+len(expr)]
		}
		// `before` must not be an identifier byte or a `.` (so `self.x` doesn't
		// match a freed `x`). `after` must not extend the path into a different
		// member/identifier.
		if isIdentByte(before) || before == '.' {
			continue
		}
		if isIdentByte(after) || after == '.' {
			continue // freed `tree.source`; `tree.sourceMap` is a different member
		}
		return true
	}
}

// ---- small lexical utilities ----

func leadingIdent(s string) string {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && isIdentByte(s[end]) {
		end++
	}
	return s[:end]
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

func isIntLiteral(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// allow 0x / 0b / 0o prefixes and underscores in Zig integer literals
	body := s
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X' || s[1] == 'b' || s[1] == 'B' || s[1] == 'o' || s[1] == 'O') {
		body = s[2:]
		for i := 0; i < len(body); i++ {
			b := body[i]
			if b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
				continue
			}
			return false
		}
		return len(body) > 0
	}
	for i := 0; i < len(body); i++ {
		b := body[i]
		if b == '_' || (b >= '0' && b <= '9') {
			continue
		}
		return false
	}
	return true
}

func splitLinesKeepIndex(s string) []string {
	return strings.Split(s, "\n")
}

// lineColOf converts a byte offset in the masked source into 1-based line and
// column numbers.
func lineColOf(s string, off int) (int, int) {
	if off > len(s) {
		off = len(s)
	}
	line := 1
	col := 1
	for i := 0; i < off; i++ {
		if s[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// excerpt returns a trimmed one-line code excerpt for the given 1-based line.
func excerpt(lines []string, line int) string {
	if line-1 < 0 || line-1 >= len(lines) {
		return ""
	}
	s := strings.TrimSpace(lines[line-1])
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// ===========================================================================
// External-origin gating (taint provenance over the masked source)
// ===========================================================================
//
// The dangerous builtins this analyzer recognises are ubiquitous on safe,
// local/comptime data. To avoid the structural false-positive flood we emit a
// finding only when the relevant operand can be traced — by a bounded
// intra-function backward scan — to an EXTERNAL / untrusted source. The model
// below is deliberately conservative: when provenance cannot be established we
// stay silent. Recall on genuinely-external flows (parameters of handler-shaped
// functions, values read from network/file/stdin/argv) is preserved.

// isAddressOfLocal reports whether expr is `&<ident>` (optionally wrapped in
// @as(T, &ident)) where <ident> is a local declared (const/var) inside the
// function body. Such an operand is a stack address, not external bytes.
func (c *zigChecker) isAddressOfLocal(expr string, span *fnSpan) bool {
	amp := strings.IndexByte(expr, '&')
	if amp < 0 {
		return false
	}
	rest := strings.TrimLeft(expr[amp+1:], " \t")
	id := leadingIdent(rest)
	if id == "" {
		return false
	}
	// after the ident, the operand must end or be a member/paren close — a
	// `&buf[i]` index into a slice could still be external, so only treat a
	// whole-object address-of (`&buffer`, `&buffer)`) as local.
	after := strings.TrimLeft(rest[len(id):], " \t")
	if after != "" && after[0] != ')' && after[0] != ',' {
		return false
	}
	body := c.masked[span.bodyOpen+1 : span.end]
	// look for a `const id` / `var id` declaration of this identifier
	for _, kw := range []string{"const " + id, "var " + id} {
		idx := 0
		for {
			p := strings.Index(body[idx:], kw)
			if p < 0 {
				break
			}
			abs := p + idx
			// boundary check: char after kw must not extend the identifier
			tail := abs + len(kw)
			if tail < len(body) && isIdentByte(body[tail]) {
				idx = abs + len(kw)
				continue
			}
			return true
		}
	}
	return false
}

// fnSpan captures one `fn <header>( <params> ) <ret> { <body> }` region of the
// masked source: byte offsets for the whole span, its body, and the parsed
// header (signature) text used to classify parameters.
type fnSpan struct {
	start    int    // offset of the `fn` keyword
	bodyOpen int    // offset of the opening '{'
	end      int    // offset of the matching '}'
	header   string // masked text from `fn` up to (not including) the body '{'
}

// zigFunctionSpans extracts every `fn ... { ... }` region with brace matching.
func zigFunctionSpans(masked string) []fnSpan {
	var spans []fnSpan
	n := len(masked)
	i := 0
	for i < n {
		fnIdx := indexFnKeyword(masked, i)
		if fnIdx < 0 {
			break
		}
		brace := strings.IndexByte(masked[fnIdx:], '{')
		if brace < 0 {
			break
		}
		open := fnIdx + brace
		depth := 0
		end := -1
		for j := open; j < n; j++ {
			switch masked[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			break
		}
		spans = append(spans, fnSpan{
			start:    fnIdx,
			bodyOpen: open,
			end:      end,
			header:   masked[fnIdx:open],
		})
		i = end + 1
	}
	return spans
}

// enclosingFn returns the innermost function span containing the given offset.
func (c *zigChecker) enclosingFn(off int) *fnSpan {
	var best *fnSpan
	for i := range c.fnSpans {
		s := &c.fnSpans[i]
		if off >= s.bodyOpen && off <= s.end {
			if best == nil || s.start > best.start {
				best = s
			}
		}
	}
	return best
}

// declStartOff returns the offset of the start of the statement/line that
// contains off — the backward scan must only consider assignments STRICTLY
// before the current statement (so a var doesn't appear to derive from itself).
func (c *zigChecker) declStartOff(off int) int {
	nl := strings.LastIndexByte(c.masked[:off], '\n')
	if nl < 0 {
		return 0
	}
	return nl + 1
}

// zigExternalSourceRE matches call/expression shapes that introduce
// EXTERNAL / untrusted data into a Zig function: process arguments, environment,
// standard input, file/socket reads, and the std.http / std.net request types.
// These are the recognised "sources" of the taint model.
var zigExternalSourceRE = regexp.MustCompile(`(?:` +
	// process args / environment
	`\bargsAlloc\b|\bargsWithAllocator\b|\bprocess\.args\b|\bstd\.os\.argv\b|\bgetEnvVarOwned\b|\bgetenv\b|` +
	// standard input
	`\bgetStdIn\b|\bstdin\b|` +
	// generic reader / file / socket reads (the dominant external ingestion API)
	`\breadToEndAlloc\w*|\breadAllAlloc\w*|\breadAlloc\w*|` +
	`\.readAll\b|\.readAllArrayList\w*|\.readUntilDelimiter\w*|\.readBytesNoEof\b|\.readNoEof\b|` +
	`\.readBytes\b|\.streamUntilDelimiter\b|` +
	`\bposix\.read\b|\bos\.read\b|\bposix\.recv\w*|\bos\.recv\w*|\.recv\b|\.recvfrom\b|` +
	// std.http / std.net request & connection inputs
	`\bstd\.http\b|\bhttp\.Server\b|\brequest\.reader\b|\.readResponseBody\b|` +
	`\bstd\.net\.Stream\b|\bnet\.Stream\b|\bconnection\.stream\b|\.accept\b` +
	`)`)

// zigByteSliceParamRE matches a parameter declaration whose type is a byte
// slice / many-item byte pointer: `name: []u8`, `name: []const u8`,
// `name: [*]u8`, `name: [:0]const u8`, etc. These are the shapes through which
// untrusted bytes flow into a handler.
var zigByteSliceParamRE = regexp.MustCompile(`([A-Za-z_]\w*)\s*:\s*\[[^\]]*\]\s*(?:const\s+)?u8\b`)

// zigHandlerNameRE matches function names that, by convention, receive external
// input: HTTP/route/request handlers, parsers/decoders of raw bytes, callbacks
// that consume a payload/body/buffer, and main/entry points that take argv.
var zigHandlerNameRE = regexp.MustCompile(`(?i)\bfn\s+\w*(handle|handler|serve|route|onRequest|onMessage|onData|process|dispatch|parse|decode|deserialize|unmarshal|read|recv|ingest|fromBytes|main)\w*`)

// handlerByteParams returns the set of parameter identifiers of a span that are
// byte slices AND whose function is "handler-shaped" — i.e. the function name
// signals it consumes external input. A byte-slice parameter of an arbitrary
// internal library helper is NOT treated as external (that would re-flood).
func handlerByteParams(span *fnSpan) map[string]bool {
	out := map[string]bool{}
	// Restrict to the parameter list `( ... )` of the header.
	open := strings.IndexByte(span.header, '(')
	if open < 0 {
		return out
	}
	params := span.header[open:]
	if !zigHandlerNameRE.MatchString(span.header) {
		return out
	}
	for _, m := range zigByteSliceParamRE.FindAllStringSubmatch(params, -1) {
		out[m[1]] = true
	}
	return out
}

// operandIsExternal reports whether the operand expression `expr`, evaluated at
// statement offset declOff inside function span, traces to an external source.
// It walks the assignment chain backward (bounded to the function body) up to a
// small depth, following identifier -> last-assignment-RHS edges, and returns
// true as soon as it reaches a recognised external source or a handler byte
// parameter.
func (c *zigChecker) operandIsExternal(span *fnSpan, expr string, declOff int) bool {
	// Direct external-source shape in the operand expression itself
	// (e.g. `@ptrCast(try reader.readAllAlloc(...))`).
	if zigExternalSourceRE.MatchString(expr) {
		return true
	}
	// `&<local>` is the address of a stack object, not a reinterpret of an
	// external byte buffer. Taking the address of a freshly-declared local
	// (even one initialised from a parameter) is benign pointer marshalling
	// — the provenance hazard this analyzer targets is reinterpreting external
	// *bytes* (a slice / .ptr), not casting a struct pointer. Treat a bare
	// address-of-local operand as non-external.
	if c.isAddressOfLocal(expr, span) {
		return false
	}
	handlerParams := handlerByteParams(span)
	roots := rootIdents(expr)
	if len(roots) == 0 {
		return false
	}
	bodyStart := span.bodyOpen + 1
	visited := map[string]bool{}
	var trace func(id string, before int, depth int) bool
	trace = func(id string, before int, depth int) bool {
		if id == "" || depth > 6 || visited[id] {
			return false
		}
		visited[id] = true
		if handlerParams[id] {
			return true
		}
		// Out-parameter buffer pattern: `id` is passed AS THE DESTINATION of an
		// external read (`posix.read(fd, id)`, `recv(s, id)`, `readAll(id)`),
		// which fills it with untrusted bytes. This is an external origin even
		// though `id` was allocated internally.
		if c.bufferFilledByExternalRead(bodyStart, before, id) {
			return true
		}
		// Find the last assignment/decl of `id` strictly before `before`.
		rhs, rhsOff, found := lastAssignmentRHS(c.masked, bodyStart, before, id)
		if !found {
			return false
		}
		if zigExternalSourceRE.MatchString(rhs) {
			return true
		}
		for _, r := range rootIdents(rhs) {
			if trace(r, rhsOff, depth+1) {
				return true
			}
		}
		return false
	}
	for _, r := range roots {
		if trace(r, declOff, 0) {
			return true
		}
	}
	return false
}

// bufferFilledByExternalRead reports whether, within masked[bodyStart:before],
// `id` appears as an argument on a line that also calls an external-read source
// (e.g. `try posix.read(fd, id)` / `_ = recv(s, id)`). Such a call fills `id`
// with untrusted bytes, making it externally-derived even when allocated
// internally.
func (c *zigChecker) bufferFilledByExternalRead(bodyStart, before int, id string) bool {
	if before > len(c.masked) {
		before = len(c.masked)
	}
	region := c.masked[bodyStart:before]
	for _, ln := range strings.Split(region, "\n") {
		if !zigExternalSourceRE.MatchString(ln) {
			continue
		}
		for _, r := range rootIdents(ln) {
			if r == id {
				return true
			}
		}
	}
	return false
}

// lastAssignmentRHS finds, within masked[bodyStart:before], the LAST line that
// assigns or declares `id` (`const id = ...` / `var id = ...` / `id = ...` /
// `id: T = ...`), and returns the right-hand side, the offset of that line, and
// ok. Assignments to `id.field` / `id[..]` are ignored (they mutate, they don't
// re-bind the root's origin).
func lastAssignmentRHS(masked string, bodyStart, before int, id string) (string, int, bool) {
	if before > len(masked) {
		before = len(masked)
	}
	region := masked[bodyStart:before]
	bestRHS := ""
	bestOff := -1
	lineStart := 0
	for i := 0; i <= len(region); i++ {
		if i == len(region) || region[i] == '\n' {
			line := region[lineStart:i]
			if rhs, ok := assignmentRHS(line, id); ok {
				bestRHS = rhs
				bestOff = bodyStart + lineStart
			}
			lineStart = i + 1
		}
	}
	if bestOff < 0 {
		return "", 0, false
	}
	return bestRHS, bestOff, true
}

// assignmentRHS reports whether `line` binds `id` as a whole (not a field/index
// mutation) and returns the RHS expression after '='.
func assignmentRHS(line, id string) (string, bool) {
	t := strings.TrimSpace(line)
	// strip a leading const/var
	for _, kw := range []string{"const ", "var ", "comptime ", "pub "} {
		if strings.HasPrefix(t, kw) {
			t = strings.TrimSpace(t[len(kw):])
		}
	}
	if !strings.HasPrefix(t, id) {
		return "", false
	}
	rest := t[len(id):]
	if rest == "" {
		return "", false
	}
	// next char after the identifier must be a binding boundary, not an
	// identifier continuation (avoid `idx` matching `id`) and not `.`/`[`
	// (those are field/index mutations of an existing binding).
	switch rest[0] {
	case '.', '[':
		return "", false
	}
	if isIdentByte(rest[0]) {
		return "", false
	}
	// allow an optional `: Type` between the name and `=`
	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return "", false
	}
	// reject `==`, `>=`, `<=`, `!=` comparisons
	if eq+1 < len(rest) && rest[eq+1] == '=' {
		return "", false
	}
	if eq > 0 && (rest[eq-1] == '!' || rest[eq-1] == '<' || rest[eq-1] == '>' || rest[eq-1] == '=') {
		return "", false
	}
	return strings.TrimSpace(rest[eq+1:]), true
}

// rootIdents extracts the leading identifiers of each sub-expression in `expr`
// that could carry provenance: it splits on common operators/brackets and keeps
// the head identifier of each fragment (so `buf.ptr` -> `buf`, `data[0..n]` ->
// `data`, `n`). Builtin calls (`@...`) and pure literals are skipped.
func rootIdents(expr string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] || isZigKeyword(id) {
			return
		}
		// a pure number is not an identifier
		if isIntLiteral(id) {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	// Tokenise on non-identifier, non-dot bytes; keep dotted heads.
	i := 0
	n := len(expr)
	for i < n {
		ch := expr[i]
		if ch == '@' {
			// skip a builtin token entirely (it's not a data identifier)
			j := i + 1
			for j < n && isIdentByte(expr[j]) {
				j++
			}
			i = j
			continue
		}
		if isIdentByte(ch) {
			j := i
			for j < n && isIdentByte(expr[j]) {
				j++
			}
			tok := expr[i:j]
			// take only the head of a dotted chain a.b.c -> a
			add(tok)
			// skip any trailing `.field` / `[..]` chain of this root
			for j < n && (expr[j] == '.' || expr[j] == '[') {
				depth := 0
				for j < n {
					if expr[j] == '[' {
						depth++
					} else if expr[j] == ']' {
						depth--
						j++
						if depth <= 0 {
							break
						}
						continue
					} else if expr[j] == '.' && depth == 0 {
						j++
						for j < n && isIdentByte(expr[j]) {
							j++
						}
						break
					} else if depth == 0 && !isIdentByte(expr[j]) && expr[j] != '.' && expr[j] != '[' {
						break
					}
					j++
				}
			}
			i = j
			continue
		}
		i++
	}
	return out
}

func isZigKeyword(s string) bool {
	switch s {
	case "const", "var", "try", "comptime", "and", "or", "if", "else",
		"return", "while", "for", "switch", "orelse", "catch", "undefined",
		"null", "true", "false", "void", "anytype", "u8", "u16", "u32", "u64",
		"usize", "isize", "i8", "i16", "i32", "i64", "f32", "f64", "bool",
		"error", "anyerror", "noreturn", "pub", "fn", "align":
		return true
	}
	return false
}

// runtimeBoundExpr returns the runtime upper-bound expression of a @memcpy
// slice argument `expr[lo..hi]` (or the source slice identifier for an
// open-ended `expr[lo..]`), and whether a runtime bound is present. A purely
// comptime literal bound (buf[0..16]) yields has=false.
func runtimeBoundExpr(arg string) (string, bool) {
	open := strings.LastIndex(arg, "[")
	closeB := strings.LastIndex(arg, "]")
	if open < 0 || closeB < 0 || closeB < open {
		return "", false
	}
	inner := arg[open+1 : closeB]
	dots := strings.Index(inner, "..")
	if dots < 0 {
		return "", false
	}
	hi := strings.TrimSpace(inner[dots+2:])
	if hi == "" {
		// open-ended slice expr[lo..] — length derives from the base slice's
		// runtime .len; the provenance-bearing operand is the base expression.
		return strings.TrimSpace(arg[:open]), true
	}
	if isIntLiteral(hi) {
		return "", false
	}
	return hi, true
}

// memcpyDestBase returns the base expression of the @memcpy destination (first
// argument) — the identifier being written to, stripped of any `[..]` slice.
func memcpyDestBase(args []string) string {
	if len(args) == 0 {
		return ""
	}
	dst := strings.TrimSpace(args[0])
	if b := strings.IndexByte(dst, '['); b >= 0 {
		dst = dst[:b]
	}
	return leadingPath(strings.TrimSpace(dst))
}

// destIsFixedArray reports whether the destination base resolves, within the
// function, to a FIXED-SIZE array (`[N]u8`-style) rather than a caller-sized
// slice / many-item pointer. Writing past a fixed array with an external length
// is the genuinely-dangerous overflow shape; copying into a caller-provided
// slice param is the dominant safe idiom (the caller owns the bound) and is not
// structurally faultable, so it is excluded.
func (c *zigChecker) destIsFixedArray(span *fnSpan, base string, declOff int) bool {
	root := leadingIdent(base)
	if root == "" {
		return false
	}
	// A declaration `var <root>: [N]u8` / `const <root>: [N]u8 = ...` /
	// `var <root>: [N]u8 = undefined` inside the body marks a fixed array.
	bodyStart := span.bodyOpen + 1
	region := c.masked[bodyStart:min(declOff, len(c.masked))]
	// Scan declarations of root for a fixed-size array type annotation.
	for _, ln := range strings.Split(region, "\n") {
		t := strings.TrimSpace(ln)
		for _, kw := range []string{"const " + root, "var " + root} {
			if strings.HasPrefix(t, kw) {
				rest := t[len(kw):]
				if rest != "" && isIdentByte(rest[0]) {
					continue // longer identifier
				}
				if zigFixedArrayTypeRE.MatchString(rest) {
					return true
				}
			}
		}
	}
	return false
}

// zigFixedArrayTypeRE matches a fixed-size array type annotation tail such as
// `: [8]u8`, `: [modulus_len]u8`, `: [N:0]u8` — a bracketed length that is NOT a
// slice (`[]`) or many-item pointer (`[*]`).
var zigFixedArrayTypeRE = regexp.MustCompile(`:\s*\[[^\]\*][^\]]*\]`)

// lengthIsClamped reports whether the length expression (or, if it is an
// identifier, its last in-function assignment) is produced by an @min(...) /
// @memset bounds clamp — an explicit bounds check that makes the copy safe.
func (c *zigChecker) lengthIsClamped(span *fnSpan, lenExpr string, declOff int) bool {
	if strings.Contains(lenExpr, "@min(") {
		return true
	}
	root := leadingIdent(lenExpr)
	if root == "" || root != strings.TrimSpace(lenExpr) {
		// compound expression — only the bare-identifier case is traced
		return false
	}
	rhs, _, ok := lastAssignmentRHS(c.masked, span.bodyOpen+1, declOff, root)
	if !ok {
		return false
	}
	return strings.Contains(rhs, "@min(")
}

// lengthIsOffsetArithmetic reports whether the length expression is (or, if a
// bare identifier, resolves to) an additive/subtractive offset computation
// rather than a raw `.len` / parsed scalar. Such lengths are typically
// loop-remainder offsets bounded by an invariant we do not model.
func (c *zigChecker) lengthIsOffsetArithmetic(span *fnSpan, lenExpr string, declOff int) bool {
	if hasOffsetArithmetic(lenExpr) {
		return true
	}
	root := leadingIdent(lenExpr)
	if root == "" || root != strings.TrimSpace(lenExpr) {
		return false
	}
	rhs, _, ok := lastAssignmentRHS(c.masked, span.bodyOpen+1, declOff, root)
	if !ok {
		return false
	}
	return hasOffsetArithmetic(rhs)
}

// hasOffsetArithmetic reports whether s contains a top-level `+` or `-` binary
// operator (offset arithmetic). A leading unary minus or `..` range token is
// ignored. A bare `x.len` or identifier returns false.
func hasOffsetArithmetic(s string) bool {
	s = strings.TrimSpace(s)
	for i := 1; i < len(s)-0; i++ {
		ch := s[i]
		if ch == '+' || ch == '-' {
			// ignore `..` and `->`-like or `-%` wrapping handled the same way;
			// any '+'/'-' between operands signals offset arithmetic.
			prev := s[i-1]
			if prev == '.' || prev == '+' || prev == '-' {
				continue
			}
			return true
		}
	}
	return false
}

// isRebindOf reports whether `line` rebinds the whole identifier `v`
// (`v = ...` or `const/var v = ...`) WITHOUT reading v on the RHS. Such a line
// ends the freed value's lifetime and is not a use-after-free.
func isRebindOf(line, v string) bool {
	rhs, ok := assignmentRHS(line, v)
	if !ok {
		return false
	}
	// If the RHS itself reads v, it IS a use of the freed value.
	for _, r := range rootIdents(rhs) {
		if r == v {
			return false
		}
	}
	return true
}
