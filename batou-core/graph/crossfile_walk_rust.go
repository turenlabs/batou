// Rust cross-file interprocedural walker (PR-Grust).
//
// Like the JS / Lua / Ruby / Python equivalents, the Go-default
// AnalyzeCallerImpact in interprocedural.go scans the caller body with the
// Go sink regex table and Go arg parsing. Routing Rust through that path
// emits zero findings — Rust calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_lua.go (consumer entry) and
// crossfile_walk_javascript.go (tainted-return producer). It uses the Rust
// taint catalog (SinksForLanguage / SourcesForLanguage) to identify sinks
// inside callee bodies and tainted returns, and a coarse direct-source
// regex for typical axum / actix / std request shapes.
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Rust callee (in a
//     `mod`/`use`-linked file) that forwards it into a sink.
//   - Path B: callee returns tainted data and the caller passes the result
//     to a sink. Recognised when the callee has TaintedReturns set.
//     ensureRustCalleeReturns scans the callee body for both the explicit
//     `return <source>` form AND — THE ONE NON-MECHANICAL ADDITION — the
//     implicit Rust tail-expression return (the last non-`;` expression in
//     the body), so the canonical idiom
//         pub fn get_name() -> String { let v = std::env::var("X").unwrap(); v }
//     in a.rs, `let n = get_name(); Command::new(n);` in b.rs, fires
//     without planted test data.
//   - 1-hop interproc only.
//
// As with the Lua walker, the Rust walker IS allowed to populate a
// callee's TaintSig.SinkCalls / TaintedReturns on the fly when empty — the
// same-file PropagateInterproc path doesn't run Rust sink regex.
//
// Every helper here is reached only for rules.LangRust callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactRustCached
// solely from its `case rules.LangRust` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// rustSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadRustSinkPatterns
// interoperates with the shared walk core without conversion (the
// module/requireModule/dangerousArgs fields stay zero — Rust sink matching is
// method-name based).
type rustSinkPattern = crossfileSinkPattern

var (
	rustSinkPatternsCache   []rustSinkPattern
	rustSinkPatternsCacheMu sync.Mutex
)

// loadRustSinkPatterns compiles and caches the Rust taint sink catalog
// into regex form.
func loadRustSinkPatterns() []rustSinkPattern {
	rustSinkPatternsCacheMu.Lock()
	defer rustSinkPatternsCacheMu.Unlock()
	if rustSinkPatternsCache != nil {
		return rustSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangRust)
	out := make([]rustSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, rustSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	rustSinkPatternsCache = out
	return out
}

// rustSourceExprRe matches taint source expressions in a Rust arg / return
// position. Distilled from rust_sources.go — std env / stdin / fs, the
// axum / actix / tide / salvo request extractor shapes. Conservative: the
// two-sided gate (a match must reach a sink) suppresses standalone hits.
var rustSourceExprRe = regexp.MustCompile(
	`\benv::var\s*\(` +
		`|\bstd::env::var\s*\(` +
		`|\benv::args\s*\(|\bstd::env::args\s*\(` +
		`|\breq\.query\s*\(` +
		`|\breq\.cookie\s*\(` +
		`|\breq\.headers\s*\(` +
		`|\.param\s*\(` +
		`|\.header\s*\(` +
		`|\.body_string\s*\(` +
		`|\.body_json\s*\(` +
		`|\.query_string\s*\(` +
		`|\bstdin\s*\(` +
		`|fs::read(_to_string)?\s*\(` +
		`|web::Query|web::Json|web::Path|web::Form` +
		`|extract::Query|extract::Json|extract::Path|extract::Form` +
		`|\bJson\s*<|\bQuery\s*<|\bPath\s*<`,
)

// rustSanitizerRe matches common Rust sanitizer-call shapes for the
// cross-file pass. Distilled from rust_sanitizers.go. Kept narrow to avoid
// swallowing the canonical-fix path before the sink fires.
var rustSanitizerRe = regexp.MustCompile(
	`ammonia::clean` +
		`|html_escape::encode` +
		`|shell_escape::escape` +
		`|shlex::try_quote` +
		`|regex::escape` +
		`|urlencoding::encode` +
		`|\.canonicalize\s*\(` +
		`|\.parse\s*::\s*<\s*(?:i|u)\d` +
		`|HeaderValue::from_str`,
)

// AnalyzeCallerImpactRust mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Rust call expressions in the caller body and
// the Rust taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule
// IDs the Go / Python / JS / Ruby / Lua paths use.
func AnalyzeCallerImpactRust(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactRustCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactRustCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the Rust config (rustCrossfileWalkCfg) and the
// call-site finder. Path A folds into the shared core; Rust's Path B stays
// behind customPathB because it fires the inline and via-variable cases
// independently for one call site (the via-variable scan even INCLUDES the
// call line with a token-after-the-call gate) and carries linked-module
// wording the shared forward-scan doesn't reproduce.
func analyzeCallerImpactRustCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *rustCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		rustCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return rustCallSitesToShared(findRustCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// rustCallSitesToShared converts rustCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func rustCallSitesToShared(in []rustCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureRustCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls when
// it's empty. Idempotent.
func ensureRustCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangRust {
		return
	}
	if len(calleeNode.TaintSig.SinkCalls) > 0 {
		return
	}
	content, ok := loadCallerFile(cg, calleeNode.FilePath, map[string]string{})
	if !ok {
		return
	}
	body := extractFuncBody(content, calleeNode.StartLine, calleeNode.EndLine)
	if body == "" {
		return
	}
	sinks := scanRustBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findRustParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureRustCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for a tainted return.
// Idempotent.
func ensureRustCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangRust {
		return
	}
	if len(calleeNode.TaintSig.TaintedReturns) > 0 {
		return
	}
	content, ok := loadCallerFile(cg, calleeNode.FilePath, map[string]string{})
	if !ok {
		return
	}
	body := extractFuncBody(content, calleeNode.StartLine, calleeNode.EndLine)
	if body == "" {
		return
	}
	cat, found := scanRustBodyForTaintedReturn(body)
	if !found {
		return
	}
	if calleeNode.TaintSig.TaintedReturns == nil {
		calleeNode.TaintSig.TaintedReturns = make(map[int][]taint.SourceCategory)
	}
	calleeNode.TaintSig.TaintedReturns[0] = appendUniqueCat(calleeNode.TaintSig.TaintedReturns[0], cat)
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// rustReturnStmtRe captures the expression of an explicit `return <expr>`
// statement even when it does not start the line. Stops at `;` or `}`.
var rustReturnStmtRe = regexp.MustCompile(`\breturn\s+([^;}]+)`)

// scanRustBodyForTaintedReturn reports whether the body returns a catalog
// source expression. It handles BOTH:
//
//   - explicit `return <source>` / `return v` (where v was bound to a
//     source), and
//   - THE RUST TAIL EXPRESSION: a function returns the last non-`;`
//     expression in its block WITHOUT a `return` keyword. The probe's
//     `let v = std::env::var(...); v` ends with a bare `v` tail expr that
//     carries the source. A pure JS-style `return <src>` scan MISSES this,
//     so this is the one hand-written, non-mechanical addition for Rust.
//
// Returns the source category. Mirrors scanJavaScriptBodyForTaintedReturn
// for the explicit-return / intermediate-binding cases.
func scanRustBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `let v = source; ...
	// v` is recognised (both via explicit return and tail expr).
	taintedVars := map[string]bool{}
	// lastExpr is the most recent non-`;`, non-`{`/`}`, non-comment line —
	// the tail-expression candidate. In Rust the function's return value is
	// the final expression in the block when it has no trailing `;`.
	lastTailExpr := ""

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Record `let x = <source>` / bare `x = <source>` bindings.
		if eq := rustAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if rustSourceExprRe.MatchString(rhs) && !rustSanitizerRe.MatchString(rhs) {
				name := rustLastIdent(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}

		// Explicit `return <expr>` anywhere on the line.
		for _, m := range rustReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if rustSanitizerRe.MatchString(expr) {
				continue
			}
			if rustSourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			retVar := rustLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}

		// Track the tail-expression candidate: a line that does NOT end
		// with a `;` (and isn't a pure brace / attribute / control opener)
		// is a value expression that — if it's the last such line — is the
		// implicit return. We strip a leading binding keyword when present.
		if !strings.HasSuffix(trimmed, ";") {
			cand := strings.TrimSuffix(trimmed, "{")
			cand = strings.TrimSpace(cand)
			// Skip lone braces / block openers / common control keywords —
			// they aren't the tail VALUE.
			if cand != "" && cand != "}" && cand != "{" &&
				!strings.HasPrefix(cand, "}") &&
				!rustIsControlOpener(cand) {
				lastTailExpr = cand
			}
		} else {
			// A `;`-terminated statement clears any pending tail candidate
			// from a prior line — the tail must be the LAST expression.
			lastTailExpr = ""
		}
	}

	// Implicit tail-expression return.
	if lastTailExpr != "" {
		if rustSanitizerRe.MatchString(lastTailExpr) {
			return "", false
		}
		if rustSourceExprRe.MatchString(lastTailExpr) {
			return taint.SrcUserInput, true
		}
		tailVar := rustLastIdent(lastTailExpr)
		if tailVar != "" && taintedVars[tailVar] {
			return taint.SrcUserInput, true
		}
	}
	return "", false
}

// rustIsControlOpener reports whether a non-`;`-terminated line is a
// control-flow opener (if/for/while/match/loop/else/unsafe/fn/impl/...)
// rather than a tail value expression.
func rustIsControlOpener(s string) bool {
	for _, kw := range []string{
		"if ", "if(", "for ", "while ", "match ", "loop",
		"else", "unsafe", "fn ", "impl ", "mod ", "struct ",
		"enum ", "trait ", "let ", "use ", "#[", "//",
	} {
		if strings.HasPrefix(s, kw) {
			return true
		}
	}
	return false
}

// rustAssignEq returns the index of the single `=` assignment operator in
// a line, or -1 when the line isn't a plain assignment (skips ==, !=, <=,
// >=). Mirrors jsAssignEq.
func rustAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		if i > 0 {
			prev := line[i-1]
			if prev == '!' || prev == '<' || prev == '>' || prev == '=' {
				continue
			}
		}
		return i
	}
	return -1
}

// rustLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / return expression). Strips a leading
// `let ` / `let mut ` binding keyword. Mirrors jsLastIdent.
func rustLastIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "let mut ")
	s = strings.TrimPrefix(s, "let ")
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanRustBodyForSinks walks the body line-by-line with each cached
// rustSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanRustBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadRustSinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Same-line sanitizer suppression.
			if rustSanitizerRe.MatchString(line) && rustSinkLineSanitizerNeutralises(p.category) {
				continue
			}
			out = append(out, SinkRef{
				SinkCategory: p.category,
				MethodName:   p.method,
				Line:         startLine + i,
				ArgFromParam: -1,
			})
		}
	}
	return out
}

// rustSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func rustSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput,
		taint.SnkRedirect, taint.SnkTemplate, taint.SnkFileRead,
		taint.SnkFileWrite, taint.SnkURLFetch, taint.SnkHeader:
		return true
	}
	return false
}

// findRustParamFlowToSink returns the source-param index whose name appears
// in the sink line's argument expression, or -1 when none do.
func findRustParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
	if sig == nil || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return -1
	}
	sinkLine := lines[sinkLineIdx]
	if len(sig.SourceParams) > 0 {
		for paramIdx := range sig.SourceParams {
			name := paramNameFromSig(sig, paramIdx)
			if name == "" {
				continue
			}
			if containsToken(sinkLine, name) {
				return paramIdx
			}
		}
		return -1
	}
	for _, p := range sig.Params {
		if p.Name == "" {
			continue
		}
		if containsToken(sinkLine, p.Name) {
			return p.Index
		}
	}
	return -1
}

// checkRustCallerUsesTaintedReturn is the Rust analog of
// checkLuaCallerUsesTaintedReturn (Path B). Triggers when callee has
// TaintedReturns and the caller passes the result to a sink — either via
// an intermediate variable (`let n = get_name(); Command::new(n)`) or
// inlined directly (`Command::new(get_name())`).
func checkRustCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs rustCallSite,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
	sanGate *callerSanitizerGate,
) []rules.Finding {
	if len(calleeSig.TaintedReturns) == 0 {
		return nil
	}
	if isSanitizerByCalleeName(calleeNode.Name) || isSanitizerByCalleeName(callerNode.Name) {
		return nil
	}

	srcCatLabel := "tainted"
	srcCatJSON := string(taint.SrcExternal)
	for _, cats := range calleeSig.TaintedReturns {
		if len(cats) > 0 {
			srcCatLabel = string(cats[0])
			srcCatJSON = string(cats[0])
			break
		}
	}
	calleeBaseName := extractBaseName(calleeNode.Name)
	patterns := loadRustSinkPatterns()

	var findings []rules.Finding

	emit := func(sinkLineNum int, sinkMethod string, cat taint.SinkCategory, propLabel string) {
		sev := severityForSinkCategory[cat]
		if sev < rules.High {
			sev = rules.High
		}
		taintPath := []rules.TaintStep{
			{
				File:  calleeNode.FilePath,
				Line:  calleeNode.StartLine,
				Kind:  rules.TaintStepSource,
				Label: fmt.Sprintf("%s() returns %s data", calleeNode.Name, srcCatLabel),
			},
			{
				File:  callerNode.FilePath,
				Line:  callLineNum,
				Kind:  rules.TaintStepPropagation,
				Label: propLabel,
			},
			{
				File:  callerNode.FilePath,
				Line:  sinkLineNum,
				Kind:  rules.TaintStepSink,
				Label: sinkMethod,
			},
		}
		findings = append(findings, rules.Finding{
			RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(cat))),
			Severity:      sev,
			SeverityLabel: sev.String(),
			Title: fmt.Sprintf(
				"Interprocedural taint: %s data from %s() reaches %s",
				srcCatLabel, calleeNode.Name, sinkMethod,
			),
			Description: fmt.Sprintf(
				"Return value of %s() (called at %s:%d) carries %s taint from a linked module. "+
					"The caller %s() passes it to %s at line %d without sanitization, "+
					"creating a cross-file %s vulnerability.",
				calleeNode.Name, callerNode.FilePath, callLineNum,
				srcCatLabel, callerNode.Name, sinkMethod, sinkLineNum, cat,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: sinkLineNum,
			MatchedText: fmt.Sprintf(
				"%s() -> %s (line %d)",
				calleeNode.Name, sinkMethod, sinkLineNum,
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize the value returned by %s() (e.g. shell_escape::escape) before passing it to %s.",
				calleeNode.Name, sinkMethod,
			),
			CWEID:           cweForSinkCategory[cat],
			OWASPCategory:   owaspForSinkCategory[cat],
			Confidence:      "high",
			ConfidenceScore: 0.8,
			SourceCategory:  srcCatJSON,
			SinkCategory:    string(cat),
			Language:        calleeNode.Language,
			Tags: []string{
				"interprocedural", "taint-analysis", "cross-function",
				"return-taint", "rust", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call itself is an argument to a
	// sink on the SAME line (`Command::new(get_name())`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") {
			for _, p := range patterns {
				if !p.pattern.MatchString(line) {
					continue
				}
				// The callee call must be present on the line as an argument
				// (it is, by construction). Skip if the line sanitizes it.
				if rustSanitizerRe.MatchString(line) && rustSinkLineSanitizerNeutralises(p.category) {
					continue
				}
				// Avoid double-firing the same-line case when the call is
				// also assigned to a variable used by a sink on this very
				// line — that's the Case-2 path. Only treat as inline when
				// the call is NOT the assignment RHS, i.e. there's no
				// assignedTo, OR the sink and call share the line without an
				// intervening `=`.
				if cs.assignedTo != "" {
					// Defer to Case 2 (assignment path) to avoid duplicates.
					continue
				}
				emit(callLineNum, p.method, p.category,
					fmt.Sprintf("result of %s(...) passed inline to sink", calleeBaseName))
			}
		}
	}

	// Case 2: intermediate variable — `let n = get_name()` then a later
	// (or same) line uses n in a sink.
	returnVar := cs.assignedTo
	if returnVar != "" {
		for i := callLineIdx; i < len(callerLines); i++ {
			line := callerLines[i]
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// On the call line itself, the assignment `let n = get_name()`
			// also contains returnVar; require the sink usage to appear
			// strictly after the call expression so the LHS occurrence
			// isn't mistaken for sink consumption.
			if i == callLineIdx {
				callPos := strings.Index(line, calleeBaseName+"(")
				if callPos < 0 || !tokenAfter(line, returnVar, callPos) {
					continue
				}
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if rustSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
					sanitized = true
					break
				}
			}
			if sanitized {
				continue
			}

			for _, p := range patterns {
				if !p.pattern.MatchString(line) {
					continue
				}
				// Catalog-backed sanitizer gate: returnVar was rebound from a
				// catalog sanitizer neutralising this category before the sink
				// line (last-assignment-wins; the tainted call assignment
				// itself is a plain fact that revokes any earlier sanitize).
				if sanGate.argSanitized(returnVar, callerNode.StartLine+i, p.category) {
					continue
				}
				if rustSanitizerRe.MatchString(line) && rustSinkLineSanitizerNeutralises(p.category) {
					continue
				}
				sinkLineNum := callerNode.StartLine + i
				emit(sinkLineNum, p.method, p.category,
					fmt.Sprintf("result of %s(...) assigned to %s", calleeBaseName, returnVar))
			}
		}
	}

	return findings
}

// rustRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `[index]` / `(args)` / `::path` tail
// (`a::other` → "a", `req.query` → "req"). Also strips a `let`/`&`/`mut`
// prefix.
func rustRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	root = strings.TrimPrefix(root, "&mut ")
	root = strings.TrimPrefix(root, "&")
	root = strings.TrimPrefix(root, "mut ")
	root = strings.TrimSpace(root)
	if i := strings.IndexAny(root, ".[(:"); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
