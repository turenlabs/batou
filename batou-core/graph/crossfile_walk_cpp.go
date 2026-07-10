// C++ cross-file interprocedural walker (PR-Gcpp).
//
// Like the Swift / JS / Lua equivalents, the Go-default
// AnalyzeCallerImpact in interprocedural.go scans the caller body with
// the Go sink regex table and uses Go arg parsing. Routing C++ through
// that path emits zero findings — C++ calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_swift.go (consumer half) and
// crossfile_walk_javascript.go (tainted-return producer half). It uses
// the C++ taint catalog (SinksForLanguage) to identify sinks inside
// callee bodies and tainted returns, and a coarse direct-source regex for
// typical request shapes (`req.query(...)`, `getenv(...)`, `std::cin >>`,
// `scanf(...)`, ...).
//
// Cross-translation-unit resolution is driven by `#include "x.h"`:
// resolver_cpp.go resolves a header include to its sibling `.cpp`
// implementation file, so the canonical idiom —
//
//	// helper.h / helper.cpp
//	std::string getName(const Request& req){ return req.query("n"); }
//	// main.cpp
//	#include "helper.h"
//	void handler(const Request& req){
//	    std::string n = getName(req);
//	    std::system(n.c_str());
//	}
//
// fires BATOU-INTERPROC-COMMAND_EXEC (CWE-78) with a 2-file taint path.
// THE V1 MILESTONE is this Path B (tainted return) shape.
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a C++ callee (in an
//     included file) that forwards it into a sink.
//   - Path B: callee returns tainted data and the caller passes the
//     result to a sink. ensureCPPCalleeReturns scans the callee body for
//     `return <source-expr>` and populates TaintedReturns on the fly.
//   - 1-hop interproc only.
//
// Every helper here is reached only for C-family callees (rules.LangC and
// rules.LangCPP): the dispatcher in crossfile_walk.go routes to
// analyzeCallerImpactCPPCached from its `case rules.LangC, rules.LangCPP`
// arm and gates the ensure* helpers with isCPPFamily. Sink/source pattern
// loads are keyed on the callee's own language so a C callee uses c_sinks.go
// and a C++ callee uses cpp_sinks.go.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// cppSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so the C-family sink
// loader interoperates with the shared walk core without conversion (the
// module/requireModule/dangerousArgs fields stay zero — C/C++ sink matching is
// method-name based).
type cppSinkPattern = crossfileSinkPattern

var (
	cppSinkPatternsCache   = map[rules.Language][]cppSinkPattern{}
	cppSinkPatternsCacheMu sync.Mutex
)

// loadCPPSinkPatterns compiles and caches the C-family taint sink catalog
// for lang into regex form. C and C++ have distinct catalogs (c_sinks.go vs
// cpp_sinks.go), so the cache is keyed by language: a LangCPP callee loads
// the C++ sinks exactly as before (byte-identical), a LangC callee loads the
// C sinks. Any non-C-family lang falls back to the C++ catalog (defensive;
// the dispatcher only routes C-family callees here).
func loadCPPSinkPatterns(lang rules.Language) []cppSinkPattern {
	if lang != rules.LangC && lang != rules.LangCPP {
		lang = rules.LangCPP
	}
	cppSinkPatternsCacheMu.Lock()
	defer cppSinkPatternsCacheMu.Unlock()
	if cached, ok := cppSinkPatternsCache[lang]; ok {
		return cached
	}
	sinks := taint.SinksForLanguage(lang)
	out := make([]cppSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, cppSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	cppSinkPatternsCache[lang] = out
	return out
}

// cppSourceExprRe matches taint source expressions in a C++ arg position.
// Distilled from cpp_sources.go — generic HTTP request shapes plus the
// C-inherited stdin / env / network sources. Conservative: only the
// high-signal attacker-controlled accessors so a standalone match in a
// non-source context does not flood (the two-sided sink gate suppresses
// spurious pairs regardless).
var cppSourceExprRe = regexp.MustCompile(
	`\b(?:req|request)\.query\s*\(` +
		`|\b(?:req|request)\.(?:body|url|get_param_value|get_header_value|url_params)\b` +
		`|req->(?:getParameter|getBody|getCookie|getHeader|query)\s*\(` +
		`|\.url_params\.get\s*\(` +
		`|std::cin\s*>>` +
		`|std::getline\s*\(` +
		`|\bgetenv\s*\(` +
		`|\bscanf\s*\(` +
		`|\bgets\s*\(` +
		`|\bfgets\s*\(` +
		`|\brecv(?:from|msg)?\s*\(` +
		`|\bargv\s*\[`,
)

// cppSanitizerRe matches common C++ sanitizer-call shapes for the cross-
// file pass. Distilled from cpp_sanitizers.go. Kept narrow to avoid
// swallowing the canonical-fix path before the sink fires: numeric-string
// conversions (std::stoi/stol/...) neutralise SQL/command/path taint;
// sqlite3_bind_*/mysql_stmt_bind_param is parameterized-query binding;
// the html-escape family covers XSS escaping; bounded string copies
// (strncpy/snprintf/strlcpy) cap path/command taint.
var cppSanitizerRe = regexp.MustCompile(
	`\bstd::sto[ilfdu]\w*\s*\(` +
		`|\bsqlite3_bind_(?:text|int|int64|double|blob)\s*\(` +
		`|\bmysql_stmt_bind_param\s*\(` +
		`|\bsqlite3_mprintf\s*\(` +
		`|(?:html_escape|htmlEncode|escapeHtml|escape_html)\s*\(` +
		`|\bstrncpy\s*\(` +
		`|\bstrlcpy\s*\(` +
		`|\bsnprintf\s*\(` +
		`|\bstrtol\s*\(|\bstrtoul\s*\(|\bstrtoll\s*\(` +
		`|\.find\s*\(` +
		`|\bbasename\s*\(`,
)

// AnalyzeCallerImpactCPP mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find C++ call expressions in the caller body and
// the C++ taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule
// IDs the Go / Python / JS / Swift paths use.
func AnalyzeCallerImpactCPP(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactCPPCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactCPPCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the C-family config (cppCrossfileWalkCfg) and the
// call-site finder. The config serves BOTH rules.LangC and rules.LangCPP: the
// ensure* helpers gate on isCPPFamily and the customPathB loads the sink
// catalog keyed on the callee's own language. Path A folds into the shared
// core; C/C++'s Path B stays behind customPathB because it fires the inline
// and via-variable cases independently and carries translation-unit-specific
// wording the shared forward-scan doesn't reproduce.
func analyzeCallerImpactCPPCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *cppCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		cppCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return cppCallSitesToShared(findCPPCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// cppCallSitesToShared converts cppCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func cppCallSitesToShared(in []cppCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureCPPCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls when
// it's empty. Idempotent.
func ensureCPPCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || !isCPPFamily(calleeNode.Language) {
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
	sinks := scanCPPBodyForSinks(body, calleeNode.StartLine, calleeNode.Language)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findCPPParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureCPPCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>`.
// This handles the canonical header/impl getter idiom where a helper
// returns request-derived data. Idempotent.
func ensureCPPCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || !isCPPFamily(calleeNode.Language) {
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
	cat, found := scanCPPBodyForTaintedReturn(body)
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

// scanCPPBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return req.query("n")`,
// or `auto v = req.query("n"); ... return v`). Returns the source category.
func scanCPPBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Record `T x = <source>` / `x = <source>` bindings.
		if eq := cppAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if cppSourceExprRe.MatchString(rhs) && !cppSanitizerRe.MatchString(rhs) {
				name := cppBindingName(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// Match `return <expr>` anywhere on the line — C++ commonly keeps a
		// single-line body on the same line as the declaration.
		for _, m := range cppReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if cppSanitizerRe.MatchString(expr) {
				continue
			}
			if cppSourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			retVar := cppLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}
	}
	return "", false
}

// cppReturnStmtRe captures the expression of a `return <expr>;` statement
// even when it does not start the line — the compact C++ idiom
// `std::string getName(const Request& req){ return req.query("n"); }`
// keeps the body on the same line as the declaration. The capture group
// stops at `;` or `}` so the trailing punctuation isn't swept in.
var cppReturnStmtRe = regexp.MustCompile(`\breturn\s+([^;}]+)`)

// cppAssignEq returns the index of the single `=` assignment operator in a
// line, or -1 when the line isn't a plain assignment (skips ==, !=, <=,
// >=, +=, -=, *=, /=, %=, &=, |=, ^=).
func cppAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, ===.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		// Skip !=, <=, >=, and the compound-assignment operators.
		if i > 0 {
			switch line[i-1] {
			case '!', '<', '>', '=', '+', '-', '*', '/', '%', '&', '|', '^', '~':
				continue
			}
		}
		return i
	}
	return -1
}

// cppBindingName returns the bound variable name from a declaration LHS
// that may carry a type / qualifiers (`std::string n` → "n", `auto x` →
// "x", `const char* p` → "p").
func cppBindingName(lhs string) string {
	return cppLastIdent(lhs)
}

// scanCPPBodyForSinks walks the body line-by-line with each cached
// cppSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanCPPBodyForSinks(body string, startLine int, lang rules.Language) []SinkRef {
	patterns := loadCPPSinkPatterns(lang)
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
			// Same-line sanitizer suppression: a SQL/command/path sink whose
			// argument is wrapped in a numeric conversion / parameterized
			// binding is safe.
			if cppSanitizerRe.MatchString(line) && cppSinkLineSanitizerNeutralises(p.category) {
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

// cppSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func cppSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput,
		taint.SnkRedirect, taint.SnkTemplate, taint.SnkFileRead,
		taint.SnkFileWrite, taint.SnkURLFetch:
		return true
	}
	return false
}

// findCPPParamFlowToSink returns the source-param index whose name appears
// in the sink line's argument expression, or -1 when none do.
func findCPPParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkCPPCallerUsesTaintedReturn is the C++ analog of
// checkSwiftCallerUsesTaintedReturn (Path B). Triggers when the callee has
// TaintedReturns and the caller passes the result to a sink — either via
// an intermediate variable (`auto x = getName(req); system(x.c_str())`) or
// inlined directly (`system(getName(req).c_str())`).
func checkCPPCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs cppCallSite,
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
	patterns := loadCPPSinkPatterns(calleeNode.Language)

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
				"Return value of %s() (called at %s:%d) carries %s taint from another translation unit. "+
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
				"Sanitize the value returned by %s() (e.g. validate / coerce it or use a parameterized API) before passing it to %s.",
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
				"return-taint", "cpp", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call itself is an argument to a
	// sink on the SAME line (`system(getName(req).c_str())`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if cppSanitizerRe.MatchString(line) && cppSinkLineSanitizerNeutralises(p.category) {
				continue
			}
			emit(callLineNum, p.method, p.category,
				fmt.Sprintf("result of %s(...) passed inline to sink", calleeBaseName))
		}
	}

	// Case 2: intermediate variable — `auto x = getName(req)` then a later
	// line uses x in a sink.
	returnVar := cs.assignedTo
	if returnVar != "" {
		for i := callLineIdx + 1; i < len(callerLines); i++ {
			line := callerLines[i]
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if cppSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
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
				if cppSanitizerRe.MatchString(line) && cppSinkLineSanitizerNeutralises(p.category) {
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

// cppRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `->field` / `[index]` / `(args)` / `::scope` tail
// (`req.query` → "req", `n.c_str()` → "n").
func cppRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	// Strip a leading address-of / dereference.
	root = strings.TrimLeft(root, "&*")
	if i := strings.IndexAny(root, ".[(-:!<>+ "); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
