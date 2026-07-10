// Lua cross-file interprocedural walker (PR-Glua).
//
// Like the JS / Ruby / Python equivalents, the Go-default
// AnalyzeCallerImpact in interprocedural.go scans the caller body with
// the Go sink regex table and uses Go arg parsing. Routing Lua through
// that path emits zero findings — Lua calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_ruby.go. It uses the Lua taint catalog
// (SinksForLanguage / SourcesForLanguage) to identify sinks inside callee
// bodies and tainted returns, and a coarse direct-source regex for typical
// OpenResty / LuaSQL request shapes (`ngx.var.*`, `ngx.req.get_*`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Lua callee (in a
//     required module) that forwards it into a sink. Direct source
//     expressions in the call site (`ngx.var.arg_id`, `ngx.req.get_uri_
//     args()`, ...) are recognised.
//   - Path B: callee (in a required module) returns tainted data and the
//     caller passes the result to a sink. Recognised when the callee has
//     TaintedReturns set. ensureLuaCalleeReturns scans the callee body for
//     `return <source-expr>` and populates TaintedReturns on the fly, so
//     the canonical OpenResty idiom — `function M.get_id() return
//     ngx.var.arg_id end` in mod.lua, `db:query(m.get_id())` in app.lua —
//     fires without planted test data.
//   - 1-hop interproc only.
//
// As with the Ruby walker, the Lua walker IS allowed to populate a
// callee's TaintSig.SinkCalls / TaintedReturns on the fly when empty —
// the same-file PropagateInterproc path doesn't run Lua sink regex.
//
// Every helper here is reached only for rules.LangLua callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactLuaCached
// solely from its `case rules.LangLua` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// luaSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadLuaSinkPatterns
// interoperates with the shared walk core without conversion (the
// module/requireModule/dangerousArgs fields stay zero — Lua sink matching
// is method-name based).
type luaSinkPattern = crossfileSinkPattern

var (
	luaSinkPatternsCache   []luaSinkPattern
	luaSinkPatternsCacheMu sync.Mutex
)

// loadLuaSinkPatterns compiles and caches the Lua taint sink catalog into
// regex form.
func loadLuaSinkPatterns() []luaSinkPattern {
	luaSinkPatternsCacheMu.Lock()
	defer luaSinkPatternsCacheMu.Unlock()
	if luaSinkPatternsCache != nil {
		return luaSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangLua)
	out := make([]luaSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, luaSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	luaSinkPatternsCache = out
	return out
}

// luaSourceExprRe matches taint source expressions in a Lua arg position.
// Conservative — OpenResty / ngx_lua request shapes plus standard input.
var luaSourceExprRe = regexp.MustCompile(
	`\bngx\.var\.\w+` +
		`|\bngx\.req\.get_uri_args\s*\(` +
		`|\bngx\.req\.get_post_args\s*\(` +
		`|\bngx\.req\.get_body_data\s*\(` +
		`|\bngx\.req\.get_headers\s*\(` +
		`|\bngx\.req\.raw_header\s*\(` +
		`|\bngx\.req\.get_method\s*\(` +
		`|\bio\.read\s*\(` +
		`|\barg\s*\[`,
)

// luaSanitizerRe matches common Lua sanitizer-call shapes for the
// cross-file pass. Kept narrow to avoid swallowing the canonical-fix path
// before the sink fires. ngx.quote_sql_str is the OpenResty SQL escaper;
// ngx.escape_uri / ngx.encode_args cover URL encoding; tonumber coerces a
// value to a number (kills SQLi/path taint when the result is used).
var luaSanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`ngx\.quote_sql_str` +
		`|ngx\.escape_uri` +
		`|ngx\.encode_args` +
		`|ngx\.unescape_uri` +
		`|tonumber` +
		`|tostring` +
		`)\s*\(`,
)

// AnalyzeCallerImpactLua mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Lua call expressions in the caller body and
// the Lua taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule
// IDs the Go / Python / JS / Ruby paths use.
func AnalyzeCallerImpactLua(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactLuaCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactLuaCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core
// (crossfile_walk_core.go); this wrapper supplies the Lua config
// (luaCrossfileWalkCfg) and the call-site finder. Lua's Path B stays behind
// the config's customPathB hook (checkLuaCallerUsesTaintedReturn) because it
// diverges from the shared forward-scan shape.
func analyzeCallerImpactLuaCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *luaCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		luaCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return luaCallSitesToShared(findLuaCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// luaCallSitesToShared converts luaCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func luaCallSitesToShared(in []luaCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureLuaCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls when
// it's empty. Idempotent.
func ensureLuaCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangLua {
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
	sinks := scanLuaBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findLuaParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureLuaCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>`.
// This handles the canonical OpenResty module idiom where a required
// module exposes a getter returning request-derived data. Idempotent.
func ensureLuaCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangLua {
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
	cat, found := scanLuaBodyForTaintedReturn(body)
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

// scanLuaBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return ngx.var.arg_id`,
// or `local v = ngx.var.x ... return v`). Returns the source category.
func scanLuaBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables assigned a source expression so `local v = source;
	// return v` is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		// Record `local x = <source>` / `x = <source>` bindings.
		if eq := luaAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if luaSourceExprRe.MatchString(rhs) && !luaSanitizerRe.MatchString(rhs) {
				name := luaLastIdent(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		if !strings.HasPrefix(trimmed, "return") {
			continue
		}
		expr := strings.TrimSpace(strings.TrimPrefix(trimmed, "return"))
		if expr == "" {
			continue
		}
		if luaSanitizerRe.MatchString(expr) {
			continue
		}
		if luaSourceExprRe.MatchString(expr) {
			return taint.SrcUserInput, true
		}
		// `return v` where v was assigned a source above.
		retVar := luaLastIdent(expr)
		if retVar != "" && taintedVars[retVar] {
			return taint.SrcUserInput, true
		}
	}
	return "", false
}

// luaAssignEq returns the index of the single `=` assignment operator in
// a line, or -1 when the line isn't a plain assignment (skips ==, <=, >=,
// ~=, and the `==` comparison).
func luaAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, ~=, <=, >=.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		if i > 0 {
			prev := line[i-1]
			if prev == '=' || prev == '~' || prev == '<' || prev == '>' {
				continue
			}
		}
		return i
	}
	return -1
}

// luaLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / return expression).
func luaLastIdent(s string) string {
	s = strings.TrimSpace(s)
	// Strip a leading `local ` keyword.
	s = strings.TrimPrefix(s, "local ")
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanLuaBodyForSinks walks the body line-by-line with each cached
// luaSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanLuaBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadLuaSinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Same-line sanitizer suppression: a SQL sink whose argument is
			// wrapped in ngx.quote_sql_str (or numeric coercion) is safe.
			if luaSanitizerRe.MatchString(line) && luaSinkLineSanitizerNeutralises(p.category) {
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

// luaSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func luaSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkRedirect,
		taint.SnkTemplate, taint.SnkFileRead, taint.SnkFileWrite:
		return true
	}
	return false
}

// findLuaParamFlowToSink returns the source-param index whose name appears
// in the sink line's argument expression, or -1 when none do.
func findLuaParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkLuaCallerUsesTaintedReturn is the Lua analog of
// checkRubyCallerUsesTaintedReturn (Path B). Triggers when callee has
// TaintedReturns and the caller passes the result to a sink — either via
// an intermediate variable (`local x = m.get_id(); db:query(x)`) or
// inlined directly (`db:query(m.get_id())`).
func checkLuaCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs luaCallSite,
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
	patterns := loadLuaSinkPatterns()

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
				"Return value of %s() (called at %s:%d) carries %s taint from a required module. "+
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
				"Sanitize the value returned by %s() (e.g. ngx.quote_sql_str) before passing it to %s.",
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
				"return-taint", "lua", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call itself is an argument to a
	// sink on the SAME line (`db:query(m.get_id())`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// The callee call must appear as an argument (it's on this
			// line by construction). Skip if the line sanitizes it.
			if luaSanitizerRe.MatchString(line) && luaSinkLineSanitizerNeutralises(p.category) {
				continue
			}
			emit(callLineNum, p.method, p.category,
				fmt.Sprintf("result of %s(...) passed inline to sink", calleeBaseName))
		}
	}

	// Case 2: intermediate variable — `local x = m.get_id()` then a later
	// line uses x in a sink.
	returnVar := cs.assignedTo
	if returnVar != "" {
		for i := callLineIdx + 1; i < len(callerLines); i++ {
			line := callerLines[i]
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "--") {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if luaSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
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
				if luaSanitizerRe.MatchString(line) && luaSinkLineSanitizerNeutralises(p.category) {
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

// luaRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `[index]` / `(args)` tail (`m.get_id` → "m").
func luaRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	if i := strings.IndexAny(root, ".[(:"); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
