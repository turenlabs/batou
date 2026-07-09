// PHP cross-file interprocedural walker (PR-Gphp).
//
// Like the JS / Python / Ruby equivalents, the Go-default
// AnalyzeCallerImpact in interprocedural.go scans the caller body with
// the Go sink regex table and uses Go arg parsing. Routing PHP through
// that path emits zero findings — PHP calls never match Go sink shapes,
// so every cross-file (caller, callee) pair is fast-skipped with
// callee-sink=0.
//
// This file mirrors crossfile_walk_ruby.go (PHP `$obj->method()` is
// structurally like Ruby `obj.method`). It uses the per-pass call-site
// index (crossfile_walk_php_index.go) to find call expressions in the
// caller, the PHP taint catalog (SinksForLanguage / SourcesForLanguage)
// to identify sinks inside callee bodies, and a coarse direct-source
// regex for the canonical PHP superglobal request shapes (`$_GET[`,
// `$_POST[`, `php://input`, `getallheaders()`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a PHP callee that
//     forwards it into a sink. Direct source expressions at the call site
//     (`$_GET['n']`) and backward-traced local assignments
//     (`$n = $_GET['n']; Repo::find($n);`) are recognised.
//   - Path B: callee returns tainted data and the caller passes the
//     result to a sink (`$x = Helper::raw(); echo $x;`). Recognised when
//     ensurePHPCalleeReturns tags TaintedReturns from a `return <source>`
//     statement in the callee body.
//   - 1-hop interproc only — multi-module relays compose through the
//     transitive RETURN machinery, not here.
//
// As with the Ruby / Lua walkers, the PHP walker IS allowed to populate a
// callee's TaintSig.SinkCalls / TaintedReturns on the fly when empty. The
// same-file PropagateInterproc path doesn't run PHP sink regex either, so
// most PHP callees arrive at the cross-file walk with SinkCalls == nil.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// phpSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadPHPSinkPatterns
// and its stored-state consumer (loadPHPStoredStateSinks) interoperate with
// the shared walk core without conversion (the module/requireModule/
// dangerousArgs fields stay zero — PHP sink matching is method-name based).
type phpSinkPattern = crossfileSinkPattern

var (
	phpSinkPatternsCache   []phpSinkPattern
	phpSinkPatternsCacheMu sync.Mutex
)

// loadPHPSinkPatterns compiles and caches the PHP taint sink catalog into
// regex form. Returns the cached slice on second+ calls.
func loadPHPSinkPatterns() []phpSinkPattern {
	phpSinkPatternsCacheMu.Lock()
	defer phpSinkPatternsCacheMu.Unlock()
	if phpSinkPatternsCache != nil {
		return phpSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangPHP)
	out := make([]phpSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, phpSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	phpSinkPatternsCache = out
	return out
}

// phpSourceExprRe matches taint source expressions in a PHP arg position.
// Conservative — the canonical PHP superglobal request reads plus the raw
// input stream and the header helpers. Mirrors rubySourceExprRe. (The
// authoritative source list lives in the php_sources.go catalog; this is
// a coarse net for the cross-file arg/return check.)
var phpSourceExprRe = regexp.MustCompile(
	`\$_GET\s*\[` +
		`|\$_POST\s*\[` +
		`|\$_REQUEST\s*\[` +
		`|\$_COOKIE\s*\[` +
		`|\$_FILES\s*\[` +
		`|\$_SERVER\s*\[\s*['"]HTTP_` +
		`|\$_SERVER\s*\[\s*['"]REQUEST_URI['"]` +
		`|\$_SERVER\s*\[\s*['"]QUERY_STRING['"]` +
		`|\$_SERVER\s*\[\s*['"]PATH_INFO['"]` +
		`|\$_SERVER\s*\[\s*['"]PHP_SELF['"]` +
		`|php://input` +
		`|\bgetallheaders\s*\(` +
		`|\bapache_request_headers\s*\(`,
)

// phpSanitizerRe matches common PHP sanitizer-call shapes for the
// cross-file pass. Kept narrow to avoid swallowing the canonical-fix path
// before the sink fires. The per-file tsflow walker remains the source of
// truth — this is only consulted when gating a coarse cross-file flow.
// (The authoritative sanitizer list lives in php_sanitizers.go.)
var phpSanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`htmlspecialchars` +
		`|htmlentities` +
		`|strip_tags` +
		`|escapeshellarg` +
		`|escapeshellcmd` +
		`|intval` +
		`|floatval` +
		`|mysqli_real_escape_string` +
		`|urlencode` +
		`|rawurlencode` +
		`|filter_var` +
		`|filter_input` +
		// WordPress / framework helpers
		`|wp_kses(?:_post)?` +
		`|esc_html` +
		`|esc_attr` +
		`|esc_url` +
		`|esc_sql` +
		`|esc_js` +
		`|sanitize_text_field` +
		`|sanitize_email` +
		`|sanitize_key` +
		`|absint` +
		`)\s*\(` +
		// PDO / mysqli parameterization and casts (not call-shaped above).
		`|\(int\)` +
		`|\(float\)` +
		`|->prepare\s*\(` +
		`|->quote\s*\(` +
		`|->esc_like\s*\(`,
)

// phpBaseName returns the bare method name for a PHP callee. Unlike the
// shared extractBaseName (which only strips on `.`), PHP method nodes are
// named `Cls::method` (scoped) or `recv.method` (member). This strips
// both the `Cls::` scope prefix AND any namespace-qualified `\` so a
// callee registered as `App\Repo::find` matches the call-index basename
// `find`.
func phpBaseName(name string) string {
	if i := strings.LastIndex(name, "::"); i >= 0 {
		name = name[i+2:]
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return strings.TrimSpace(name)
}

// AnalyzeCallerImpactPHP mirrors AnalyzeCallerImpact (Go-specific) but
// uses the PHP call-site index to find PHP call expressions in the caller
// body and the PHP taint catalog to identify sinks / tainted returns
// inside the callee. Returns findings keyed by the same
// BATOU-INTERPROC-<CAT> rule IDs the Go / Python / JS / Ruby paths use.
func AnalyzeCallerImpactPHP(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactPHPCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactPHPCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core
// (crossfile_walk_core.go); this wrapper supplies the PHP config
// (phpCrossfileWalkCfg) and the call-site finder. PHP's Path B stays behind
// the config's customPathB hook (checkPHPCallerUsesTaintedReturn) because it
// applies a sink-line sanitizer gate and `$`-decorates the return variable.
func analyzeCallerImpactPHPCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *phpCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		phpCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return phpCallSitesToShared(findPHPCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// phpCallSitesToShared converts phpCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func phpCallSitesToShared(in []phpCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensurePHPCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls when
// it's empty. Idempotent — skips work when already populated.
func ensurePHPCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangPHP {
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
	sinks := scanPHPBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findPHPParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensurePHPCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>` or
// `$v = <source>; ... return $v`. Handles the common DAO idiom where a
// helper returns request-derived data. Idempotent.
func ensurePHPCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangPHP {
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
	cat, found := scanPHPBodyForTaintedReturn(body)
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

// scanPHPBodyForSinks walks the body line-by-line with each cached
// phpSinkPattern. Returns SinkRef rows with file-absolute line numbers.
// Multiple distinct sinks on the same line each produce their own row.
func scanPHPBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadPHPSinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		if phpIsCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Inline sanitizer suppression for output / redirect categories.
			if phpSanitizerRe.MatchString(line) && phpSinkLineSanitizerNeutralises(p.category) {
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

// scanPHPBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return $_GET['id']`, or
// `$v = $_GET['x']; ... return $v`). Returns the source category.
func scanPHPBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if phpIsCommentLine(line) {
			continue
		}
		// Record `$x = <source>` bindings.
		if eq := phpAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if phpSourceExprRe.MatchString(rhs) && !phpSanitizerRe.MatchString(rhs) {
				name := phpStripSigil(phpLastIdent(lhs))
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		if !strings.HasPrefix(trimmed, "return") {
			continue
		}
		expr := strings.TrimSpace(strings.TrimPrefix(trimmed, "return"))
		expr = strings.TrimSuffix(strings.TrimSpace(expr), ";")
		if expr == "" {
			continue
		}
		if phpSanitizerRe.MatchString(expr) {
			continue
		}
		if phpSourceExprRe.MatchString(expr) {
			return taint.SrcUserInput, true
		}
		retVar := phpStripSigil(phpLastIdent(expr))
		if retVar != "" && taintedVars[retVar] {
			return taint.SrcUserInput, true
		}
	}
	return "", false
}

// phpIsCommentLine reports whether a body line is a PHP comment-only line
// (`//`, `#`, or `*`/`/*` block continuation). Used to skip commented
// dangerous calls.
func phpIsCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") ||
		strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "*") ||
		strings.HasPrefix(t, "/*")
}

// phpAssignEq returns the index of the single `=` assignment operator in a
// line, or -1 when the line isn't a plain assignment (skips ==, ===, <=,
// >=, !=, and the `=>` array arrow).
func phpAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, ===, <=, >=, !=.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		// Skip `=>` array arrow.
		if i+1 < len(line) && line[i+1] == '>' {
			continue
		}
		if i > 0 {
			prev := line[i-1]
			if prev == '=' || prev == '!' || prev == '<' || prev == '>' ||
				prev == '+' || prev == '-' || prev == '*' || prev == '/' ||
				prev == '.' || prev == '%' || prev == '&' || prev == '|' {
				continue
			}
		}
		return i
	}
	return -1
}

// phpLastIdent returns the last identifier-ish token in s (variable or
// name). Used to extract the bound variable from an assignment LHS or the
// returned variable from a `return $v` expression.
func phpLastIdent(s string) string {
	s = strings.TrimSpace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && r != '$' && (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// phpStripSigil removes a leading `$` from a PHP variable token so it
// matches the bare-name form used by containsToken (`$n` → `n`).
func phpStripSigil(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "$")
}

// phpSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func phpSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkRedirect,
		taint.SnkTemplate, taint.SnkCommand, taint.SnkFileRead,
		taint.SnkFileWrite, taint.SnkHeader:
		return true
	}
	return false
}

// findPHPParamFlowToSink returns the source-param index whose name appears
// in the sink line's argument expression, or -1 when none do. The PHP
// builder does not populate typed Params, so this returns -1 in practice;
// the slot is kept for parity and forward-compatibility with a future
// typed-summary extractor.
func findPHPParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
	if sig == nil || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return -1
	}
	sinkLine := lines[sinkLineIdx]
	if len(sig.SourceParams) > 0 {
		for paramIdx := range sig.SourceParams {
			name := phpStripSigil(paramNameFromSig(sig, paramIdx))
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
		if containsToken(sinkLine, phpStripSigil(p.Name)) {
			return p.Index
		}
	}
	return -1
}

// checkPHPCallerUsesTaintedReturn is the PHP analog of
// checkRubyCallerUsesTaintedReturn (Path B). Triggers when the callee has
// TaintedReturns and the caller stores the return value, then passes it to
// a sink.
func checkPHPCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs phpCallSite,
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
	returnVar := phpStripSigil(cs.assignedTo)
	if returnVar == "" {
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
	calleeBaseName := phpBaseName(calleeNode.Name)
	patterns := loadPHPSinkPatterns()

	var findings []rules.Finding
	for i := callLineIdx + 1; i < len(callerLines); i++ {
		line := callerLines[i]
		if phpIsCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if phpSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
					sanitized = true
					break
				}
			}
			if sanitized {
				continue
			}

			// Catalog-backed sanitizer gate: returnVar was rebound from a
			// catalog sanitizer neutralising this category before the sink
			// line (last-assignment-wins; the tainted call assignment
			// itself is a plain fact that revokes any earlier sanitize).
			if sanGate.argSanitized(returnVar, callerNode.StartLine+i, p.category) {
				continue
			}
			if phpSanitizerRe.MatchString(line) && phpSinkLineSanitizerNeutralises(p.category) {
				continue
			}

			sinkLineNum := callerNode.StartLine + i
			sev := severityForSinkCategory[p.category]
			if sev < rules.High {
				sev = rules.High
			}
			cwe := cweForSinkCategory[p.category]
			owasp := owaspForSinkCategory[p.category]

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
					Label: fmt.Sprintf("result of %s(...) assigned to $%s", calleeBaseName, returnVar),
				},
				{
					File:  callerNode.FilePath,
					Line:  sinkLineNum,
					Kind:  rules.TaintStepSink,
					Label: p.method,
				},
			}

			findings = append(findings, rules.Finding{
				RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(p.category))),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title: fmt.Sprintf(
					"Interprocedural taint: %s data from %s() reaches %s",
					srcCatLabel, calleeNode.Name, p.method,
				),
				Description: fmt.Sprintf(
					"Return value of %s() (called at %s:%d) carries %s taint. "+
						"The caller %s() stores it in '$%s' and passes it to %s at line %d "+
						"without sanitization, creating a cross-function %s vulnerability.",
					calleeNode.Name, callerNode.FilePath, callLineNum,
					srcCatLabel,
					callerNode.Name, returnVar, p.method, sinkLineNum,
					p.category,
				),
				FilePath:   callerNode.FilePath,
				LineNumber: sinkLineNum,
				MatchedText: fmt.Sprintf(
					"%s() -> $%s -> %s (line %d)",
					calleeNode.Name, returnVar, p.method, sinkLineNum,
				),
				TaintPath: taintPath,
				Suggestion: fmt.Sprintf(
					"Sanitize '$%s' (returned by %s()) before passing it to %s.",
					returnVar, calleeNode.Name, p.method,
				),
				CWEID:           cwe,
				OWASPCategory:   owasp,
				Confidence:      "high",
				ConfidenceScore: 0.8,
				SourceCategory:  srcCatJSON,
				SinkCategory:    string(p.category),
				Language:        calleeNode.Language,
				Tags: []string{
					"interprocedural", "taint-analysis", "cross-function",
					"return-taint", "php", string(p.category),
				},
			})
		}
	}
	return findings
}

// phpArgRoot reduces an argument expression to its root variable name
// (sigil-stripped). `$n` → "n"; `$obj->prop` → "obj"; `$arr['k']` →
// "arr". Returns "" when the expression has no leading variable.
func phpArgRoot(argExpr string) string {
	root := strings.TrimSpace(argExpr)
	if dotIdx := strings.Index(root, "->"); dotIdx > 0 {
		root = root[:dotIdx]
	}
	if bracketIdx := strings.Index(root, "["); bracketIdx > 0 {
		root = root[:bracketIdx]
	}
	return phpStripSigil(strings.TrimSpace(root))
}
