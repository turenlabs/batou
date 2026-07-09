// Perl cross-file interprocedural walker (PR-Gperl).
//
// Like the JS / Lua / Rust equivalents, the Go-default AnalyzeCallerImpact
// in interprocedural.go scans the caller body with the Go sink regex table
// and uses Go arg parsing. Routing Perl through that path emits zero
// findings — Perl calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_lua.go. It uses the Perl taint catalog
// (SinksForLanguage / SourcesForLanguage) to identify sinks inside callee
// bodies and tainted returns, and a coarse direct-source regex for typical
// CGI / Plack / Mojolicious / Catalyst / Dancer2 request shapes
// (`$cgi->param(...)`, `$req->param(...)`, `$c->req->param(...)`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Perl callee (in a
//     `use`d package) that forwards it into a sink. Direct source
//     expressions in the call site (`$cgi->param('id')`, `$ENV{...}`, ...)
//     are recognised.
//   - Path B: callee (in a `use`d package) returns tainted data and the
//     caller passes the result to a sink. Recognised when the callee has
//     TaintedReturns set. ensurePerlCalleeReturns scans the callee body for
//     `return <source-expr>` and populates TaintedReturns on the fly, so
//     the canonical module-getter idiom — `sub get_name { return
//     $cgi->param('n') }` in A.pm, `system(A::get_name($cgi))` /
//     `my $n = A::get_name($cgi); system($n)` in main.pl — fires without
//     planted test data. THIS IS THE V1 MILESTONE PATH.
//   - 1-hop interproc only.
//
// As with the Lua walker, the Perl walker IS allowed to populate a callee's
// TaintSig.SinkCalls / TaintedReturns on the fly when empty — the same-file
// PropagateInterproc path doesn't run Perl sink regex.
//
// Every helper here is reached only for rules.LangPerl callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactPerlCached
// solely from its `case rules.LangPerl` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// perlSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadPerlSinkPatterns
// interoperates with the shared walk core without conversion (the
// module/requireModule/dangerousArgs fields stay zero — Perl sink matching is
// method-name based).
type perlSinkPattern = crossfileSinkPattern

var (
	perlSinkPatternsCache   []perlSinkPattern
	perlSinkPatternsCacheMu sync.Mutex
)

// loadPerlSinkPatterns compiles and caches the Perl taint sink catalog into
// regex form.
func loadPerlSinkPatterns() []perlSinkPattern {
	perlSinkPatternsCacheMu.Lock()
	defer perlSinkPatternsCacheMu.Unlock()
	if perlSinkPatternsCache != nil {
		return perlSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangPerl)
	out := make([]perlSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, perlSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	perlSinkPatternsCache = out
	return out
}

// perlSourceExprRe matches taint source expressions in a Perl arg position.
// Distilled from perl_sources.go — covers the framework request idioms most
// likely to appear as a direct call-site argument or in a `return <src>`.
var perlSourceExprRe = regexp.MustCompile(
	`\$\w+->param\s*\(` + // $cgi->param / $q->param / $req->param / $c->param
		`|\$\w+->Vars\b` + // $cgi->Vars
		`|->req->param\s*\(` + // $c->req->param
		`|->request->param\s*\(` + // $c->request->param
		`|->query->param\s*\(` + // CGI::App $self->query->param
		`|\$\w+->cookie\s*\(` + // ->cookie(...)
		`|\$\w+->upload\s*\(` + // ->upload(...)
		`|\$\w+->path_info\b` +
		`|\$\w+->referer\b` +
		`|\$\w+->user_agent\b` +
		`|->body_parameters\b` +
		`|->query_parameters\b` +
		`|\bparams->\{` + // Dancer2 params->{...}
		`|\$ENV\{` + // %ENV
		`|\@ARGV\b|\$ARGV\[` + // @ARGV
		`|<STDIN>` +
		`|\bdecode_json\s*\(` +
		`|\bdecode_jwt\s*\(`,
)

// perlSanitizerRe matches common Perl sanitizer-call shapes for the cross-
// file pass. Kept narrow to avoid swallowing the canonical-fix path before
// the sink fires. Distilled from perl_sanitizers.go: HTML/URL/SQL/command/
// regex escapers and numeric coercion.
var perlSanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`quotemeta` +
		`|encode_entities` +
		`|escapeHTML` +
		`|escape_html` +
		`|uri_escape` +
		`|url_escape` +
		`|shell_quote` +
		`|looks_like_number` +
		`|basename` +
		`|canonpath` +
		`|escape_filter_value` +
		`|escape_dn_value` +
		`)\s*\(` +
		`|->quote\s*\(` + // $dbh->quote(...)
		`|->execute\s*\(` + // DBI placeholder execute
		`|\\Q`, // \Q...\E regex escape
)

// AnalyzeCallerImpactPerl mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Perl call expressions in the caller body and the
// Perl taint catalog to identify sinks / tainted returns inside the callee.
// Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs the Go
// / Python / JS / Lua paths use.
func AnalyzeCallerImpactPerl(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactPerlCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactPerlCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the Perl config (perlCrossfileWalkCfg) and the
// call-site finder. Path A folds into the shared core; Perl's Path B stays
// behind the config's customPathB hook (checkPerlCallerUsesTaintedReturn)
// because it fires the inline-sink and via-variable cases independently for
// one call site (the shared Path B is XOR by returnVar) and carries
// used-package-specific wording the shared forward-scan doesn't reproduce.
func analyzeCallerImpactPerlCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *perlCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		perlCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return perlCallSitesToShared(findPerlCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// perlCallSitesToShared converts perlCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func perlCallSitesToShared(in []perlCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensurePerlCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls when
// it's empty. Idempotent.
func ensurePerlCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangPerl {
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
	sinks := scanPerlBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findPerlParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensurePerlCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>`.
// This handles the canonical module-getter idiom where a `use`d package
// exposes a getter returning request-derived data. Idempotent.
func ensurePerlCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangPerl {
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
	cat, found := scanPerlBodyForTaintedReturn(body)
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

// scanPerlBodyForTaintedReturn reports whether any `return` statement in the
// body carries a catalog source expression (`return $cgi->param('n')`, or
// `my $v = $cgi->param('n'); ... return $v`). Returns the source category.
// Perl subs also have an implicit return of the last expression, so a final
// bare source expression is treated as a tainted return too.
//
// The body is split into STATEMENTS, not just newline-lines, because Perl
// subs are routinely written on a single physical line —
// `sub g { my $v = $cgi->param('n'); return $v; }` — where every statement
// collapses onto one line. Splitting only on `\n` there would (a) capture
// just the FIRST `=` of the line as the binding (tainting `$cgi`, never `$v`)
// and (b) miss the `return $v` because the line as a whole does not START
// with `return`. perlSplitStatements strips the enclosing `sub … { … }`
// wrapper and splits on top-level `;` so each statement is analysed
// independently, making single-line and multi-line subs behave identically.
func scanPerlBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	stmts := perlSplitStatements(body)
	// Track variables assigned a source expression so `my $v = source;
	// return $v` is recognised.
	taintedVars := map[string]bool{}
	for _, stmt := range stmts {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Record `my $x = <source>` / `$x = <source>` bindings.
		if eq := perlAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if perlSourceExprRe.MatchString(rhs) && !perlSanitizerRe.MatchString(rhs) {
				name := perlLastIdent(lhs)
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
		if perlSanitizerRe.MatchString(expr) {
			continue
		}
		if perlSourceExprRe.MatchString(expr) {
			return taint.SrcUserInput, true
		}
		// `return $v` where $v was assigned a source above.
		retVar := perlLastIdent(expr)
		if retVar != "" && taintedVars[retVar] {
			return taint.SrcUserInput, true
		}
	}
	return "", false
}

// perlSplitStatements breaks a sub body into individual statements so the
// tainted-return scan works whether the sub is written multi-line or all on
// one physical line. It first strips a leading `sub <name> {` declaration
// header and the matching trailing `}` (the body extracted by
// extractFuncBody includes the `sub … {` line and the closing brace), then
// splits the remaining text on BOTH newlines and top-level `;`. Semicolons
// inside single- or double-quoted strings are not treated as separators so a
// `system("a; b")` argument isn't mis-split. Braces are tracked only to drop
// the outermost wrapper; nested blocks are flattened into statements, which
// is acceptable for the conservative source/return matching here.
func perlSplitStatements(body string) []string {
	// Drop a leading `sub NAME {` header. Find the first `{` and discard up
	// to and including it — that brace opens the sub body. Everything the
	// header carries (the `sub`, the name, prototypes/attributes) is not a
	// statement we care about.
	if br := strings.IndexByte(body, '{'); br >= 0 {
		// Only strip when the text before the first `{` looks like a sub
		// header (begins with `sub`), so a body passed without the wrapper
		// (e.g. from a unit test) is left intact.
		if strings.HasPrefix(strings.TrimSpace(body[:br]), "sub") {
			body = body[br+1:]
			// Drop the matching trailing `}` of the sub.
			if last := strings.LastIndexByte(body, '}'); last >= 0 {
				body = body[:last]
			}
		}
	}

	var stmts []string
	var cur strings.Builder
	var quote byte // 0, '\'' or '"'
	flush := func() {
		if cur.Len() > 0 {
			stmts = append(stmts, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == quote && (i == 0 || body[i-1] != '\\') {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == ';' || c == '\n':
			// Statement boundary.
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return stmts
}

// perlAssignEq returns the index of the single `=` assignment operator in a
// line, or -1 when the line isn't a plain assignment (skips ==, !=, <=, >=,
// =~, =>).
func perlAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, =~, =>.
		if i+1 < len(line) {
			nxt := line[i+1]
			if nxt == '=' || nxt == '~' || nxt == '>' {
				i++
				continue
			}
		}
		if i > 0 {
			prev := line[i-1]
			if prev == '=' || prev == '!' || prev == '<' || prev == '>' || prev == '~' || prev == '+' || prev == '-' || prev == '.' || prev == '*' {
				continue
			}
		}
		return i
	}
	return -1
}

// perlLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / return expression). Strips Perl sigils
// ($, @, %) and a leading `my`/`our`/`local` keyword.
func perlLastIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "my ")
	s = strings.TrimPrefix(s, "our ")
	s = strings.TrimPrefix(s, "local ")
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanPerlBodyForSinks walks the body line-by-line with each cached
// perlSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanPerlBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadPerlSinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Same-line sanitizer suppression: a sink whose argument is
			// wrapped in an escaper / numeric coercion is safe.
			if perlSanitizerRe.MatchString(line) && perlSinkLineSanitizerNeutralises(p.category) {
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

// perlSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func perlSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkRedirect,
		taint.SnkTemplate, taint.SnkFileRead, taint.SnkFileWrite,
		taint.SnkCommand, taint.SnkLDAP, taint.SnkHeader:
		return true
	}
	return false
}

// findPerlParamFlowToSink returns the source-param index whose name appears
// in the sink line's argument expression, or -1 when none do.
func findPerlParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkPerlCallerUsesTaintedReturn is the Perl analog of
// checkLuaCallerUsesTaintedReturn (Path B). Triggers when callee has
// TaintedReturns and the caller passes the result to a sink — either via an
// intermediate variable (`my $x = A::get_name($cgi); system($x)`) or inlined
// directly (`system(A::get_name($cgi))`). THIS IS THE V1 MILESTONE PATH.
func checkPerlCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs perlCallSite,
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
	patterns := loadPerlSinkPatterns()

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
				"Return value of %s() (called at %s:%d) carries %s taint from a used package. "+
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
				"Sanitize the value returned by %s() (e.g. quotemeta / shell_quote / a validation regex) before passing it to %s.",
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
				"return-taint", "perl", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call itself is an argument to a sink
	// on the SAME line (`system(A::get_name($cgi))`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if perlSanitizerRe.MatchString(line) && perlSinkLineSanitizerNeutralises(p.category) {
				continue
			}
			emit(callLineNum, p.method, p.category,
				fmt.Sprintf("result of %s(...) passed inline to sink", calleeBaseName))
		}
	}

	// Case 2: intermediate variable — `my $x = A::get_name($cgi)` then a
	// later line uses $x in a sink.
	returnVar := cs.assignedTo
	if returnVar != "" {
		for i := callLineIdx + 1; i < len(callerLines); i++ {
			line := callerLines[i]
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if perlSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
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
				if perlSanitizerRe.MatchString(line) && perlSinkLineSanitizerNeutralises(p.category) {
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

// perlRootIdent returns the leading variable name of an expression,
// stripping the Perl sigil and a `->method` / `[index]` / `{key}` / `(args)`
// tail (`$obj->get` → "obj", `$x` → "x").
func perlRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	root = strings.TrimLeft(root, "$@%\\")
	if i := strings.IndexAny(root, ".[({-"); i > 0 {
		root = root[:i]
	}
	// `->` starts with '-', already cut above; trim any trailing sigil noise.
	return strings.TrimSpace(root)
}
