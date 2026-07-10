// Shell cross-file interprocedural walker (PR-Gshell).
//
// Like the JS / Lua / Swift equivalents, the Go-default AnalyzeCallerImpact
// in interprocedural.go scans the caller body with the Go sink regex table
// and uses Go arg parsing. Routing Shell through that path emits zero
// findings — shell commands never match Go sink shapes.
//
// This file mirrors crossfile_walk_swift.go (the closest structural
// sibling: single-bucket bare-name resolution, no method receivers). It
// uses the Shell taint catalog (SinksForLanguage) to identify sinks inside
// callee bodies and a coarse direct-source regex for the canonical shell
// source shapes ($1/$@ positional args, $QUERY_STRING / CGI env, `read`,
// curl/jq output).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Shell function (defined
//     in another sourced file) that forwards it into a sink.
//   - Path B: callee "returns" tainted data and the caller passes the
//     result to a sink. Shell functions have no return value — they emit on
//     stdout, captured via command substitution (`n=$(get_name)`).
//     ensureShellCalleeReturns scans the callee body for a source reaching
//     stdout (`echo "$QUERY_STRING"`) and populates TaintedReturns on the
//     fly, so the V1 milestone — `get_name(){ echo "$QUERY_STRING"; }` in
//     lib.sh, `n=$(get_name); eval "$n"` in main.sh — fires without planted
//     test data. THE V1 MILESTONE is Path B.
//   - 1-hop interproc only.
//
// Every helper here is reached only for rules.LangShell callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactShellCached
// solely from its `case rules.LangShell` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// shellSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadShellSinkPatterns
// interoperates with the shared walk core without conversion (the
// module/requireModule/dangerousArgs fields stay zero — Shell sink matching is
// command-word based).
type shellSinkPattern = crossfileSinkPattern

var (
	shellSinkPatternsCache   []shellSinkPattern
	shellSinkPatternsCacheMu sync.Mutex
)

// loadShellSinkPatterns compiles and caches the Shell taint sink catalog
// into regex form.
func loadShellSinkPatterns() []shellSinkPattern {
	shellSinkPatternsCacheMu.Lock()
	defer shellSinkPatternsCacheMu.Unlock()
	if shellSinkPatternsCache != nil {
		return shellSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangShell)
	out := make([]shellSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, shellSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	shellSinkPatternsCache = out
	return out
}

// shellSourceExprRe matches taint source expressions in a Shell context.
// Distilled from shell_sources.go — positional args, CGI request env vars,
// the `read` builtin / $REPLY, and curl/jq/wget output capture. Used to
// recognise a source in a tainted-return body or a caller-arg expression.
var shellSourceExprRe = regexp.MustCompile(
	`\$(?:[1-9][0-9]*|@|\*|#)` + // $1, $2, $@, $*, $#
		`|\$\{(?:[1-9][0-9]*|@|\*)` + // ${1}, ${@}
		`|\$\{?(?:QUERY_STRING|HTTP_[A-Z_]+|REQUEST_[A-Z]+|REMOTE_[A-Z]+|CONTENT_[A-Z]+|PATH_INFO)\b` + // CGI env
		`|\$REPLY\b` + // read → $REPLY
		`|(?:^|[^\w.-])read\s+(?:-[a-zA-Z]+\s+)*` + // read builtin
		`|(?:^|[^\w.-])jq\s` + // jq output
		`|(?:^|[^\w.-])curl\s` + // curl output
		`|(?:^|[^\w.-])wget\s`, // wget output
)

// shellSanitizerRe matches common Shell sanitizer-call shapes for the
// cross-file pass. Distilled from shell_sanitizers.go. Kept narrow to avoid
// swallowing the canonical-fix path before the sink fires: printf %q/%d
// safe-quoting/numeric coercion, realpath/readlink/basename path
// canonicalisation, ${var//.../} character stripping, =~ allowlist regex,
// tr -cd/-dc allowlist scrub, and jq --arg parameterised binding.
var shellSanitizerRe = regexp.MustCompile(
	`printf\s+(?:-v\s+\w+\s+)?["']?%(?:q|[0-9.*+ -]*[di])` + // printf %q / %d
		`|(?:^|[^\w.-])realpath\s` +
		`|(?:^|[^\w.-])readlink\s` +
		`|(?:^|[^\w.-])basename\s` +
		`|\$\{[A-Za-z_][A-Za-z0-9_]*//` + // ${var//pat/}
		`|=~\s*\^[^$]` + // [[ $x =~ ^... ]]
		`|\btr\s+-[A-Za-z]*c[A-Za-z]*d[A-Za-z]*\b` + // tr -cd
		`|\btr\s+-[A-Za-z]*d[A-Za-z]*c[A-Za-z]*\b` + // tr -dc
		`|(?:^|[^\w.-])jq\s+(?:-[^\s]+\s+)*--arg(?:json)?\s`, // jq --arg
)

// AnalyzeCallerImpactShell mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Shell command calls in the caller body and the
// Shell taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs
// the Go / Python / JS / Lua / Swift paths use.
func AnalyzeCallerImpactShell(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactShellCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactShellCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the Shell config (shellCrossfileWalkCfg) and the
// call-site finder. Shell is the one language whose BOTH paths diverge: its
// Path A renders the callee without call parentheses (no shared knob controls
// that), so it stays behind customPathA, and its Path B fires the inline and
// via-variable cases independently, so it stays behind customPathB. Both keep
// their pre-migration functions byte-identical.
func analyzeCallerImpactShellCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *shellCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		shellCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return shellCallSitesToShared(findShellCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// shellCallSitesToShared converts shellCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func shellCallSitesToShared(in []shellCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureShellCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls when
// it's empty. Idempotent.
func ensureShellCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangShell {
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
	sinks := scanShellBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findShellParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureShellCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for a source reaching
// stdout. This handles the canonical shell idiom where a helper echoes
// request-derived data (`echo "$QUERY_STRING"`). Idempotent.
func ensureShellCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangShell {
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
	cat, found := scanShellBodyForTaintedReturn(body)
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

// scanShellBodyForTaintedReturn reports whether the function body emits a
// catalog source on stdout — the shell analogue of a tainted return. A
// shell function "returns" via stdout, captured by `$(...)`. We recognise:
//
//   - `echo "$QUERY_STRING"` / `printf '%s' "$1"` — a source printed
//     directly to stdout.
//   - `v="$1"; echo "$v"` — a source bound to a var, then echoed.
//
// printf %q / %d quoting/coercion on the same line neutralises the flow.
func scanShellBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `v="$1"; echo "$v"`
	// is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Record `x=<source>` bindings (shell assignments have no spaces
		// around `=`).
		if eq := shellAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if shellSourceExprRe.MatchString(rhs) && !shellSanitizerRe.MatchString(rhs) {
				name := shellLastIdent(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// An `echo`/`printf` line that emits a source (or a tainted var) to
		// stdout is the return.
		if m := shellStdoutEmitRe.FindStringSubmatch(trimmed); m != nil {
			emitArgs := m[1]
			if shellSanitizerRe.MatchString(trimmed) {
				continue
			}
			if shellSourceExprRe.MatchString(emitArgs) {
				return taint.SrcUserInput, true
			}
			// `echo "$v"` where v was bound to a source above.
			for v := range taintedVars {
				if shellExpandsVar(emitArgs, v) {
					return taint.SrcUserInput, true
				}
			}
		}
	}
	return "", false
}

// shellStdoutEmitRe matches an `echo`/`printf` command and captures the
// remainder of the line (its arguments). Anchored at a command boundary —
// start-of-line, after a `;`/`&`/`|` separator, OR after a `{`/`(`
// group/function-body opener — so it does not match `recho`/embedded text
// but DOES match the inline single-line function shape
// `get_name(){ echo "$x"; }` where `echo` follows the body brace.
var shellStdoutEmitRe = regexp.MustCompile(`(?:^|[;&|{(]\s*)(?:echo|printf)\b(.*)$`)

// shellExpandsVar reports whether expr expands the shell variable name
// (`$v`, `${v}`, `"$v"`).
func shellExpandsVar(expr, name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(expr, "$"+name) {
		// Guard against `$name` matching `$namelong` — require a non-ident
		// boundary after the name.
		idx := strings.Index(expr, "$"+name)
		end := idx + 1 + len(name)
		if end >= len(expr) || !isShellIdentByte(expr[end]) {
			return true
		}
	}
	if strings.Contains(expr, "${"+name+"}") {
		return true
	}
	return false
}

func isShellIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// shellAssignEq returns the index of the `=` in a shell assignment
// (`x=value`), or -1 when the line isn't a plain assignment. Shell
// assignments have NO spaces around `=`, so the byte immediately before `=`
// must be an identifier char and the byte after must not be `=` (skip
// `==`). Comparisons live inside `[ ]`/`[[ ]]` with spaces, which this
// rejects.
func shellAssignEq(line string) int {
	for i := 1; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		prev := line[i-1]
		// LHS char must be an identifier byte (no space → not a comparison).
		if !isShellIdentByte(prev) {
			continue
		}
		// Skip !=, <=, >=.
		if prev == '!' || prev == '<' || prev == '>' {
			continue
		}
		return i
	}
	return -1
}

// shellLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / argument expression). Strips a leading
// `local`/`export`/`declare`/`readonly` keyword.
func shellLastIdent(s string) string {
	s = strings.TrimSpace(s)
	for _, kw := range []string{"local ", "export ", "declare ", "readonly "} {
		s = strings.TrimPrefix(s, kw)
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanShellBodyForSinks walks the body line-by-line with each cached
// shellSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanShellBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadShellSinkPatterns()
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
			// Same-line sanitizer suppression.
			if shellSanitizerRe.MatchString(line) && shellSinkLineSanitizerNeutralises(p.category) {
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

// shellSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func shellSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkCommand, taint.SnkEval, taint.SnkNoSQL,
		taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkTemplate,
		taint.SnkFileRead, taint.SnkFileWrite, taint.SnkURLFetch:
		return true
	}
	return false
}

// findShellParamFlowToSink returns the source-param index whose name
// appears in the sink line's argument expression, or -1 when none do.
// Shell functions take no named formal parameters (positionals $1/$2 are
// referenced directly), so this primarily handles the SourceParams path
// when a signature carries one.
func findShellParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkShellCallerPassesTaintToCallee is the Shell analog of
// checkSwiftCallerPassesTaintToCallee (Path A). Emits one finding per
// (tainted arg, matching sink) pair.
func checkShellCallerPassesTaintToCallee(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs shellCallSite,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
	sanGate *callerSanitizerGate,
) []rules.Finding {
	if len(calleeSig.SinkCalls) == 0 {
		return nil
	}
	var findings []rules.Finding

	for argIdx, arg := range cs.args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		calleeHasSources := len(calleeSig.SourceParams) > 0
		var matchedSink *SinkRef
		for i := range calleeSig.SinkCalls {
			sink := &calleeSig.SinkCalls[i]
			if sink.ArgFromParam != argIdx {
				continue
			}
			if isPathSanitized(calleeSig.SanitizedPaths, argIdx, sink.SinkCategory) {
				continue
			}
			matchedSink = sink
			break
		}
		if matchedSink == nil && !calleeHasSources {
			for i := range calleeSig.SinkCalls {
				sink := &calleeSig.SinkCalls[i]
				if sink.ArgFromParam != -1 {
					continue
				}
				if isPathSanitized(calleeSig.SanitizedPaths, argIdx, sink.SinkCategory) {
					continue
				}
				matchedSink = sink
				break
			}
		}
		if matchedSink == nil {
			continue
		}

		if !isArgTaintedInShellCaller(arg, callerLines, callLineIdx, &callerNode.TaintSig) {
			continue
		}
		if shellSanitizerRe.MatchString(arg) {
			continue
		}
		if isSanitizerByName(calleeNode.Name, matchedSink.SinkCategory) {
			continue
		}

		// Catalog-backed caller-side sanitizer gate: the arg's base
		// variable was assigned from a catalog sanitizer neutralising
		// this sink category on an earlier line, with no plain rebind
		// since (last-assignment-wins). Purely suppressive; fails open
		// on parse failure or complex arg expressions.
		if sanGate.argSanitized(arg, callLineNum, matchedSink.SinkCategory) {
			continue
		}

		sev := severityForSinkCategory[matchedSink.SinkCategory]
		if sev < rules.High {
			sev = rules.High
		}
		cwe := cweForSinkCategory[matchedSink.SinkCategory]
		owasp := owaspForSinkCategory[matchedSink.SinkCategory]

		sinkLabel := matchedSink.MethodName
		if sinkLabel == "" {
			sinkLabel = string(matchedSink.SinkCategory)
		}
		taintPath := []rules.TaintStep{
			{
				File:  callerNode.FilePath,
				Line:  callLineNum,
				Kind:  rules.TaintStepSource,
				Label: fmt.Sprintf("tainted argument %q (arg %d)", arg, argIdx),
			},
			{
				File:  callerNode.FilePath,
				Line:  callLineNum,
				Kind:  rules.TaintStepPropagation,
				Label: fmt.Sprintf("passed to %s", extractBaseName(calleeNode.Name)),
			},
			{
				File:  calleeNode.FilePath,
				Line:  matchedSink.Line,
				Kind:  rules.TaintStepSink,
				Label: fmt.Sprintf("%s (in %s)", sinkLabel, calleeNode.Name),
			},
		}

		findings = append(findings, rules.Finding{
			RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(matchedSink.SinkCategory))),
			Severity:      sev,
			SeverityLabel: sev.String(),
			Title: fmt.Sprintf(
				"Interprocedural taint: user input flows through %s to %s",
				calleeNode.Name, matchedSink.MethodName,
			),
			Description: fmt.Sprintf(
				"Tainted data from %s (%s:%d) is passed as argument %d to %s, "+
					"which forwards it to %s without sanitization. "+
					"This creates a cross-function %s vulnerability.",
				callerNode.Name, callerNode.FilePath, callLineNum,
				argIdx, calleeNode.Name,
				matchedSink.MethodName, matchedSink.SinkCategory,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: callLineNum,
			MatchedText: fmt.Sprintf(
				"%s (arg %d) -> %s -> %s %s",
				arg, argIdx, calleeNode.Name,
				matchedSink.MethodName, formatSinkLocation(*matchedSink, calleeNode.FilePath),
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize '%s' before passing it to %s, or add sanitization inside %s (e.g. printf %%q / a =~ allowlist) before the %s call.",
				arg, calleeNode.Name, calleeNode.Name, matchedSink.MethodName,
			),
			CWEID:           cwe,
			OWASPCategory:   owasp,
			Confidence:      "high",
			ConfidenceScore: 0.8,
			SourceCategory:  string(taint.SrcExternal),
			SinkCategory:    string(matchedSink.SinkCategory),
			Language:        calleeNode.Language,
			Tags: []string{
				"interprocedural", "taint-analysis", "cross-function",
				"shell", string(matchedSink.SinkCategory),
			},
		})
	}

	return findings
}

// checkShellCallerUsesTaintedReturn is the Shell analog of
// checkSwiftCallerUsesTaintedReturn (Path B). Triggers when the callee has
// TaintedReturns and the caller passes the captured stdout to a sink —
// either via an intermediate variable (`n=$(get_name); eval "$n"`) or
// inlined directly (`eval "$(get_name)"`). THIS IS THE V1 MILESTONE PATH.
func checkShellCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs shellCallSite,
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
	patterns := loadShellSinkPatterns()

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
				Label: fmt.Sprintf("%s emits %s data on stdout", calleeNode.Name, srcCatLabel),
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
				"Interprocedural taint: %s data from %s reaches %s",
				srcCatLabel, calleeNode.Name, sinkMethod,
			),
			Description: fmt.Sprintf(
				"Output of %s (called at %s:%d) carries %s taint from another file in the project. "+
					"The caller %s passes it to %s at line %d without sanitization, "+
					"creating a cross-file %s vulnerability.",
				calleeNode.Name, callerNode.FilePath, callLineNum,
				srcCatLabel, callerNode.Name, sinkMethod, sinkLineNum, cat,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: sinkLineNum,
			MatchedText: fmt.Sprintf(
				"%s -> %s (line %d)",
				calleeNode.Name, sinkMethod, sinkLineNum,
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize the value captured from %s (e.g. printf %%q, a numeric coercion, or a =~ allowlist) before passing it to %s.",
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
				"return-taint", "shell", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call substitution is itself an
	// argument to a sink on the SAME line (`eval "$(get_name)"`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		// Only treat as inline when the substitution is NOT being captured
		// into a variable (that's Case 2). A `n=$(get_name)` line has the
		// substitution on the RHS of an assignment; a bare `eval "$(...)"`
		// has the sink command-word leading.
		if cs.assignedTo == "" {
			for _, p := range patterns {
				if !p.pattern.MatchString(line) {
					continue
				}
				if shellSanitizerRe.MatchString(line) && shellSinkLineSanitizerNeutralises(p.category) {
					continue
				}
				emit(callLineNum, p.method, p.category,
					fmt.Sprintf("output of %s captured inline into sink", calleeBaseName))
			}
		}
	}

	// Case 2: intermediate variable — `n=$(get_name)` then a later line
	// uses $n in a sink.
	returnVar := cs.assignedTo
	if returnVar != "" {
		for i := callLineIdx + 1; i < len(callerLines); i++ {
			line := callerLines[i]
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !shellExpandsVar(line, returnVar) {
				continue
			}
			// Sanitizer between capture and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if shellSanitizerRe.MatchString(callerLines[j]) && shellExpandsVar(callerLines[j], returnVar) {
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
				if shellSanitizerRe.MatchString(line) && shellSinkLineSanitizerNeutralises(p.category) {
					continue
				}
				sinkLineNum := callerNode.StartLine + i
				emit(sinkLineNum, p.method, p.category,
					fmt.Sprintf("output of %s captured into $%s", calleeBaseName, returnVar))
			}
		}
	}

	return findings
}

// isArgTaintedInShellCaller checks whether argExpr is tainted in the
// caller's context. Recognises direct catalog source expressions and
// backward-traces local variable assignments to source expressions.
func isArgTaintedInShellCaller(argExpr string, callerLines []string, callLineIdx int, callerSig *TaintSignature) bool {
	argTrim := strings.TrimSpace(argExpr)
	if argTrim == "" {
		return false
	}

	if shellSourceExprRe.MatchString(argExpr) {
		return true
	}

	argVar := shellArgVarName(argTrim)
	if argVar == "" {
		return false
	}
	for i := callLineIdx - 1; i >= 0; i-- {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		eqIdx := shellAssignEq(trimmed)
		if eqIdx <= 0 {
			continue
		}
		lhs := strings.TrimSpace(trimmed[:eqIdx])
		if shellLastIdent(lhs) != argVar {
			continue
		}
		rhs := trimmed[eqIdx+1:]
		if shellSanitizerRe.MatchString(rhs) {
			return false
		}
		if shellSourceExprRe.MatchString(rhs) {
			return true
		}
		// Nearest rebind of argVar is neither sanitizer nor source (a literal/
		// constant/other local). Last-write-wins kills any older tainted
		// binding — stop here instead of scanning further up to a stale source.
		return false
	}
	return false
}

// shellArgVarName extracts the variable name referenced by a shell argument
// expression: `"$arg"` / `$arg` / `${arg}` → "arg". Returns "" when the
// expression is not a single variable expansion.
func shellArgVarName(expr string) string {
	s := strings.TrimSpace(expr)
	s = strings.Trim(s, `"'`)
	if !strings.HasPrefix(s, "$") {
		return ""
	}
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	// Stop at the first non-identifier char.
	for i := 0; i < len(s); i++ {
		if !isShellIdentByte(s[i]) {
			s = s[:i]
			break
		}
	}
	return s
}
