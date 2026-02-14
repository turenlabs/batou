// Cross-function taint propagation for GTSS.
//
// When Claude modifies function B, GTSS doesn't just analyze B in isolation.
// It walks the call graph to find all callers of B, checks if taint from
// B's parameters flows through callers to dangerous sinks, and reports
// interprocedural taint paths that would be invisible to single-function analysis.
//
// The algorithm:
//  1. Compute taint signatures for changed functions
//  2. Compare with previous signatures to detect meaningful changes
//  3. Walk CalledBy edges transitively to find impacted callers
//  4. Analyze each caller for cross-function taint flows
//  5. Return findings with clear interprocedural explanations
package graph

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// maxTraversalDepth limits how far we walk up the call graph.
const maxTraversalDepth = 5

// cweForSinkCategory maps sink categories to their CWE IDs.
var cweForSinkCategory = map[taint.SinkCategory]string{
	taint.SnkSQLQuery:    "CWE-89",
	taint.SnkCommand:     "CWE-78",
	taint.SnkFileWrite:   "CWE-22",
	taint.SnkHTMLOutput:  "CWE-79",
	taint.SnkEval:        "CWE-94",
	taint.SnkRedirect:    "CWE-601",
	taint.SnkLDAP:        "CWE-90",
	taint.SnkXPath:       "CWE-643",
	taint.SnkHeader:      "CWE-113",
	taint.SnkTemplate:    "CWE-1336",
	taint.SnkDeserialize: "CWE-502",
	taint.SnkLog:         "CWE-117",
	taint.SnkCrypto:      "CWE-327",
	taint.SnkURLFetch:    "CWE-918",
}

// owaspForSinkCategory maps sink categories to OWASP top 10.
var owaspForSinkCategory = map[taint.SinkCategory]string{
	taint.SnkSQLQuery:    "A03:2021-Injection",
	taint.SnkCommand:     "A03:2021-Injection",
	taint.SnkFileWrite:   "A01:2021-Broken Access Control",
	taint.SnkHTMLOutput:  "A03:2021-Injection",
	taint.SnkEval:        "A03:2021-Injection",
	taint.SnkRedirect:    "A01:2021-Broken Access Control",
	taint.SnkLDAP:        "A03:2021-Injection",
	taint.SnkXPath:       "A03:2021-Injection",
	taint.SnkHeader:      "A03:2021-Injection",
	taint.SnkTemplate:    "A03:2021-Injection",
	taint.SnkDeserialize: "A08:2021-Software and Data Integrity Failures",
	taint.SnkLog:         "A09:2021-Security Logging and Monitoring Failures",
	taint.SnkCrypto:      "A02:2021-Cryptographic Failures",
	taint.SnkURLFetch:    "A10:2021-Server-Side Request Forgery",
}

// severityForSinkCategory maps sink categories to finding severity.
var severityForSinkCategory = map[taint.SinkCategory]rules.Severity{
	taint.SnkSQLQuery:    rules.Critical,
	taint.SnkCommand:     rules.Critical,
	taint.SnkEval:        rules.Critical,
	taint.SnkDeserialize: rules.Critical,
	taint.SnkFileWrite:   rules.High,
	taint.SnkHTMLOutput:  rules.High,
	taint.SnkRedirect:    rules.High,
	taint.SnkLDAP:        rules.High,
	taint.SnkXPath:       rules.High,
	taint.SnkHeader:      rules.High,
	taint.SnkTemplate:    rules.High,
	taint.SnkURLFetch:    rules.High,
	taint.SnkLog:         rules.Medium,
	taint.SnkCrypto:      rules.High,
}

// Patterns for identifying taint source parameter types.
var sourceParamPatterns = map[*regexp.Regexp]taint.SourceCategory{
	regexp.MustCompile(`\*?http\.Request`):            taint.SrcUserInput,
	regexp.MustCompile(`\*?gin\.Context`):              taint.SrcUserInput,
	regexp.MustCompile(`\*?echo\.Context`):             taint.SrcUserInput,
	regexp.MustCompile(`\*?fiber\.Ctx`):                taint.SrcUserInput,
	regexp.MustCompile(`http\.ResponseWriter`):         taint.SrcExternal,
	regexp.MustCompile(`\*?sql\.Row`):                  taint.SrcDatabase,
	regexp.MustCompile(`\*?sql\.Rows`):                 taint.SrcDatabase,
	regexp.MustCompile(`\*?gorm\.DB`):                  taint.SrcDatabase,
	regexp.MustCompile(`io\.Reader`):                   taint.SrcNetwork,
	regexp.MustCompile(`io\.ReadCloser`):               taint.SrcNetwork,
	regexp.MustCompile(`net\.Conn`):                    taint.SrcNetwork,
}

// directSourcePatterns matches common taint source expressions in argument expressions.
// Compiled once at package level to avoid re-compiling on every call to isArgTaintedInCaller.
var directSourcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bRequest\b`),
	regexp.MustCompile(`\.FormValue\s*\(`),
	regexp.MustCompile(`\.Query\(\)\.(Get|Encode)`),
	regexp.MustCompile(`\.PostForm\b`),
	regexp.MustCompile(`\.URL\.Query\b`),
	regexp.MustCompile(`\.Body\b`),
	regexp.MustCompile(`\.Header\.(Get|Values)\s*\(`),
	regexp.MustCompile(`\.Param\s*\(`),
	regexp.MustCompile(`\.QueryParam\s*\(`),
	regexp.MustCompile(`\bc\.Query\s*\(`),
	regexp.MustCompile(`\bc\.PostForm\s*\(`),
	regexp.MustCompile(`os\.Args\b`),
	regexp.MustCompile(`os\.Getenv\s*\(`),
}

// Patterns for identifying sink calls.
var sinkCallPatterns = []struct {
	pattern  *regexp.Regexp
	category taint.SinkCategory
	method   string
}{
	{regexp.MustCompile(`\bdb\.\s*(Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(`), taint.SnkSQLQuery, "sql.Query"},
	{regexp.MustCompile(`\bsql\.\s*(Query|QueryRow|Exec)\s*\(`), taint.SnkSQLQuery, "sql.Query"},
	{regexp.MustCompile(`\bexec\.\s*(Command|CommandContext)\s*\(`), taint.SnkCommand, "exec.Command"},
	{regexp.MustCompile(`\bos\.\s*(Create|Open|OpenFile|WriteFile|Remove|Rename|Mkdir)\s*\(`), taint.SnkFileWrite, "os.File"},
	{regexp.MustCompile(`\bfmt\.\s*(Fprintf|Fprint|Fprintln)\s*\(\s*w\b`), taint.SnkHTMLOutput, "fmt.Fprint(w)"},
	{regexp.MustCompile(`\bw\.Write\s*\(`), taint.SnkHTMLOutput, "ResponseWriter.Write"},
	{regexp.MustCompile(`\btemplate\.\s*(HTML|JS|URL)\s*\(`), taint.SnkTemplate, "template"},
	{regexp.MustCompile(`\bhttp\.Redirect\s*\(`), taint.SnkRedirect, "http.Redirect"},
	{regexp.MustCompile(`\bhttp\.\s*(Get|Post|Head)\s*\(`), taint.SnkURLFetch, "http.Get"},
	{regexp.MustCompile(`\beval\s*\(`), taint.SnkEval, "eval"},
	{regexp.MustCompile(`\bjson\.Unmarshal\s*\(`), taint.SnkDeserialize, "json.Unmarshal"},
	{regexp.MustCompile(`\byaml\.Unmarshal\s*\(`), taint.SnkDeserialize, "yaml.Unmarshal"},
	{regexp.MustCompile(`\blog\.\s*(Print|Printf|Println|Fatal|Fatalf)\s*\(`), taint.SnkLog, "log.Print"},
}

// sanitizerPatterns identifies sanitization calls.
var sanitizerPatterns = []struct {
	pattern   *regexp.Regexp
	category  taint.SinkCategory
	sanitizer string
}{
	{regexp.MustCompile(`\bhtml\.EscapeString\s*\(`), taint.SnkHTMLOutput, "html.EscapeString"},
	{regexp.MustCompile(`\burl\.QueryEscape\s*\(`), taint.SnkRedirect, "url.QueryEscape"},
	{regexp.MustCompile(`\burl\.PathEscape\s*\(`), taint.SnkFileWrite, "url.PathEscape"},
	{regexp.MustCompile(`\bfilepath\.Clean\s*\(`), taint.SnkFileWrite, "filepath.Clean"},
	{regexp.MustCompile(`\bstrconv\.\s*(Atoi|ParseInt|ParseFloat|ParseBool)\s*\(`), taint.SnkSQLQuery, "strconv.Parse"},
	{regexp.MustCompile(`\bsqlx?\.\s*Named\s*\(`), taint.SnkSQLQuery, "sql.Named"},
	{regexp.MustCompile(`\bregexp\.\s*(Match|Find|Replace)\w*\s*\(`), taint.SnkSQLQuery, "regexp.Match"},
}

// PropagateInterproc performs interprocedural taint analysis starting
// from the given changed functions. It:
//  1. Computes the taint signature of each changed function
//  2. Compares with the previous signature
//  3. If changed, walks all callers and computes cross-function flows
//  4. Returns findings for any new interprocedural taint paths
func PropagateInterproc(cg *CallGraph, changedFuncIDs []string, fileContents map[string]string) []rules.Finding {
	var findings []rules.Finding

	for _, funcID := range changedFuncIDs {
		node := cg.GetNode(funcID)
		if node == nil {
			continue
		}

		content, ok := fileContents[node.FilePath]
		if !ok {
			continue
		}

		// Compute the new taint signature for this changed function.
		newSig := ComputeTaintSig(node, content, node.Language)

		// Compare with the old signature.
		oldSig := node.TaintSig
		if !SignatureChanged(oldSig, newSig) {
			continue
		}

		// Update the node's signature.
		node.TaintSig = newSig

		// Walk callers transitively up to maxTraversalDepth levels.
		callers := cg.GetTransitiveCallers(funcID, maxTraversalDepth)
		for _, callerNode := range callers {
			callerContent, ok := fileContents[callerNode.FilePath]
			if !ok {
				// We may only have the changed file's content; skip unknown callers.
				continue
			}

			callerFindings := AnalyzeCallerImpact(cg, callerNode, node, callerContent)
			findings = append(findings, callerFindings...)
		}
	}

	return findings
}

// ComputeTaintSig analyzes a function body and produces its TaintSignature.
// This summarizes: which params carry taint, which returns carry taint,
// what sinks exist, what sanitizers are applied.
func ComputeTaintSig(node *FuncNode, content string, lang rules.Language) TaintSignature {
	sig := TaintSignature{
		TaintedParams:  make(map[int][]taint.SourceCategory),
		TaintedReturns: make(map[int][]taint.SourceCategory),
		SourceParams:   make(map[int]taint.SourceCategory),
	}

	// Extract the function body from the full file content.
	body := extractFuncBody(content, node.StartLine, node.EndLine)
	if body == "" {
		sig.IsPure = true
		return sig
	}

	lines := strings.Split(body, "\n")

	// Step 1: Identify source parameters from the function signature.
	// Look at the first line (function declaration) for parameter types.
	if len(lines) > 0 {
		funcDecl := lines[0]
		identifySourceParams(funcDecl, &sig)
	}

	// Step 2: Find sink calls in the function body.
	for lineIdx, line := range lines {
		lineNum := node.StartLine + lineIdx

		for _, sp := range sinkCallPatterns {
			if sp.pattern.MatchString(line) {
				sinkRef := SinkRef{
					SinkCategory: sp.category,
					MethodName:   sp.method,
					Line:         lineNum,
					ArgFromParam: -1, // Will be refined below
				}

				// Try to determine which parameter flows to this sink.
				sinkRef.ArgFromParam = findParamFlowToSink(lines, lineIdx, &sig)

				sig.SinkCalls = append(sig.SinkCalls, sinkRef)
			}
		}
	}

	// Step 3: Find sanitized paths.
	for lineIdx, line := range lines {
		lineNum := node.StartLine + lineIdx
		for _, sp := range sanitizerPatterns {
			if sp.pattern.MatchString(line) {
				// Record sanitized paths for each source param + matching sink.
				for paramIdx := range sig.SourceParams {
					for _, sink := range sig.SinkCalls {
						if sink.SinkCategory == sp.category && sink.Line > lineNum {
							sig.SanitizedPaths = append(sig.SanitizedPaths, SanitizedPath{
								ParamIndex:    paramIdx,
								SinkCategory:  sp.category,
								SanitizerName: sp.sanitizer,
								SanitizerLine: lineNum,
							})
						}
					}
				}
			}
		}
	}

	// Step 4: Determine tainted params and returns.
	// If a source param exists and reaches a sink, the param is tainted.
	for paramIdx, srcCat := range sig.SourceParams {
		for _, sink := range sig.SinkCalls {
			if sink.ArgFromParam == paramIdx || sink.ArgFromParam == -1 {
				if !isPathSanitized(sig.SanitizedPaths, paramIdx, sink.SinkCategory) {
					sig.TaintedParams[paramIdx] = appendUniqueCat(
						sig.TaintedParams[paramIdx], srcCat,
					)
				}
			}
		}
	}

	// If there are source params but no sinks, taint may propagate through returns.
	if len(sig.SourceParams) > 0 && len(sig.SinkCalls) == 0 {
		// Check if the function returns values derived from params.
		for lineIdx := len(lines) - 1; lineIdx >= 0; lineIdx-- {
			line := strings.TrimSpace(lines[lineIdx])
			if strings.HasPrefix(line, "return ") {
				for paramIdx, srcCat := range sig.SourceParams {
					_ = paramIdx
					sig.TaintedReturns[0] = appendUniqueCat(
						sig.TaintedReturns[0], srcCat,
					)
				}
				break
			}
		}
	}

	// A function is pure if it has no source params, no sinks, and no tainted returns.
	sig.IsPure = len(sig.SourceParams) == 0 &&
		len(sig.SinkCalls) == 0 &&
		len(sig.TaintedReturns) == 0 &&
		len(sig.TaintedParams) == 0

	return sig
}

// AnalyzeCallerImpact checks if a caller is impacted by a callee's taint
// signature change. Returns findings if tainted data from the caller
// flows through the callee to a sink.
func AnalyzeCallerImpact(cg *CallGraph, callerNode *FuncNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	var findings []rules.Finding

	callerBody := extractFuncBody(callerContent, callerNode.StartLine, callerNode.EndLine)
	if callerBody == "" {
		return nil
	}

	calleeSig := calleeNode.TaintSig
	lines := strings.Split(callerBody, "\n")

	// Find lines where the caller calls the callee.
	calleeBaseName := extractBaseName(calleeNode.Name)
	callPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(calleeBaseName) + `\s*\(`)

	for lineIdx, line := range lines {
		if !callPattern.MatchString(line) {
			continue
		}

		callLine := callerNode.StartLine + lineIdx

		// --- Path A: Caller passes tainted data TO the callee ---
		// Check if caller passes tainted arguments to callee's sink-connected params.
		findings = append(findings,
			checkCallerPassesTaintToCallee(callerNode, calleeNode, &calleeSig, line, callLine, lines, lineIdx)...,
		)

		// --- Path B: Caller uses callee's tainted return value ---
		// Check if callee returns tainted data and caller passes it to a sink.
		findings = append(findings,
			checkCallerUsesTaintedReturn(callerNode, calleeNode, &calleeSig, line, callLine, lines, lineIdx)...,
		)
	}

	return findings
}

// FindImpactedCallers returns all functions that may be affected by
// changes to the given functions, walking up the call graph transitively.
func FindImpactedCallers(cg *CallGraph, changedFuncIDs []string) []ImpactedCaller {
	visited := make(map[string]bool)
	var impacted []ImpactedCaller

	for _, funcID := range changedFuncIDs {
		visited[funcID] = true
	}

	for _, funcID := range changedFuncIDs {
		node := cg.GetNode(funcID)
		if node == nil {
			continue
		}

		// BFS up the call graph.
		queue := []string{funcID}
		depth := 0

		for len(queue) > 0 && depth < maxTraversalDepth {
			var nextQueue []string
			for _, id := range queue {
				n := cg.GetNode(id)
				if n == nil {
					continue
				}
				for _, callerID := range n.CalledBy {
					if visited[callerID] {
						continue
					}
					visited[callerID] = true

					callerNode := cg.GetNode(callerID)
					if callerNode == nil {
						continue
					}

					// Determine severity based on the changed function's sinks.
					sev := bestSeverityFromSinks(node.TaintSig.SinkCalls)

					reason := fmt.Sprintf(
						"calls %s which has modified taint signature", node.Name,
					)
					if len(node.TaintSig.SinkCalls) > 0 {
						reason = fmt.Sprintf(
							"calls %s which now has %s sink (%s)",
							node.Name,
							node.TaintSig.SinkCalls[0].MethodName,
							node.TaintSig.SinkCalls[0].SinkCategory,
						)
					}

					impacted = append(impacted, ImpactedCaller{
						CallerID:   callerID,
						CallerNode: callerNode,
						Reason:     reason,
						Severity:   sev,
					})

					nextQueue = append(nextQueue, callerID)
				}
			}
			queue = nextQueue
			depth++
		}
	}

	// Sort by severity (highest first).
	sort.Slice(impacted, func(i, j int) bool {
		return impacted[i].Severity > impacted[j].Severity
	})

	return impacted
}

// --- Internal helpers ---

// extractFuncBody extracts lines startLine..endLine (1-indexed, inclusive) from content.
func extractFuncBody(content string, startLine, endLine int) string {
	if startLine <= 0 || endLine <= 0 || endLine < startLine {
		return ""
	}

	lines := strings.Split(content, "\n")
	if startLine > len(lines) {
		return ""
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}

	return strings.Join(lines[startLine-1:endLine], "\n")
}

// identifySourceParams parses a function declaration line and identifies
// which parameters are taint sources based on their types.
func identifySourceParams(funcDecl string, sig *TaintSignature) {
	// Extract the parameter list from the function declaration.
	parenStart := strings.Index(funcDecl, "(")
	if parenStart < 0 {
		return
	}

	// Find the matching closing paren (handle nested parens for method receivers).
	depth := 0
	paramStart := -1
	paramEnd := -1
	parenCount := 0

	for i := parenStart; i < len(funcDecl); i++ {
		switch funcDecl[i] {
		case '(':
			depth++
			parenCount++
			if parenCount == 2 {
				paramStart = i
			}
			if parenCount == 1 && paramStart == -1 {
				paramStart = i
			}
		case ')':
			depth--
			if depth == 0 {
				paramEnd = i
				goto done
			}
		}
	}
done:
	if paramStart < 0 || paramEnd < 0 {
		return
	}

	paramStr := funcDecl[paramStart+1 : paramEnd]
	params := strings.Split(paramStr, ",")

	for idx, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}

		for re, srcCat := range sourceParamPatterns {
			if re.MatchString(param) {
				sig.SourceParams[idx] = srcCat
				break
			}
		}
	}
}

// findParamFlowToSink attempts to determine which source parameter
// flows to a sink call on the given line by tracing variable assignments
// backward through the function body.
func findParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
	if len(sig.SourceParams) == 0 {
		return -1
	}

	sinkLine := lines[sinkLineIdx]

	// Extract argument expressions from the sink call.
	parenIdx := strings.Index(sinkLine, "(")
	if parenIdx < 0 {
		return -1
	}

	argsStr := sinkLine[parenIdx:]
	// Simplified: look backward for variable assignments that trace to params.
	// For each source param, check if any variable derived from it appears in the sink args.
	for paramIdx := range sig.SourceParams {
		// Search backward for assignments from this param.
		// This is a lightweight heuristic — full tracking is done by taint.Analyze.
		paramName := findParamName(lines, paramIdx)
		if paramName == "" {
			continue
		}
		if strings.Contains(argsStr, paramName) {
			return paramIdx
		}

		// Also check if any variable assigned from this param appears in the sink.
		for i := 0; i < sinkLineIdx; i++ {
			trimmed := strings.TrimSpace(lines[i])
			if strings.Contains(trimmed, paramName) {
				// This line references the param. Extract the LHS variable.
				if eqIdx := strings.Index(trimmed, ":="); eqIdx > 0 {
					lhs := strings.TrimSpace(trimmed[:eqIdx])
					if strings.Contains(argsStr, lhs) {
						return paramIdx
					}
				} else if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 {
					before := trimmed[eqIdx-1]
					if before != '!' && before != '<' && before != '>' && before != '=' {
						lhs := strings.TrimSpace(trimmed[:eqIdx])
						if strings.Contains(argsStr, lhs) {
							return paramIdx
						}
					}
				}
			}
		}
	}

	return -1
}

// findParamName extracts the Nth parameter name from the function declaration
// (assumed to be the first line).
func findParamName(lines []string, paramIdx int) string {
	if len(lines) == 0 {
		return ""
	}

	funcDecl := lines[0]
	parenStart := strings.Index(funcDecl, "(")
	if parenStart < 0 {
		return ""
	}

	// For methods, skip the receiver by finding the second '('.
	rest := funcDecl[parenStart+1:]
	closeIdx := strings.Index(rest, ")")
	if closeIdx < 0 {
		return ""
	}

	// Check if there's another param list (method receiver was first).
	afterClose := rest[closeIdx+1:]
	nextParen := strings.Index(afterClose, "(")
	if nextParen >= 0 {
		// This was the receiver; use the next param list.
		rest = afterClose[nextParen+1:]
		closeIdx = strings.Index(rest, ")")
		if closeIdx < 0 {
			return ""
		}
	}

	paramStr := rest[:closeIdx]
	params := strings.Split(paramStr, ",")

	if paramIdx >= len(params) {
		return ""
	}

	param := strings.TrimSpace(params[paramIdx])
	if param == "" {
		return ""
	}

	// Extract just the name (before the type).
	parts := strings.Fields(param)
	if len(parts) == 0 {
		return ""
	}

	return parts[0]
}

// isPathSanitized checks if a param→sink path has a sanitizer.
func isPathSanitized(paths []SanitizedPath, paramIdx int, sinkCat taint.SinkCategory) bool {
	for _, p := range paths {
		if p.ParamIndex == paramIdx && p.SinkCategory == sinkCat {
			return true
		}
	}
	return false
}

// appendUniqueCat appends a SourceCategory to a slice if not already present.
func appendUniqueCat(cats []taint.SourceCategory, cat taint.SourceCategory) []taint.SourceCategory {
	for _, c := range cats {
		if c == cat {
			return cats
		}
	}
	return append(cats, cat)
}

// extractBaseName returns the function name without package or receiver prefix.
// E.g. "pkg.Receiver.Method" → "Method", "FuncName" → "FuncName".
func extractBaseName(name string) string {
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// bestSeverityFromSinks returns the highest severity among a set of sink refs.
func bestSeverityFromSinks(sinks []SinkRef) rules.Severity {
	best := rules.High // Interprocedural findings are at least High.
	for _, sink := range sinks {
		if sev, ok := severityForSinkCategory[sink.SinkCategory]; ok && sev > best {
			best = sev
		}
	}
	return best
}

// checkCallerPassesTaintToCallee checks Path A: caller passes tainted data
// as arguments to the callee, and the callee has sinks for those params.
func checkCallerPassesTaintToCallee(
	callerNode *FuncNode,
	calleeNode *FuncNode,
	calleeSig *TaintSignature,
	callLine string,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
) []rules.Finding {
	var findings []rules.Finding

	if len(calleeSig.SinkCalls) == 0 {
		return nil
	}

	// Extract the arguments the caller passes to the callee.
	calleeBaseName := extractBaseName(calleeNode.Name)
	callIdx := strings.Index(callLine, calleeBaseName)
	if callIdx < 0 {
		return nil
	}

	argsStart := strings.Index(callLine[callIdx:], "(")
	if argsStart < 0 {
		return nil
	}

	argStr := callLine[callIdx+argsStart:]
	args := extractArgList(argStr)

	// Check each argument: is it tainted in the caller's context?
	for argIdx, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		// Check if this argument position connects to a sink in the callee.
		var matchedSink *SinkRef
		for i := range calleeSig.SinkCalls {
			sink := &calleeSig.SinkCalls[i]
			if sink.ArgFromParam == argIdx || sink.ArgFromParam == -1 {
				// Check if this path is sanitized in the callee.
				if !isPathSanitized(calleeSig.SanitizedPaths, argIdx, sink.SinkCategory) {
					matchedSink = sink
					break
				}
			}
		}
		if matchedSink == nil {
			continue
		}

		// Check if the argument is tainted in the caller's context.
		// Look backward in the caller for taint sources flowing to this arg.
		if !isArgTaintedInCaller(arg, callerLines, callLineIdx) {
			continue
		}

		sev := severityForSinkCategory[matchedSink.SinkCategory]
		if sev < rules.High {
			sev = rules.High
		}

		cwe := cweForSinkCategory[matchedSink.SinkCategory]
		owasp := owaspForSinkCategory[matchedSink.SinkCategory]

		finding := rules.Finding{
			RuleID:   fmt.Sprintf("GTSS-INTERPROC-%s", strings.ToUpper(string(matchedSink.SinkCategory))),
			Severity: sev,
			SeverityLabel: sev.String(),
			Title: fmt.Sprintf(
				"Interprocedural taint: user input flows through %s() to %s",
				calleeNode.Name, matchedSink.MethodName,
			),
			Description: fmt.Sprintf(
				"Tainted data from %s() (%s:%d) is passed as argument %d to %s(), "+
					"which forwards it to %s without sanitization. "+
					"This creates a cross-function %s vulnerability.",
				callerNode.Name, callerNode.FilePath, callLineNum,
				argIdx, calleeNode.Name,
				matchedSink.MethodName, matchedSink.SinkCategory,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: callLineNum,
			MatchedText: fmt.Sprintf(
				"%s (arg %d) -> %s() -> %s (line %d)",
				arg, argIdx, calleeNode.Name,
				matchedSink.MethodName, matchedSink.Line,
			),
			Suggestion: fmt.Sprintf(
				"Sanitize '%s' before passing it to %s(), or add sanitization inside %s() before the %s call.",
				arg, calleeNode.Name, calleeNode.Name, matchedSink.MethodName,
			),
			CWEID:         cwe,
			OWASPCategory: owasp,
			Confidence:    "high",
			Tags:          []string{"interprocedural", "taint-analysis", "cross-function", string(matchedSink.SinkCategory)},
		}

		findings = append(findings, finding)
	}

	return findings
}

// checkCallerUsesTaintedReturn checks Path B: callee returns tainted data,
// and the caller passes it to a sink without sanitization.
func checkCallerUsesTaintedReturn(
	callerNode *FuncNode,
	calleeNode *FuncNode,
	calleeSig *TaintSignature,
	callLine string,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
) []rules.Finding {
	var findings []rules.Finding

	if len(calleeSig.TaintedReturns) == 0 {
		return nil
	}

	// Find what variable receives the callee's return value.
	trimmed := strings.TrimSpace(callLine)
	var returnVar string

	if idx := strings.Index(trimmed, ":="); idx > 0 {
		lhs := strings.TrimSpace(trimmed[:idx])
		// Handle multi-return: take the first variable.
		if commaIdx := strings.Index(lhs, ","); commaIdx > 0 {
			returnVar = strings.TrimSpace(lhs[:commaIdx])
		} else {
			returnVar = lhs
		}
	} else if idx := strings.Index(trimmed, "="); idx > 0 {
		before := trimmed[idx-1]
		if before != '!' && before != '<' && before != '>' && before != '=' {
			if idx+1 >= len(trimmed) || trimmed[idx+1] != '=' {
				lhs := strings.TrimSpace(trimmed[:idx])
				if commaIdx := strings.Index(lhs, ","); commaIdx > 0 {
					returnVar = strings.TrimSpace(lhs[:commaIdx])
				} else {
					returnVar = lhs
				}
			}
		}
	}

	if returnVar == "" {
		return nil
	}

	// Search forward from the call site: does the return variable reach a sink?
	for i := callLineIdx + 1; i < len(callerLines); i++ {
		line := callerLines[i]

		for _, sp := range sinkCallPatterns {
			if !sp.pattern.MatchString(line) {
				continue
			}
			if !strings.Contains(line, returnVar) {
				continue
			}

			// Check if the return variable was sanitized between the call and the sink.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				for _, san := range sanitizerPatterns {
					if san.pattern.MatchString(callerLines[j]) && strings.Contains(callerLines[j], returnVar) {
						if san.category == sp.category {
							sanitized = true
							break
						}
					}
				}
				if sanitized {
					break
				}
			}
			if sanitized {
				continue
			}

			sinkLineNum := callerNode.StartLine + i
			sev := severityForSinkCategory[sp.category]
			if sev < rules.High {
				sev = rules.High
			}

			cwe := cweForSinkCategory[sp.category]
			owasp := owaspForSinkCategory[sp.category]

			// Determine the source category from the tainted return.
			srcCatLabel := "tainted"
			for _, cats := range calleeSig.TaintedReturns {
				if len(cats) > 0 {
					srcCatLabel = string(cats[0])
					break
				}
			}

			finding := rules.Finding{
				RuleID:   fmt.Sprintf("GTSS-INTERPROC-%s", strings.ToUpper(string(sp.category))),
				Severity: sev,
				SeverityLabel: sev.String(),
				Title: fmt.Sprintf(
					"Interprocedural taint: %s data from %s() reaches %s",
					srcCatLabel, calleeNode.Name, sp.method,
				),
				Description: fmt.Sprintf(
					"Return value of %s() (called at %s:%d) carries %s taint. "+
						"The caller %s() stores it in '%s' and passes it to %s at line %d "+
						"without sanitization, creating a cross-function %s vulnerability.",
					calleeNode.Name, callerNode.FilePath, callLineNum,
					srcCatLabel,
					callerNode.Name, returnVar, sp.method, sinkLineNum,
					sp.category,
				),
				FilePath:   callerNode.FilePath,
				LineNumber: sinkLineNum,
				MatchedText: fmt.Sprintf(
					"%s() -> %s -> %s (line %d)",
					calleeNode.Name, returnVar, sp.method, sinkLineNum,
				),
				Suggestion: fmt.Sprintf(
					"Sanitize '%s' (returned by %s()) before passing it to %s.",
					returnVar, calleeNode.Name, sp.method,
				),
				CWEID:         cwe,
				OWASPCategory: owasp,
				Confidence:    "high",
				Tags:          []string{"interprocedural", "taint-analysis", "cross-function", "return-taint", string(sp.category)},
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// isArgTaintedInCaller checks if an argument expression is tainted in the
// caller's context by looking backward for taint sources.
func isArgTaintedInCaller(argExpr string, callerLines []string, callLineIdx int) bool {
	// Direct source patterns in the argument itself.
	for re := range sourceParamPatterns {
		if re.MatchString(argExpr) {
			return true
		}
	}

	// Common taint source patterns directly in the argument.
	for _, re := range directSourcePatterns {
		if re.MatchString(argExpr) {
			return true
		}
	}

	// Trace the variable backward: look for assignments from taint sources.
	argVar := strings.TrimSpace(argExpr)
	// Strip method calls / field accesses to get the root variable.
	if dotIdx := strings.Index(argVar, "."); dotIdx > 0 {
		argVar = argVar[:dotIdx]
	}
	if bracketIdx := strings.Index(argVar, "["); bracketIdx > 0 {
		argVar = argVar[:bracketIdx]
	}

	for i := callLineIdx - 1; i >= 0; i-- {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)

		// Check if this line assigns to our variable.
		if !strings.Contains(trimmed, argVar) {
			continue
		}

		// Check if the RHS contains a taint source.
		for _, re := range directSourcePatterns {
			if re.MatchString(trimmed) {
				return true
			}
		}
	}

	return false
}

// extractArgList extracts a list of argument expressions from a string
// that starts at an opening parenthesis.
func extractArgList(s string) []string {
	if len(s) == 0 || s[0] != '(' {
		return nil
	}

	// Find the matching close paren.
	depth := 0
	end := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				goto found
			}
		}
	}
found:
	if end < 0 {
		end = len(s)
	}

	inner := s[1:end]
	if strings.TrimSpace(inner) == "" {
		return nil
	}

	// Split by commas, respecting nested parens.
	var args []string
	depth = 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	args = append(args, strings.TrimSpace(inner[start:]))

	return args
}
