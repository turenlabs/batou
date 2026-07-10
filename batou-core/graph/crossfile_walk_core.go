// Shared cross-file interprocedural walk core.
//
// The per-language cross-file walkers (crossfile_walk_python.go,
// crossfile_walk_javascript.go, crossfile_walk_ruby.go, ...) grew as
// ~15-function line-for-line clones of one template:
//
//	AnalyzeCallerImpactX(+Cached) -> findXCallSites ->
//	  Path A: checkXCallerPassesTaintToCallee (tainted arg -> callee sink)
//	  Path B: checkXCallerUsesTaintedReturn  (tainted return -> caller sink)
//
// This file implements that template ONCE, parameterised by
// crossfileWalkLangConfig — the same consolidation pattern
// crossfile_stored_state_langs.go proved with storedStateLangConfig. The
// genuinely language-specific parts (tree-sitter call-site extraction,
// source/sanitizer regexes, comment syntax, alias recovery, field
// sensitivity) live in per-language config structs
// (crossfile_walk_core_langs.go); everything else — the two-pass sink
// match (exact ArgFromParam then wildcard -1 gated on !calleeHasSources),
// isPathSanitized, the catalog-backed callerSanitizerGate (#1316), the
// isSanitizerByName cure-guard, the severity High floor, CWE/OWASP
// lookup, taintPath construction with the OriginFile lift-vs-direct
// branch, and the Confidence 0.8 emit — is shared verbatim.
//
// Phase 1 migrates Python and JavaScript/TypeScript (the reference
// implementations). The remaining 11 language files keep their clones
// until their own migration PRs; every shared branch below is therefore
// config-gated so a migrated language reproduces its pre-migration
// behaviour finding-for-finding.
package graph

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// crossfileCallSite is the language-neutral call-site shape the shared
// walker consumes. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`x = foo(...)` form).
//
// Per-language call-site types either alias this struct directly
// (javascriptCallSite) or convert into it (pythonCallSite, which carries
// an extra keywordArg map the shared checks never consume).
type crossfileCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// crossfileSinkPattern is a compiled SinkDef plus its category metadata
// so the shared walker can scan callee bodies / caller sink lines
// without hitting the catalog every time. The per-language
// *SinkPattern types (pythonSinkPattern, javascriptSinkPattern) are
// aliases of this struct so the existing per-language loaders and their
// stored-state consumers keep compiling unchanged.
type crossfileSinkPattern struct {
	pattern       *regexp.Regexp
	category      taint.SinkCategory
	method        string
	dangerousArgs []int
	// module is the qualifying receiver/module name (e.g. "subprocess",
	// "pickle"). Empty means "no module constraint" — the pattern matches
	// anywhere it textually appears. When requireModule is set the line
	// must also mention the module so bare-name collisions (json.loads
	// vs pickle.loads) don't fire on the wrong call.
	module        string
	requireModule bool
}

// crossfileFieldHooks carries the optional access-path field-sensitivity
// overlay (today: JavaScript/TypeScript, crossfile_walk_javascript_field.go).
// Languages without field sensitivity leave the config's field pointer
// nil, which disables every field-gated branch in the shared walker.
type crossfileFieldHooks struct {
	// buildCallerTaintedPaths scans the caller body up to the call line
	// and returns the set of bounded access paths tainted by a catalog
	// source (`o.cmd = req.body.cmd` -> "o.cmd").
	buildCallerTaintedPaths func(callerLines []string, callLineIdx int) map[string]bool
	// callerArgFieldTainted reports whether the composed caller arg field
	// path (arg + "." + argFieldPath, bounded) hits a tainted path.
	callerArgFieldTainted func(arg, argFieldPath string, taintedPaths map[string]bool) bool
	// argRootDirectlyTainted is the field-gate fallback: the arg is
	// tainted at its ROOT (direct catalog source or source-typed param),
	// so a field read off it is genuinely tainted even without an
	// intra-file field assignment.
	argRootDirectlyTainted func(argExpr string, callerLines []string, callLineIdx int, callerSig *TaintSignature) bool
	// sinkFieldPathForParam extracts the bounded field access path a sink
	// line reads off the given variable ("user.id" for `exec(r.user.id)`).
	sinkFieldPathForParam func(sinkLine, param string) string
}

// crossfileWalkLangConfig describes one language's cross-file walk
// surface. Every field reuses machinery that already exists in the
// per-language files — this struct only wires it into the shared core.
type crossfileWalkLangConfig struct {
	// commentPrefix is the line-comment marker skipped during body scans
	// ("#" for Python, "//" for JS/TS).
	commentPrefix string

	// sourceExprRe matches inline taint-source expressions in argument /
	// RHS position (request.args, req.body, ...).
	sourceExprRe *regexp.Regexp

	// sanitizerRe matches the language's coarse sanitizer-call net.
	sanitizerRe *regexp.Regexp

	// loadSinkPatterns returns the language's compiled sink catalog
	// (cached by the per-language loader).
	loadSinkPatterns func() []crossfileSinkPattern

	// ensureCalleeSinks / ensureCalleeReturns lazily populate the callee's
	// TaintSig when the per-file pass left it empty. ensureCalleeReturns
	// is nil for languages whose walker doesn't seed returns (Python).
	ensureCalleeSinks   func(cg *CallGraph, calleeNode *FuncNode)
	ensureCalleeReturns func(cg *CallGraph, calleeNode *FuncNode)

	// bindingAlias recovers the caller's LOCAL binding name for the callee
	// when it differs from the callee node name (JS default exports /
	// aliased imports — jsCallerBindingAlias). Nil when the language has
	// no import-alias recovery.
	bindingAlias func(cg *CallGraph, callerNode, calleeNode *FuncNode) string

	// findingLanguage / langTag control the Language field and the
	// language tag on emitted findings. Python pins rules.LangPython;
	// JS/TS report the callee node's language (JavaScript or TypeScript).
	findingLanguage func(calleeNode *FuncNode) rules.Language
	langTag         func(calleeNode *FuncNode) string

	// rootIsSourceParam reports whether an argument's root identifier is
	// a source-typed caller parameter. Kept per-language because the
	// historical implementations key SourceParams differently: Python by
	// Params SLICE POSITION, JS/TS by ParamTaint.Index.
	rootIsSourceParam func(root string, callerSig *TaintSignature) bool

	// stripDeclPrefixes are declarator keywords stripped from an
	// assignment LHS during the backward arg trace ("const ", "let ",
	// "var " for JS/TS; empty for Python).
	stripDeclPrefixes []string

	// pathBIncludesCallLine makes the Path B sink scan start AT the call
	// line (with a token-after-the-call gate) instead of the line after,
	// covering the compact `const n = f(req); cp.exec(n);` idiom (JS/TS).
	pathBIncludesCallLine bool

	// pathBInlineSink enables the inline 1-hop Path B shape where the
	// tainted return is consumed directly inside a sink argument on the
	// call line (`cp.exec(getA(req))`) with no intervening variable.
	pathBInlineSink bool

	// pathBCrossFileVulnWording swaps the shared Path B Description's
	// "cross-function %s vulnerability" phrasing for "cross-file %s
	// vulnerability". Purely cosmetic — the finding is otherwise identical.
	// C#'s pre-migration Path B used the "cross-file" phrasing; Python /
	// JS / Ruby used "cross-function". Defaults to false (cross-function)
	// so already-migrated languages stay byte-identical.
	pathBCrossFileVulnWording bool

	// field enables the access-path field-sensitivity overlay; nil for
	// languages without it.
	field *crossfileFieldHooks

	// --- Phase 2 knobs (Ruby / Lua / PHP migration). Each defaults to the
	// Python/JS behaviour when left zero, so already-migrated languages are
	// unaffected. ---

	// argRootFn reduces an argument expression to its root identifier for
	// both the source-param check and the backward-trace variable. Nil uses
	// the inline `.`/`[` strip (Python/JS/Ruby). Lua: luaRootIdent (also
	// strips `(` and `:`); PHP: phpArgRoot (strips `->` and the `$` sigil).
	argRootFn func(argExpr string) string

	// assignEqFinder locates the assignment `=` in a backward-trace line,
	// returning -1 to skip the line. Nil uses the inline first-`=` scan with
	// comparison-operator rejection (Python/JS/Ruby). Lua: luaAssignEq;
	// PHP: phpAssignEq (both reject their language's compound/comparison
	// operators the inline scan doesn't know about).
	assignEqFinder func(trimmed string) int

	// rejectArrowAssign additionally rejects a `=>` hash-rocket as an
	// assignment in the inline `=` scan (Ruby, where `k => v` is a hash
	// entry, not an assignment). Ignored when assignEqFinder is set.
	rejectArrowAssign bool

	// isCommentLineFn overrides the comment-line predicate in the backward
	// trace. Nil uses HasPrefix(trimmed, commentPrefix) (Python/JS/Ruby/Lua).
	// PHP needs it because PHP comments come in four shapes (//, #, *, /*).
	isCommentLineFn func(line string) bool

	// calleeBaseNameFn overrides the base-name shown in the Path A
	// propagation label. Nil uses extractBaseName (Python/JS/Ruby/Lua).
	// PHP: phpBaseName (strips `Cls::` scope and `\` namespace).
	calleeBaseNameFn func(name string) string

	// pathAPropLabelPassedToOnly forces the Path A propagation label to the
	// one-form "passed to X(...)" even when the matched sink binds a param
	// (ArgFromParam >= 0). The default (false) uses the richer two-form
	// "caller's A flows to X as param N" — the historical Python/JS/Ruby
	// behaviour. Lua and PHP's pre-migration Path A only ever emitted the
	// one-form, so they set this to stay label-identical.
	pathAPropLabelPassedToOnly bool

	// customPathA replaces the shared Path A entirely. Set only for
	// languages whose Path A wording genuinely diverges from the shared
	// emit and can't be reproduced with the existing label knobs:
	//   - Shell renders the callee WITHOUT call parentheses throughout its
	//     Path A finding (Title/Description/MatchedText/propagation label
	//     all say `foo`, not `foo()`), because shell functions are invoked
	//     bare. No existing knob controls the paren suffix, so its
	//     checkShellCallerPassesTaintToCallee stays byte-identical behind
	//     this hook. Defaults nil → shared Path A (every other language).
	customPathA func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding

	// customPathB replaces the shared Path B entirely. Set for languages
	// whose tainted-return handling genuinely diverges from the shared
	// forward-scan shape and can't be reproduced with knobs without
	// perturbing already-migrated languages:
	//   - Lua fires an inline-sink case AND a via-variable case
	//     independently for one call site (the shared Path B is XOR by
	//     returnVar), skips the inline nesting check, and applies a
	//     sink-line sanitizer gate the shared path lacks.
	//   - PHP applies a sink-line sanitizer gate and decorates the return
	//     variable with a `$` sigil throughout its finding text.
	// Their existing checkLuaCallerUsesTaintedReturn /
	// checkPHPCallerUsesTaintedReturn stay byte-identical behind this hook.
	customPathB func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding
}

// calleeBaseName returns the base name for Path A propagation labels,
// honouring the per-language override.
func (cfg *crossfileWalkLangConfig) calleeBaseName(name string) string {
	if cfg.calleeBaseNameFn != nil {
		return cfg.calleeBaseNameFn(name)
	}
	return extractBaseName(name)
}

// crossfileArgRoot reduces an argument expression to its root identifier,
// honouring the per-language override.
func crossfileArgRoot(cfg *crossfileWalkLangConfig, argExpr string) string {
	if cfg.argRootFn != nil {
		return cfg.argRootFn(argExpr)
	}
	root := strings.TrimSpace(argExpr)
	if dotIdx := strings.Index(root, "."); dotIdx > 0 {
		root = root[:dotIdx]
	}
	if bracketIdx := strings.Index(root, "["); bracketIdx > 0 {
		root = root[:bracketIdx]
	}
	return strings.TrimSpace(root)
}

// crossfileIsCommentLine reports whether a backward-trace line is a
// comment, honouring the per-language override.
func crossfileIsCommentLine(cfg *crossfileWalkLangConfig, line string) bool {
	if cfg.isCommentLineFn != nil {
		return cfg.isCommentLineFn(line)
	}
	return strings.HasPrefix(strings.TrimSpace(line), cfg.commentPrefix)
}

// analyzeCallerImpactCrossfile is the shared AnalyzeCallerImpactX body:
// ensure callee signatures, extract the caller body, locate call sites
// (via the per-language finder closure, which owns the pass-scoped parse
// cache), then run Path A and Path B per call site. findCallSites is a
// closure so each language keeps its typed call-index cache; sanMemo is
// the pass-scoped sanitizer-facts memo for the catalog-backed caller-side
// sanitizer gate (#1316), consulted lazily so non-candidate pairs never
// pay a parse.
func analyzeCallerImpactCrossfile(
	cfg *crossfileWalkLangConfig,
	cg *CallGraph,
	callerNode, calleeNode *FuncNode,
	callerContent string,
	findCallSites func(callerContent string, callerNode *FuncNode, calleeCallName string) []crossfileCallSite,
	sanMemo *sanitizerFactsMemo,
) []rules.Finding {
	if calleeNode == nil || callerNode == nil {
		return nil
	}

	// Make sure the callee has a sink/return signature we can act on.
	if cfg.ensureCalleeSinks != nil {
		cfg.ensureCalleeSinks(cg, calleeNode)
	}
	if cfg.ensureCalleeReturns != nil {
		cfg.ensureCalleeReturns(cg, calleeNode)
	}

	calleeSig := calleeNode.TaintSig
	// TaintedReturnPaths (field-sensitive) is a valid producer signal on
	// its own for field-enabled languages: a callee returning an object
	// literal with a tainted FIELD has no whole-return source but must
	// survive the fast-skip gate to reach Path B field composition.
	hasFieldReturnPaths := cfg.field != nil && len(calleeSig.TaintedReturnPaths) > 0
	if len(calleeSig.SinkCalls) == 0 && len(calleeSig.TaintedReturns) == 0 && !hasFieldReturnPaths {
		return nil
	}

	callerBody := extractFuncBody(callerContent, callerNode.StartLine, callerNode.EndLine)
	if callerBody == "" {
		return nil
	}
	lines := strings.Split(callerBody, "\n")

	// The caller may not write the call under the callee's NODE name
	// (default exports, aliased imports). Recover the caller's local
	// binding alias when the language supports it.
	calleeCallName := calleeNode.Name
	if cfg.bindingAlias != nil {
		if alias := cfg.bindingAlias(cg, callerNode, calleeNode); alias != "" {
			calleeCallName = alias
		}
	}

	callSites := findCallSites(callerContent, callerNode, calleeCallName)
	if len(callSites) == 0 {
		return nil
	}

	// Catalog-backed caller-side sanitizer gate (purely suppressive;
	// consulted lazily so non-candidate pairs never pay a parse).
	sanGate := newCallerSanitizerGate(sanMemo, callerNode, callerContent)

	var findings []rules.Finding
	for _, cs := range callSites {
		callLineNum := cs.line
		callLineIdx := callLineNum - callerNode.StartLine
		if callLineIdx < 0 || callLineIdx >= len(lines) {
			continue
		}

		// Path A: caller passes tainted args TO callee's sink-bearing params.
		// Languages whose Path A wording genuinely diverges (Shell: no call
		// parens) supply customPathA (their pre-migration function, kept
		// byte-identical); everyone else uses the shared Path A.
		if cfg.customPathA != nil {
			findings = append(findings,
				cfg.customPathA(callerNode, calleeNode, &calleeSig, cs, callLineNum, lines, callLineIdx, sanGate)...,
			)
		} else {
			findings = append(findings,
				crossfileCheckCallerPassesTaintToCallee(cfg, callerNode, calleeNode, &calleeSig, cs, callLineNum, lines, callLineIdx, sanGate)...,
			)
		}

		// Path B: caller stores callee's tainted return value, then sinks it.
		// Languages with a divergent tainted-return shape supply customPathB
		// (their pre-migration function, kept byte-identical); everyone else
		// uses the shared forward-scan Path B.
		if cfg.customPathB != nil {
			findings = append(findings,
				cfg.customPathB(callerNode, calleeNode, &calleeSig, cs, callLineNum, lines, callLineIdx, sanGate)...,
			)
		} else {
			findings = append(findings,
				crossfileCheckCallerUsesTaintedReturn(cfg, callerNode, calleeNode, &calleeSig, cs, callLineNum, lines, callLineIdx, sanGate)...,
			)
		}
	}
	return findings
}

// crossfileCheckCallerPassesTaintToCallee is the shared Path A: emits
// one finding per (tainted arg, matching sink) pair. The two-pass sink
// match tries the precise ArgFromParam == argIdx binding first, then the
// wildcard -1 fallback — the latter only when the callee has no
// SourceParams (the PR-FF constraint that avoids false positives when
// sinks carry proper positional info).
func crossfileCheckCallerPassesTaintToCallee(
	cfg *crossfileWalkLangConfig,
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs crossfileCallSite,
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

		// First pass: precise sink match (sink.ArgFromParam == argIdx).
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
		// Second pass: wildcard -1 fallback, only when the callee has no
		// SourceParams.
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

		// Field-sensitive gate: when the matched sink reads a specific
		// field off its param (ArgFieldPath != ""), compose the caller-side
		// access path and require the caller's intra-file per-field taint
		// for THAT EXACT path, falling back to a root-level direct-source
		// check (`run(req.body)` where the sink reads `.cmd`). An empty
		// ArgFieldPath — or a language without field hooks — falls through
		// to the whole-arg legacy check.
		if cfg.field != nil && matchedSink.ArgFieldPath != "" {
			taintedPaths := cfg.field.buildCallerTaintedPaths(callerLines, callLineIdx)
			if !cfg.field.callerArgFieldTainted(arg, matchedSink.ArgFieldPath, taintedPaths) {
				if !cfg.field.argRootDirectlyTainted(arg, callerLines, callLineIdx, &callerNode.TaintSig) {
					continue
				}
			}
		} else if !crossfileIsArgTaintedInCaller(cfg, arg, callerLines, callLineIdx, &callerNode.TaintSig) {
			continue
		}

		// Sanitizer applied on the arg expression itself.
		if cfg.sanitizerRe.MatchString(arg) {
			continue
		}

		// Sanitizer-named callee — emitting a finding on a function whose
		// entire job is to sanitize would flag the cure.
		if isSanitizerByName(calleeNode.Name, matchedSink.SinkCategory) {
			continue
		}

		// Catalog-backed caller-side sanitizer gate: the arg's base
		// variable was assigned from a catalog sanitizer neutralising this
		// sink category on an earlier line, with no plain rebind since
		// (last-assignment-wins). Purely suppressive; fails open on parse
		// failure or complex arg expressions.
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
		propLabel := fmt.Sprintf("passed to %s(...)", cfg.calleeBaseName(calleeNode.Name))
		if !cfg.pathAPropLabelPassedToOnly && matchedSink.ArgFromParam >= 0 {
			propLabel = fmt.Sprintf(
				"caller's %s flows to %s as param %d",
				arg, cfg.calleeBaseName(calleeNode.Name), matchedSink.ArgFromParam,
			)
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
				Label: propLabel,
			},
		}
		// When the matched sink was lifted up the call graph by
		// PropagateSignaturesAcrossCallgraph, the sink's true home is
		// OriginFile/OriginLine — calleeNode.FilePath is just an
		// intermediate "via" hop. Emit BOTH steps so the taint path
		// preserves the chain end-to-end. Direct (non-lifted) sinks leave
		// OriginFile empty and produce a single sink step rooted at the
		// callee. OriginFile may legitimately equal calleeNode.FilePath
		// when the leaf and via-hop live in the same module — honour the
		// lift either way.
		if matchedSink.OriginFile != "" {
			taintPath = append(taintPath,
				rules.TaintStep{
					File:  calleeNode.FilePath,
					Line:  matchedSink.Line,
					Kind:  rules.TaintStepPropagation,
					Label: fmt.Sprintf("forwarded by %s (inherited sink)", calleeNode.Name),
				},
				rules.TaintStep{
					File:  matchedSink.OriginFile,
					Line:  matchedSink.OriginLine,
					Kind:  rules.TaintStepSink,
					Label: fmt.Sprintf("%s (leaf sink lifted via %s)", sinkLabel, calleeNode.Name),
				},
			)
		} else {
			taintPath = append(taintPath, rules.TaintStep{
				File:  calleeNode.FilePath,
				Line:  matchedSink.Line,
				Kind:  rules.TaintStepSink,
				Label: fmt.Sprintf("%s (in %s)", sinkLabel, calleeNode.Name),
			})
		}

		findings = append(findings, rules.Finding{
			RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(matchedSink.SinkCategory))),
			Severity:      sev,
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
				"%s (arg %d) -> %s() -> %s %s",
				arg, argIdx, calleeNode.Name,
				matchedSink.MethodName, formatSinkLocation(*matchedSink, calleeNode.FilePath),
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize '%s' before passing it to %s(), or add sanitization inside %s() before the %s call.",
				arg, calleeNode.Name, calleeNode.Name, matchedSink.MethodName,
			),
			CWEID:           cwe,
			OWASPCategory:   owasp,
			Confidence:      "high",
			ConfidenceScore: 0.8,
			SourceCategory:  string(taint.SrcExternal),
			SinkCategory:    string(matchedSink.SinkCategory),
			Language:        cfg.findingLanguage(calleeNode),
			Tags: []string{
				"interprocedural", "taint-analysis", "cross-function",
				cfg.langTag(calleeNode), string(matchedSink.SinkCategory),
			},
		})
	}

	return findings
}

// crossfileCheckCallerUsesTaintedReturn is the shared Path B: triggers
// when the callee has tainted returns (whole-return, or field-sensitive
// return paths for field-enabled languages) and the caller passes the
// returned value into a sink.
func crossfileCheckCallerUsesTaintedReturn(
	cfg *crossfileWalkLangConfig,
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs crossfileCallSite,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
	sanGate *callerSanitizerGate,
) []rules.Finding {
	// A callee qualifies for Path B when it has EITHER whole-return taint
	// (legacy) OR — for field-enabled languages — field-sensitive tainted
	// return paths (an object-literal return with a tainted field).
	hasFieldReturnPaths := cfg.field != nil && len(calleeSig.TaintedReturnPaths) > 0
	if len(calleeSig.TaintedReturns) == 0 && !hasFieldReturnPaths {
		return nil
	}
	if isSanitizerByCalleeName(calleeNode.Name) {
		return nil
	}
	if isSanitizerByCalleeName(callerNode.Name) {
		return nil
	}
	returnVar := cs.assignedTo
	if returnVar == "" {
		// The return value isn't stored in a variable — it's either
		// consumed inline inside a sink argument on the call line
		// (`cp.exec(getA(req))`, handled by the inline path for languages
		// that enable it) or nested in a larger expression we can't
		// follow. Field-sensitive-only callees never qualify for the
		// inline path: an inline whole-object read can't target a
		// specific field path.
		if cfg.pathBInlineSink {
			if len(calleeSig.TaintedReturns) == 0 {
				return nil
			}
			return crossfileInlineReturnIntoSink(cfg, callerNode, calleeNode, calleeSig, cs, callLineNum, callerLines, callLineIdx)
		}
		return nil
	}
	// Field-sensitive mode: the callee taints only specific return-value
	// fields. The caller's sink must read one of those exact paths off the
	// return variable — `sink(r.user.id)` fires, `sink(r.name)` stays
	// silent. Whole-return callees skip this gate and keep the legacy
	// whole-variable behaviour.
	fieldSensitiveReturn := hasFieldReturnPaths

	var findings []rules.Finding
	patterns := cfg.loadSinkPatterns()
	calleeBase := extractBaseName(calleeNode.Name)

	// Search forward from the call site for a sink call mentioning
	// returnVar. Languages with pathBIncludesCallLine start AT the call
	// line (compact `const n = f(req); cp.exec(n);` idiom) with a
	// token-after-the-call gate; others start on the next line.
	start := callLineIdx + 1
	if cfg.pathBIncludesCallLine {
		start = callLineIdx
	}
	for i := start; i < len(callerLines); i++ {
		line := callerLines[i]
		if strings.HasPrefix(strings.TrimSpace(line), cfg.commentPrefix) {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if p.requireModule && p.module != "" && !strings.Contains(line, p.module) {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// On the call line, the sink must use returnVar at a position
			// after the call expression — otherwise it can't be consuming
			// this return value. The returnVar also appears as the
			// assignment LHS *before* the call, so we look for a whole-word
			// usage strictly after the call, not merely the first occurrence.
			if i == callLineIdx {
				callPos := strings.Index(line, calleeBase+"(")
				if callPos < 0 || !tokenAfter(line, returnVar, callPos) {
					continue
				}
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if cfg.sanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
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

			// Field-sensitive return gate: when the callee taints only
			// specific return fields, the sink line must read a field path
			// off returnVar that matches a tainted return path. A bare
			// `sink(r)` (whole-object read) only fires when the callee ALSO
			// has a whole-return source.
			if fieldSensitiveReturn {
				retFieldPath := cfg.field.sinkFieldPathForParam(line, returnVar)
				if retFieldPath == "" {
					if len(calleeSig.TaintedReturns) == 0 {
						continue
					}
				} else {
					composed := boundReturnPath("0", retFieldPath)
					if !returnPathTainted(composed, calleeSig.TaintedReturnPaths) {
						continue
					}
				}
			}

			sinkLineNum := callerNode.StartLine + i
			sev := severityForSinkCategory[p.category]
			if sev < rules.High {
				sev = rules.High
			}
			cwe := cweForSinkCategory[p.category]
			owasp := owaspForSinkCategory[p.category]

			srcCatLabel := "tainted"
			srcCatJSON := string(taint.SrcExternal)
			for _, cats := range calleeSig.TaintedReturns {
				if len(cats) > 0 {
					srcCatLabel = string(cats[0])
					srcCatJSON = string(cats[0])
					break
				}
			}
			if cfg.field != nil {
				for _, cats := range calleeSig.TaintedReturnPaths {
					if len(cats) > 0 {
						srcCatLabel = string(cats[0])
						srcCatJSON = string(cats[0])
						break
					}
				}
			}

			calleeBaseName := extractBaseName(calleeNode.Name)
			vulnKind := "cross-function"
			if cfg.pathBCrossFileVulnWording {
				vulnKind = "cross-file"
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
					Label: fmt.Sprintf("result of %s(...) assigned to %s", calleeBaseName, returnVar),
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
						"The caller %s() stores it in '%s' and passes it to %s at line %d "+
						"without sanitization, creating a %s %s vulnerability.",
					calleeNode.Name, callerNode.FilePath, callLineNum,
					srcCatLabel,
					callerNode.Name, returnVar, p.method, sinkLineNum,
					vulnKind, p.category,
				),
				FilePath:   callerNode.FilePath,
				LineNumber: sinkLineNum,
				MatchedText: fmt.Sprintf(
					"%s() -> %s -> %s (line %d)",
					calleeNode.Name, returnVar, p.method, sinkLineNum,
				),
				TaintPath: taintPath,
				Suggestion: fmt.Sprintf(
					"Sanitize '%s' (returned by %s()) before passing it to %s.",
					returnVar, calleeNode.Name, p.method,
				),
				CWEID:           cwe,
				OWASPCategory:   owasp,
				Confidence:      "high",
				ConfidenceScore: 0.8,
				SourceCategory:  srcCatJSON,
				SinkCategory:    string(p.category),
				Language:        cfg.findingLanguage(calleeNode),
				Tags: []string{
					"interprocedural", "taint-analysis", "cross-function",
					"return-taint", cfg.langTag(calleeNode), string(p.category),
				},
			})
		}
	}
	return findings
}

// crossfileInlineReturnIntoSink handles the inline 1-hop shape where the
// callee's tainted return value is consumed directly inside a sink
// argument on the call line, with no intervening variable —
// `cp.exec(getA(req))`. The assignment-based Path B scan can't fire here
// (cs.assignedTo is empty), so this helper inspects the single call
// line: if a sink pattern matches the line AND the sink's argument list
// contains the callee call (`calleeBase(`), the tainted return flows
// straight into the sink.
//
// Only whole-return-tainted callees reach this helper (the caller gates
// on len(TaintedReturns) > 0) — an inline whole-object read can't target
// a specific field path, so field-sensitive-only callees are excluded.
func crossfileInlineReturnIntoSink(
	cfg *crossfileWalkLangConfig,
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs crossfileCallSite,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
) []rules.Finding {
	if callLineIdx < 0 || callLineIdx >= len(callerLines) {
		return nil
	}
	line := callerLines[callLineIdx]
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, cfg.commentPrefix) {
		return nil
	}
	calleeBase := extractBaseName(calleeNode.Name)
	if calleeBase == "" {
		return nil
	}
	// The callee call must appear as a sink argument, i.e. text after the
	// sink's own opening paren. We require `calleeBase(` to occur on the
	// line; the sink pattern match plus the nesting check below confirm
	// the call is inside the sink expression.
	callTok := calleeBase + "("
	callPos := strings.Index(line, callTok)
	if callPos < 0 {
		return nil
	}

	var findings []rules.Finding
	patterns := cfg.loadSinkPatterns()
	for _, p := range patterns {
		loc := p.pattern.FindStringIndex(line)
		if loc == nil {
			continue
		}
		// The callee call must be nested inside the sink call: it has to
		// begin after the sink expression starts. A sink that appears AFTER
		// the callee call on the same line isn't consuming its return value.
		if callPos < loc[0] {
			continue
		}
		// A sanitizer on the same line neutralises the flow
		// (`cp.exec(escape(getA(req)))`).
		if cfg.sanitizerRe.MatchString(line) {
			continue
		}

		sinkLineNum := callerNode.StartLine + callLineIdx
		sev := severityForSinkCategory[p.category]
		if sev < rules.High {
			sev = rules.High
		}
		cwe := cweForSinkCategory[p.category]
		owasp := owaspForSinkCategory[p.category]

		srcCatLabel := "tainted"
		srcCatJSON := string(taint.SrcExternal)
		for _, cats := range calleeSig.TaintedReturns {
			if len(cats) > 0 {
				srcCatLabel = string(cats[0])
				srcCatJSON = string(cats[0])
				break
			}
		}

		calleeBaseName := calleeBase
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
				Label: fmt.Sprintf("result of %s(...) passed inline to %s", calleeBaseName, p.method),
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
					"The caller %s() passes it directly into %s without sanitization, "+
					"creating a cross-function %s vulnerability.",
				calleeNode.Name, callerNode.FilePath, callLineNum,
				srcCatLabel,
				callerNode.Name, p.method,
				p.category,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: sinkLineNum,
			MatchedText: fmt.Sprintf(
				"%s() -> %s (line %d)",
				calleeNode.Name, p.method, sinkLineNum,
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize the result of %s() before passing it to %s.",
				calleeNode.Name, p.method,
			),
			CWEID:           cwe,
			OWASPCategory:   owasp,
			Confidence:      "high",
			ConfidenceScore: 0.8,
			SourceCategory:  srcCatJSON,
			SinkCategory:    string(p.category),
			Language:        cfg.findingLanguage(calleeNode),
			Tags: []string{
				"interprocedural", "taint-analysis", "cross-function",
				"return-taint", cfg.langTag(calleeNode), string(p.category),
			},
		})
	}
	return findings
}

// crossfileIsArgTaintedInCaller checks whether argExpr is tainted in the
// caller's context: a source-typed caller param (root-form), a direct
// catalog source expression in the arg itself, or a backward trace
// through the caller's body to the nearest unconditional assignment of
// the arg's base variable (last-write-wins: a rebind that is neither
// sanitizer nor source kills any older tainted binding).
func crossfileIsArgTaintedInCaller(
	cfg *crossfileWalkLangConfig,
	argExpr string,
	callerLines []string,
	callLineIdx int,
	callerSig *TaintSignature,
) bool {
	argTrim := strings.TrimSpace(argExpr)
	if argTrim == "" {
		return false
	}

	// Caller typed Params + SourceParams: if argExpr is a source param
	// (root-form), it's tainted.
	if callerSig != nil && len(callerSig.SourceParams) > 0 && len(callerSig.Params) > 0 {
		root := crossfileArgRoot(cfg, argTrim)
		if cfg.rootIsSourceParam(root, callerSig) {
			return true
		}
	}

	// Direct catalog source expressions in the arg itself.
	if cfg.sourceExprRe.MatchString(argExpr) {
		return true
	}

	// Trace the argument backwards through the caller's body — look for
	// an assignment of the form `argVar = <source>`.
	argVar := crossfileArgRoot(cfg, argTrim)
	if argVar == "" {
		return false
	}
	for i := callLineIdx - 1; i >= 0; i-- {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)
		if crossfileIsCommentLine(cfg, line) {
			continue
		}
		if !containsToken(trimmed, argVar) {
			continue
		}
		// Locate the assignment `=`. Languages with a dedicated finder
		// (Lua/PHP) own their operator rejection; otherwise use the inline
		// first-`=` scan rejecting comparison operators (and, for Ruby, the
		// `=>` hash rocket).
		var eqIdx int
		if cfg.assignEqFinder != nil {
			eqIdx = cfg.assignEqFinder(trimmed)
			if eqIdx <= 0 {
				continue
			}
		} else {
			eqIdx = strings.Index(trimmed, "=")
			if eqIdx <= 0 {
				continue
			}
			// Reject comparison operators around `=`.
			prev := trimmed[eqIdx-1]
			if prev == '!' || prev == '<' || prev == '>' || prev == '=' {
				continue
			}
			if eqIdx+1 < len(trimmed) && trimmed[eqIdx+1] == '=' {
				continue
			}
			if cfg.rejectArrowAssign && eqIdx+1 < len(trimmed) && trimmed[eqIdx+1] == '>' {
				continue
			}
		}
		// LHS must mention argVar as a token, not just appear anywhere in
		// the line. Declarator keywords (const/let/var) are stripped first
		// for languages that use them.
		lhs := strings.TrimSpace(trimmed[:eqIdx])
		if len(cfg.stripDeclPrefixes) > 0 {
			for _, pfx := range cfg.stripDeclPrefixes {
				lhs = strings.TrimPrefix(lhs, pfx)
			}
			lhs = strings.TrimSpace(lhs)
		}
		if !containsToken(lhs, argVar) {
			continue
		}
		rhs := trimmed[eqIdx+1:]
		// Sanitizer between source and use: assignment passes through a
		// known sanitizer. Stop searching (this argument was sanitized).
		if cfg.sanitizerRe.MatchString(rhs) {
			return false
		}
		if cfg.sourceExprRe.MatchString(rhs) {
			return true
		}
		// Nearest rebind of argVar is neither sanitizer nor source (a
		// literal/constant/other local). Last-write-wins kills any older
		// tainted binding — stop here instead of scanning further up to a
		// stale source.
		return false
	}
	return false
}
