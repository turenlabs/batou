// Per-language configs for the shared cross-file walk core
// (crossfile_walk_core.go).
//
// Phase 1 registered Python and JavaScript/TypeScript — the two reference
// implementations the shared core was extracted from. Phase 2 added Ruby,
// Lua, and PHP (the "Python-shaped" batch). Phase 3 added Kotlin, Groovy,
// Swift, and C# (the "JS-shaped" batch, no field sensitivity). Phase 4 adds
// the final, idiosyncratic batch — Perl, Shell, C/C++, and Rust — completing
// the consolidation: ALL 13 languages now run on the shared cross-file walk
// core. No per-language walker keeps its own AnalyzeCallerImpact clone.
//
// Each config only WIRES existing per-language machinery (regexes, sink
// loaders, ensure/seeding helpers, field-sensitivity hooks) into the
// shared template; no detection logic lives in this file.

package graph

import (
	"github.com/turenlabs/batou-rules/rules"
)

// pythonCrossfileWalkCfg wires the Python walker surface
// (crossfile_walk_python.go) into the shared core.
//
// Delta notes vs the shared defaults:
//   - No ensureCalleeReturns: the Python walker never seeded
//     TaintedReturns lazily (the extractor sets them for source-typed
//     return annotations).
//   - No bindingAlias / field hooks / inline Path B / call-line Path B.
//   - rootIsSourceParam keys SourceParams by the Params SLICE POSITION —
//     the historical Python behaviour (JS keys by ParamTaint.Index).
//   - findingLanguage pins rules.LangPython regardless of the callee
//     node's Language field (matches the historical hardcoded value).
var pythonCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:     "#",
	sourceExprRe:      pythonSourceExprRe,
	sanitizerRe:       pythonSanitizerRe,
	loadSinkPatterns:  loadPythonSinkPatterns,
	ensureCalleeSinks: ensurePythonCalleeSinks,
	findingLanguage:   func(*FuncNode) rules.Language { return rules.LangPython },
	langTag:           func(*FuncNode) string { return "python" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for paramIdx, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[paramIdx]; isSource {
				return true
			}
		}
		return false
	},
}

// javascriptCrossfileWalkCfg wires the JavaScript/TypeScript walker
// surface (crossfile_walk_javascript.go + crossfile_walk_javascript_field.go)
// into the shared core. JS and TS share one catalog and one config; the
// callee node's own Language distinguishes the two on emitted findings.
//
// Delta notes vs Python:
//   - ensureCalleeReturns seeds `return <source>` getters and
//     field-sensitive TaintedReturnPaths (object-literal returns).
//   - bindingAlias recovers CJS default-export / aliased-import local
//     binding names (jsCallerBindingAlias).
//   - pathBIncludesCallLine covers the compact
//     `const n = getName(req); cp.exec(n);` single-line idiom.
//   - pathBInlineSink covers `cp.exec(getA(req))` (no intervening var).
//   - field enables the ArgFieldPath / TaintedReturnPaths access-path
//     overlay (PR3 field sensitivity).
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (supports
//     destructured params sharing one index).
var javascriptCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        javascriptSourceExprRe,
	sanitizerRe:         javascriptSanitizerRe,
	loadSinkPatterns:    loadJavaScriptSinkPatterns,
	ensureCalleeSinks:   ensureJavaScriptCalleeSinks,
	ensureCalleeReturns: ensureJavaScriptCalleeReturns,
	bindingAlias:        jsCallerBindingAlias,
	findingLanguage:     func(calleeNode *FuncNode) rules.Language { return calleeNode.Language },
	langTag:             func(calleeNode *FuncNode) string { return jsLanguageTag(calleeNode.Language) },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	stripDeclPrefixes:     []string{"const ", "let ", "var "},
	pathBIncludesCallLine: true,
	pathBInlineSink:       true,
	field: &crossfileFieldHooks{
		buildCallerTaintedPaths: buildJavaScriptCallerTaintedPaths,
		callerArgFieldTainted:   javaScriptCallerArgFieldTainted,
		argRootDirectlyTainted:  jsArgRootIsDirectlyTainted,
		sinkFieldPathForParam:   jsSinkFieldPathForParam,
	},
}

// rubyCrossfileWalkCfg wires the Ruby walker surface
// (crossfile_walk_ruby.go) into the shared core. Both Path A and Path B
// fold in unchanged — Ruby's tainted-return handling is the shared
// forward-scan shape.
//
// Delta notes vs Python/JS:
//   - findingLanguage / langTag report the callee node's own language
//     (always Ruby) — matches the historical calleeNode.Language value.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style;
//     the historical isArgTaintedInRubyCaller matched p.Name then indexed
//     SourceParams[p.Index]).
//   - rejectArrowAssign: the backward trace skips `k => v` hash-rocket
//     lines, which the historical Ruby clone rejected explicitly.
//   - ensureCalleeReturns is nil (Ruby seeds no returns; tests plant them).
var rubyCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:     "#",
	sourceExprRe:      rubySourceExprRe,
	sanitizerRe:       rubySanitizerRe,
	loadSinkPatterns:  loadRubySinkPatterns,
	ensureCalleeSinks: ensureRubyCalleeSinks,
	findingLanguage:   func(n *FuncNode) rules.Language { return n.Language },
	langTag:           func(*FuncNode) string { return "ruby" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	rejectArrowAssign: true,
}

// luaCrossfileWalkCfg wires the Lua walker surface (crossfile_walk_lua.go)
// into the shared core. Path A folds in; Path B stays behind customPathB
// because Lua fires the inline-sink and via-variable cases independently
// for one call site (the shared Path B is XOR by returnVar) and applies a
// sink-line sanitizer gate the shared path lacks.
//
// Delta notes vs Python/JS:
//   - argRootFn = luaRootIdent (also strips `(` and `:` for `m.get_id` →
//     "m" and `db:query` receivers).
//   - assignEqFinder = luaAssignEq (rejects ==, ~=, <=, >=).
//   - ensureCalleeReturns = ensureLuaCalleeReturns seeds the OpenResty
//     `return ngx.var.*` getter idiom.
var luaCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "--",
	sourceExprRe:        luaSourceExprRe,
	sanitizerRe:         luaSanitizerRe,
	loadSinkPatterns:    loadLuaSinkPatterns,
	ensureCalleeSinks:   ensureLuaCalleeSinks,
	ensureCalleeReturns: ensureLuaCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "lua" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  luaRootIdent,
	assignEqFinder:             luaAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkLuaCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			luaCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// phpCrossfileWalkCfg wires the PHP walker surface (crossfile_walk_php.go)
// into the shared core. Path A folds in; Path B stays behind customPathB
// because PHP applies a sink-line sanitizer gate and decorates the return
// variable with a `$` sigil throughout its finding text.
//
// Delta notes vs Python/JS:
//   - argRootFn = phpArgRoot (strips `->` and the `$` sigil).
//   - assignEqFinder = phpAssignEq (rejects ==, ===, !=, <=, >=, =>, and
//     compound-assign operators like `.=`).
//   - isCommentLineFn = phpIsCommentLine (PHP has //, #, *, /* comments).
//   - calleeBaseNameFn = phpBaseName (strips `Cls::` scope and `\`
//     namespace so the Path A propagation label reads the bare method).
//   - rootIsSourceParam sigil-strips the param name before matching.
var phpCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//", // superseded by isCommentLineFn; kept for completeness
	sourceExprRe:        phpSourceExprRe,
	sanitizerRe:         phpSanitizerRe,
	loadSinkPatterns:    loadPHPSinkPatterns,
	ensureCalleeSinks:   ensurePHPCalleeSinks,
	ensureCalleeReturns: ensurePHPCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "php" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || phpStripSigil(p.Name) != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  phpArgRoot,
	assignEqFinder:             phpAssignEq,
	isCommentLineFn:            phpIsCommentLine,
	calleeBaseNameFn:           phpBaseName,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkPHPCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			phpCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// --- Batch 2 (Kotlin / Groovy / Swift / C#): the "JS-shaped" batch, no
// field sensitivity. Each folds Path A into the shared core; Path B stays
// per-language for the three languages whose tainted-return shape diverges
// (Kotlin's single-best-sink match, Groovy/Swift's two-case emit closure),
// while C#'s Path B — identical to the shared forward-scan except for one
// word — folds in via the pathBCrossFileVulnWording knob. ---

// kotlinCrossfileWalkCfg wires the Kotlin walker surface
// (crossfile_walk_kotlin.go) into the shared core.
//
// Delta notes vs Python/JS:
//   - argRootFn = kotlinRootIdent (strips `.` / `[` / `(` tails).
//   - assignEqFinder = kotlinAssignEq (only fires on `val`/`var`/plain-ident
//     assignments and rejects ==, =>, !=, <=, >=) — genuinely stricter than
//     the shared inline `=` scan, so it must be supplied.
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only ever emitted
//     the one-form "passed to X(...)" label.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style).
//   - ensureCalleeReturns = ensureKotlinCalleeReturns (Ktor/Spring getter
//     idiom) — also authoritatively clears Go-regex phantom returns.
//   - customPathB keeps checkKotlinCallerUsesTaintedReturn byte-identical:
//     it selects the SINGLE most-specific sink pattern per line
//     (kotlinBestSinkMatch) instead of iterating every matching pattern,
//     which the shared forward-scan can't reproduce without perturbing the
//     already-migrated languages.
var kotlinCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        kotlinSourceExprRe,
	sanitizerRe:         kotlinSanitizerRe,
	loadSinkPatterns:    loadKotlinSinkPatterns,
	ensureCalleeSinks:   ensureKotlinCalleeSinks,
	ensureCalleeReturns: ensureKotlinCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "kotlin" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  kotlinRootIdent,
	assignEqFinder:             kotlinAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkKotlinCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			kotlinCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// groovyCrossfileWalkCfg wires the Groovy walker surface
// (crossfile_walk_groovy.go) into the shared core.
//
// Delta notes vs Python/JS:
//   - argRootFn = groovyRootIdent (strips a `def ` prefix and `.`/`[`/`(`).
//   - assignEqFinder = groovyAssignEq (rejects ==, =~, =>, !=, <=, >=).
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only emitted the
//     one-form "passed to X(...)" label.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style).
//   - customPathB keeps checkGroovyCallerUsesTaintedReturn byte-identical: it
//     fires an inline-sink case AND a via-variable case independently for one
//     call site and carries the "cross-file … from another file in the
//     module" description text and a Groovy-specific suggestion, none of
//     which the shared forward-scan Path B reproduces.
var groovyCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        groovySourceExprRe,
	sanitizerRe:         groovySanitizerRe,
	loadSinkPatterns:    loadGroovySinkPatterns,
	ensureCalleeSinks:   ensureGroovyCalleeSinks,
	ensureCalleeReturns: ensureGroovyCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "groovy" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  groovyRootIdent,
	assignEqFinder:             groovyAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkGroovyCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			groovyCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// swiftCrossfileWalkCfg wires the Swift walker surface
// (crossfile_walk_swift.go) into the shared core.
//
// Delta notes vs Python/JS:
//   - argRootFn = swiftRootIdent (strips a `let `/`var ` prefix and the
//     `.`/`[`/`(`/`?`/`!` optional-chaining tail).
//   - assignEqFinder = swiftAssignEq (rejects ==, ===, !=, <=, >=).
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only emitted the
//     one-form "passed to X(...)" label.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style).
//   - customPathB keeps checkSwiftCallerUsesTaintedReturn byte-identical
//     (same inline + via-variable two-case shape as Groovy).
var swiftCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        swiftSourceExprRe,
	sanitizerRe:         swiftSanitizerRe,
	loadSinkPatterns:    loadSwiftSinkPatterns,
	ensureCalleeSinks:   ensureSwiftCalleeSinks,
	ensureCalleeReturns: ensureSwiftCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "swift" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  swiftRootIdent,
	assignEqFinder:             swiftAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkSwiftCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			swiftCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// csharpCrossfileWalkCfg wires the C# walker surface
// (crossfile_walk_csharp.go) into the shared core. Unlike the other three
// batch-2 languages, C#'s Path B IS the shared forward-scan shape, so it
// folds fully into crossfileCheckCallerUsesTaintedReturn (no customPathB).
//
// Delta notes vs Python/JS:
//   - argRootFn = csRootIdent (strips `.`/`[`/`(`).
//   - assignEqFinder = csAssignEq (rejects ==, =>, !=, <=, >=, and the
//     null-coalescing-assign ??= via a `?` prev-char guard).
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only emitted the
//     one-form "passed to X(...)" label.
//   - pathBIncludesCallLine: the pre-migration Path B started AT the call
//     line (compact `var n = GetName(req); Process.Start(n);` idiom).
//   - pathBCrossFileVulnWording: the pre-migration Path B Description said
//     "cross-file" rather than the shared default "cross-function".
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style).
var csharpCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        csharpSourceExprRe,
	sanitizerRe:         csharpSanitizerRe,
	loadSinkPatterns:    loadCSharpSinkPatterns,
	ensureCalleeSinks:   ensureCSharpCalleeSinks,
	ensureCalleeReturns: ensureCSharpCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "csharp" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  csRootIdent,
	assignEqFinder:             csAssignEq,
	pathAPropLabelPassedToOnly: true,
	pathBIncludesCallLine:      true,
	pathBCrossFileVulnWording:  true,
}

// --- Batch 4 (Perl / Shell / C-C++ / Rust): the final, idiosyncratic batch.
// Each folds Path A into the shared core (except Shell, whose Path A renders
// the callee WITHOUT call parentheses and so stays behind customPathA). Every
// language's Path B stays per-language behind customPathB: like Lua/Groovy,
// they fire the inline-sink and via-variable cases independently for one call
// site (the shared Path B is XOR by returnVar) and carry origin-specific
// wording ("used package" / "another file in the project" / "another
// translation unit" / "a linked module") the shared forward-scan can't
// reproduce without perturbing the already-migrated languages. ---

// perlCrossfileWalkCfg wires the Perl walker surface (crossfile_walk_perl.go)
// into the shared core.
//
// Delta notes vs Python/JS:
//   - argRootFn = perlRootIdent (strips the `$`/`@`/`%`/`\` sigil and the
//     `->method` / `[index]` / `{key}` / `(args)` tail).
//   - assignEqFinder = perlAssignEq (rejects ==, !=, <=, >=, =~, =>, and the
//     compound-assign operators like `.=`).
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only emitted the
//     one-form "passed to X(...)" label.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (the historical
//     isArgTaintedInPerlCaller matched p.Name then indexed SourceParams[p.Index]).
//   - customPathB keeps checkPerlCallerUsesTaintedReturn byte-identical.
var perlCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "#",
	sourceExprRe:        perlSourceExprRe,
	sanitizerRe:         perlSanitizerRe,
	loadSinkPatterns:    loadPerlSinkPatterns,
	ensureCalleeSinks:   ensurePerlCalleeSinks,
	ensureCalleeReturns: ensurePerlCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "perl" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  perlRootIdent,
	assignEqFinder:             perlAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkPerlCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			perlCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// shellCrossfileWalkCfg wires the Shell walker surface (crossfile_walk_shell.go)
// into the shared core. Shell is the ONLY language whose Path A also diverges:
// shell functions are invoked bare, so every Path A finding renders the callee
// as `foo`, not `foo()` (Title/Description/MatchedText/propagation label). No
// shared knob controls the paren suffix, so its Path A stays byte-identical
// behind customPathA. Path B stays behind customPathB (independent inline +
// via-variable emit, `$`-var sink matching via shellExpandsVar).
//
// Delta notes vs Python/JS:
//   - No argRootFn / assignEqFinder / rootIsSourceParam wiring is consumed:
//     both paths are custom, so the shared Path A / backward-trace never run.
//     rootIsSourceParam is still supplied for completeness.
var shellCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "#",
	sourceExprRe:        shellSourceExprRe,
	sanitizerRe:         shellSanitizerRe,
	loadSinkPatterns:    loadShellSinkPatterns,
	ensureCalleeSinks:   ensureShellCalleeSinks,
	ensureCalleeReturns: ensureShellCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "shell" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	customPathA: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkShellCallerPassesTaintToCallee(
			callerNode, calleeNode, calleeSig,
			shellCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkShellCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			shellCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// cppCrossfileWalkCfg wires the C-family walker surface (crossfile_walk_cpp.go)
// into the shared core. ONE config serves BOTH rules.LangC and rules.LangCPP:
// the ensure* helpers gate on isCPPFamily internally, findingLanguage reports
// the callee's own language, and the customPathB loads the sink catalog keyed
// on the callee's language (c_sinks.go vs cpp_sinks.go).
//
// Delta notes vs Python/JS:
//   - argRootFn = cppRootIdent (strips `&`/`*`, and the `.`/`->`/`::`/`[`/`(`
//     member-access / scope tail).
//   - assignEqFinder = cppAssignEq (rejects ==, !=, <=, >=, and the C/C++
//     compound-assign operators +=, -=, *=, /=, %=, &=, |=, ^=, ~=).
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only emitted the
//     one-form "passed to X(...)" label.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style).
//   - loadSinkPatterns is supplied defensively (LangCPP catalog); the shared
//     Path B never runs for C-family (customPathB owns it, with its own
//     language-keyed load).
//   - customPathB keeps checkCPPCallerUsesTaintedReturn byte-identical.
var cppCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        cppSourceExprRe,
	sanitizerRe:         cppSanitizerRe,
	loadSinkPatterns:    func() []crossfileSinkPattern { return loadCPPSinkPatterns(rules.LangCPP) },
	ensureCalleeSinks:   ensureCPPCalleeSinks,
	ensureCalleeReturns: ensureCPPCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "cpp" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  cppRootIdent,
	assignEqFinder:             cppAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkCPPCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			cppCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}

// rustCrossfileWalkCfg wires the Rust walker surface (crossfile_walk_rust.go)
// into the shared core.
//
// Delta notes vs Python/JS:
//   - argRootFn = rustRootIdent (strips a `&`/`&mut`/`mut ` prefix and the
//     `.`/`[`/`(`/`::` path tail).
//   - assignEqFinder = rustAssignEq (rejects ==, !=, <=, >=).
//   - pathAPropLabelPassedToOnly: the pre-migration Path A only emitted the
//     one-form "passed to X(...)" label.
//   - rootIsSourceParam keys SourceParams by ParamTaint.Index (JS-style).
//   - customPathB keeps checkRustCallerUsesTaintedReturn byte-identical: its
//     via-variable scan INCLUDES the call line with a token-after-the-call
//     gate and fires alongside the inline case, which the shared forward-scan
//     doesn't reproduce.
var rustCrossfileWalkCfg = &crossfileWalkLangConfig{
	commentPrefix:       "//",
	sourceExprRe:        rustSourceExprRe,
	sanitizerRe:         rustSanitizerRe,
	loadSinkPatterns:    loadRustSinkPatterns,
	ensureCalleeSinks:   ensureRustCalleeSinks,
	ensureCalleeReturns: ensureRustCalleeReturns,
	findingLanguage:     func(n *FuncNode) rules.Language { return n.Language },
	langTag:             func(*FuncNode) string { return "rust" },
	rootIsSourceParam: func(root string, callerSig *TaintSignature) bool {
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
		return false
	},
	argRootFn:                  rustRootIdent,
	assignEqFinder:             rustAssignEq,
	pathAPropLabelPassedToOnly: true,
	customPathB: func(callerNode, calleeNode *FuncNode, calleeSig *TaintSignature, cs crossfileCallSite, callLineNum int, callerLines []string, callLineIdx int, sanGate *callerSanitizerGate) []rules.Finding {
		return checkRustCallerUsesTaintedReturn(
			callerNode, calleeNode, calleeSig,
			rustCallSite(cs),
			callLineNum, callerLines, callLineIdx, sanGate,
		)
	},
}
