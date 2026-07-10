package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Cross-method / cross-function STORED-STATE taint (the third propagation
// channel).
//
// tsflow's TaintSummary models param->return threading only. Two pervasive
// shapes were therefore silently dropped — taint stored in one scope and read
// in another (a missed detection in every engine):
//
//	# instance field (the canonical OO web-handler vuln)
//	class H:
//	    def a(self): self.q = request.args.get('q')   # write in method A
//	    def b(self): cursor.execute(self.q)           # read in method B  -> MISSED
//
//	# module global
//	g = None
//	def store(): global g; g = request.args.get('q') # write in function A
//	def use():   cursor.execute(g)                    # read in function B -> MISSED
//
// Fix: a bounded file-level side-table. Pass 1.5 walks every function body and
// the module top level, harvesting which instance-field keys (`self.x`,
// `this.x`) and which module-global names receive a TAINTED write in ANY scope.
// Pass 2 then seeds those keys into every scope's taint map, so the existing
// (already field-sensitive) intra-scope read+sink machinery surfaces the flow.
//
// This is NOT whole-program points-to. It is:
//   - field-sensitive: `self.x` is a distinct key from `self.y` — a field that
//     only ever receives a constant write never becomes a source (FP discipline);
//   - may-analysis: a field written with taint in any method taints its reads
//     in every method (conservative, mirrors the within-scope field model);
//   - scoped to a single file: cross-file carrying is left to Layer 4, which
//     already bridges field/global writes via the call-graph machinery.

// storedTaint is the per-file side-table of instance-field and module-global
// keys that receive a tainted write somewhere in the file. Each key maps to a
// representative taintState template used to seed reader scopes.
type storedTaint struct {
	// fields keys instance-field access paths (`self.q`, `this.data`) to a
	// representative tainted state. The base segment is always an instance
	// receiver name (cfg.instanceReceivers), so the key is stable across the
	// methods of a class — unlike a function-local `obj.attr`.
	fields map[string]*storedEntry
	// globals keys module-global variable names (`g`) to a representative
	// tainted state. Only names confirmed to be module globals (written at
	// module top level, or under a Python `global` declaration) are recorded,
	// so a function's local variable of the same name is never auto-tainted.
	globals map[string]*storedEntry
}

// storedEntry captures the minimum needed to reconstruct a seed taintState for
// a stored field/global: the source, its line, the in-writer step trail, the
// categories sanitized on the write path, and the writer scope name (for the
// step description). The highest-confidence tainted writer for a given key
// wins (may-analysis: any tainted writer makes the key a source).
type storedEntry struct {
	source     *taint.SourceDef
	sourceLine int
	confidence float64
	sanitized  map[taint.SinkCategory]bool
	steps      []taint.FlowStep
	writer     string
}

func newStoredTaint() *storedTaint {
	return &storedTaint{
		fields:  make(map[string]*storedEntry),
		globals: make(map[string]*storedEntry),
	}
}

func (st *storedTaint) empty() bool {
	return st == nil || (len(st.fields) == 0 && len(st.globals) == 0)
}

// recordField records (may-merge) a tainted write to an instance-field key.
// The higher-confidence writer wins so the seeded read carries the strongest
// representative flow; either way the key becomes a source.
func (st *storedTaint) recordField(key string, e *storedEntry) {
	if prev, ok := st.fields[key]; !ok || e.confidence > prev.confidence {
		st.fields[key] = e
	}
}

// recordGlobal records (may-merge) a tainted write to a module-global name.
func (st *storedTaint) recordGlobal(name string, e *storedEntry) {
	if prev, ok := st.globals[name]; !ok || e.confidence > prev.confidence {
		st.globals[name] = e
	}
}

// supportsStoredStateChannel gates the third channel to the languages whose
// tsflow config ALREADY supports shallow field-sensitive LHS keys (`self.x` /
// `this.x` → a distinct taint-map key) AND that carry a clear instance-receiver
// token. The required set is Python, JS/TS, Java; C# and Rust qualify on the
// same machinery (their extractAssignLHS returns dotted field keys). Languages
// whose extractAssignLHS collapses a field write to the bare receiver
// (Kotlin/Swift: simple_identifier only) or has no field-key path (PHP `$this->x`,
// C/C++) are intentionally excluded — for them this change is a no-op.
func supportsStoredStateChannel(lang rules.Language) bool {
	switch lang {
	case rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangCSharp, rules.LangRust:
		return true
	}
	return false
}

// SupportsStoredStateChannel reports whether tsflow's intra-file stored-state
// channel (this file) covers the language — i.e. a same-file cross-method
// instance-field flow is already surfaced by the Layer-3 walk. The graph
// package's stored-state pass uses this to decide which languages need the
// SAME-FILE cross-method join at Layer 4 (only those NOT covered here), so the
// two channels never double-report one flow.
func SupportsStoredStateChannel(lang rules.Language) bool {
	return supportsStoredStateChannel(lang)
}

// collectStoredFieldTaint is pass 1.5: it harvests the file-level stored-state
// side-table. For every function body (and the module top level) it runs a
// seeded body walk and inspects the resulting taint map for:
//   - instance-field keys (`self.x`, `this.x`) carrying a fromFieldAssign taint
//   - module-global names (collected separately) carrying a bare taint
//
// The walk reuses the real walkBodyInterproc with summaries, so catalog
// sources, sanitizers, branch decay and the strong-update kill all apply — a
// field written only with a constant (or sanitized) value never lands here.
func collectStoredFieldTaint(funcNodes []*ast.Node, root *ast.Node, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary, moduleConstContainers map[string]bool) *storedTaint {
	st := newStoredTaint()
	if cfg == nil || !supportsStoredStateChannel(cfg.language) {
		return st
	}

	// Module-global names: the set of bare identifiers that are genuine module
	// globals (written at file scope, or declared `global g` in a function).
	// Only these are eligible for the global channel — a same-named function
	// local is never auto-tainted.
	globalNames := collectModuleGlobalNames(root, funcNodes, cfg)

	harvest := func(body *ast.Node, scopeName string) {
		if body == nil {
			return
		}
		tm := newTaintMap()
		for name := range moduleConstContainers {
			tm.constContainers[name] = true
		}
		// NOTE: parameters are deliberately NOT seeded here. A field written
		// from a parameter (`def __init__(self, data): self._store = data`) is
		// NOT file-level stored taint — the value is the caller's, and the
		// param->return summary + call-site interprocedural logic already model
		// it. Promoting such a field to a file-level source would re-taint every
		// read of it in every method (the Django `__init__(self, data)` ->
		// `self._store` over-taint). Only a write whose RHS is a GENUINE catalog
		// source (request.args, etc.) makes a field/global a stored source —
		// enforced by the isSyntheticParamSource filter below.
		fb := newFlowBuilder("")
		walkBodyInterproc(body, tm, cfg, matcher, scopeName, fb, summaries)

		for key, ts := range tm.vars {
			if ts == nil || ts.source == nil || isSyntheticParamSource(ts.source) {
				continue
			}
			base, isField := isFieldKey(key)
			if isField {
				// Instance fields only: the base must be a stable receiver
				// token (self/this/...), and the write must be an explicit
				// field assignment (fromFieldAssign) — not a `request.args`
				// source-attribute marker.
				if !cfg.instanceReceivers[base] || !ts.fromFieldAssign {
					continue
				}
				st.recordField(key, storedEntryFrom(ts, scopeName))
				continue
			}
			// Bare name: only a confirmed module global qualifies.
			if globalNames[key] {
				st.recordGlobal(key, storedEntryFrom(ts, scopeName))
			}
		}
	}

	for _, fnNode := range funcNodes {
		name := cfg.extractFuncName(fnNode)
		if name == "" {
			name = "__anonymous__"
		}
		harvest(cfg.extractFuncBody(fnNode), name)
	}
	// Module top level: writes here (e.g. `g = request.args.get('q')` at file
	// scope) also seed the global channel.
	if root != nil {
		st.harvestTopLevel(root, cfg, matcher, summaries, moduleConstContainers, globalNames)
	}

	return st
}

// harvestTopLevel walks the module top-level statements (skipping function and
// class bodies, which are harvested per-scope) and records tainted module-global
// writes.
func (st *storedTaint) harvestTopLevel(root *ast.Node, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary, moduleConstContainers map[string]bool, globalNames map[string]bool) {
	tm := newTaintMap()
	for name := range moduleConstContainers {
		tm.constContainers[name] = true
	}
	fb := newFlowBuilder("")
	for i := 0; i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil || !child.IsNamed() {
			continue
		}
		if cfg.funcTypes[child.Type()] || cfg.classTypes[child.Type()] {
			continue
		}
		walkBodyInterproc(child, tm, cfg, matcher, "__toplevel__", fb, summaries)
	}
	for key, ts := range tm.vars {
		if ts == nil || ts.source == nil || isSyntheticParamSource(ts.source) {
			continue
		}
		if _, isField := isFieldKey(key); isField {
			continue
		}
		if globalNames[key] {
			st.recordGlobal(key, storedEntryFrom(ts, "__toplevel__"))
		}
	}
}

// isSyntheticParamSource reports whether a source is a SYNTHETIC parameter
// source — the marker the summary/seed passes inject to model "this parameter
// could be tainted by some caller" (`param.<i>.<name>` / `<lang>.param.<name>`,
// MethodName `parameter:<name>`). Such a source is taint RELATIVE to a caller,
// not a genuine external read, so a field/global written from it must NOT be
// promoted to a file-level stored source — that is what the param->return
// summary + interprocedural call-site logic already handle. Genuine catalog
// sources (request.args, sys.argv, …) are not param-shaped and pass this gate.
func isSyntheticParamSource(src *taint.SourceDef) bool {
	if src == nil {
		return false
	}
	if strings.HasPrefix(src.MethodName, "parameter:") {
		return true
	}
	// ID forms: "param.0.data" (pass-1 summary seed) and "<lang>.param.<name>"
	// (seedParams handler seed). Match both without false-positiving on a real
	// catalog ID that merely contains the substring elsewhere.
	if strings.HasPrefix(src.ID, "param.") || strings.Contains(src.ID, ".param.") {
		return true
	}
	return false
}

// storedEntryFrom builds a side-table entry from a harvested taint state,
// deep-copying the mutable maps/slices so later per-call-site mutation never
// aliases the shared template.
func storedEntryFrom(ts *taintState, writer string) *storedEntry {
	san := make(map[taint.SinkCategory]bool, len(ts.sanitized))
	for k, v := range ts.sanitized {
		san[k] = v
	}
	steps := make([]taint.FlowStep, len(ts.steps))
	copy(steps, ts.steps)
	return &storedEntry{
		source:     ts.source,
		sourceLine: ts.sourceLine,
		confidence: ts.confidence,
		sanitized:  san,
		steps:      steps,
		writer:     writer,
	}
}

// seedTaintState materializes a fresh taintState to seed into a reader scope's
// taint map. The mutable fields are copied so the seeded entry is independent
// of the shared template and of other scopes' seeds.
func (e *storedEntry) seedTaintState(key string) *taintState {
	_, isField := isFieldKey(key)
	san := make(map[taint.SinkCategory]bool, len(e.sanitized))
	for k, v := range e.sanitized {
		san[k] = v
	}
	steps := make([]taint.FlowStep, len(e.steps), len(e.steps)+1)
	copy(steps, e.steps)
	steps = append(steps, taint.FlowStep{
		Line:        e.sourceLine,
		Description: "stored in " + key + " by " + e.writer + "()",
		VarName:     key,
	})
	return &taintState{
		varName:    key,
		source:     e.source,
		sourceLine: e.sourceLine,
		sanitized:  san,
		confidence: e.confidence,
		steps:      steps,
		// A field key (`self.x`) is stamped fromFieldAssign so anyFieldTainted
		// surfaces it at a bare-object read; the bare-name global path leaves it
		// false. The seed is conceptually "present on entry on every path", so
		// mark it setUnconditionally — a later UNCONDITIONAL safe rebinding of a
		// bare global (`g = "safe"; sink(g)`) then strong-updates the seed away
		// (the read uses the local-safe value, not the stored global). Field
		// keys are excluded from the bare-var strong-update gate in
		// processAssignInterproc, so this flag only affects the global channel.
		fromFieldAssign:    isField,
		setUnconditionally: true,
	}
}

// seedStoredFieldState seeds the per-scope taint map with the file-level
// instance-field stored taints (all of them — a method may read any field of
// `self`) and the module globals that are NOT shadowed by a parameter of this
// scope. Called at the start of each reader scope's pass-2 walk, BEFORE the
// body is walked, so a local rebinding (`self.x = "safe"` / `g = "safe"`)
// earlier in the body still strong-updates the seeded entry away.
func seedStoredFieldState(tm *taintMap, fnNode *ast.Node, cfg *langConfig, st *storedTaint) {
	if st.empty() || tm == nil {
		return
	}
	// Instance fields: seed every recorded field key. A field key is
	// receiver-qualified (`self.x`), so it can never collide with a parameter
	// or local of this scope.
	for key, e := range st.fields {
		if existing := tm.get(key); existing != nil && existing.source != nil {
			continue // an in-scope write already established taint; don't clobber
		}
		tm.set(key, e.seedTaintState(key))
	}

	// Module globals: seed only names not shadowed by a parameter of this
	// function (a parameter binding is the reader's own input, not the global).
	if len(st.globals) > 0 {
		params := map[string]bool{}
		if fnNode != nil {
			for _, p := range cfg.extractFuncParams(fnNode) {
				params[strings.TrimPrefix(p, "$")] = true
				params[p] = true
			}
		}
		for name, e := range st.globals {
			if params[name] {
				continue
			}
			if existing := tm.get(name); existing != nil && existing.source != nil {
				continue
			}
			tm.set(name, e.seedTaintState(name))
		}
	}
}

// collectModuleGlobalNames returns the set of bare identifier names that are
// genuine module globals for the file: names assigned at module top level, plus
// names declared via a Python `global <name>` statement inside any function.
// This is the gate that keeps the global channel from auto-tainting an
// unrelated function-local of the same name.
func collectModuleGlobalNames(root *ast.Node, funcNodes []*ast.Node, cfg *langConfig) map[string]bool {
	out := make(map[string]bool)
	if root == nil || cfg == nil {
		return out
	}
	// Top-level assignments: `g = ...` at module scope.
	record := func(node *ast.Node) {
		if node == nil || !node.IsNamed() {
			return
		}
		if !cfg.assignTypes[node.Type()] && !cfg.varDeclTypes[node.Type()] {
			return
		}
		lhs := cfg.extractAssignLHS(node)
		if lhs == "" {
			return
		}
		if _, isField := isFieldKey(lhs); isField {
			return
		}
		// Strip subscripts / quoted keys — only plain identifiers are globals.
		if !isPlainIdent(lhs) {
			return
		}
		out[lhs] = true
	}
	for i := 0; i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil || !child.IsNamed() {
			continue
		}
		if cfg.funcTypes[child.Type()] || cfg.classTypes[child.Type()] {
			continue
		}
		record(child)
		for j := 0; j < child.ChildCount(); j++ {
			record(child.Child(j))
		}
	}
	// Python `global g` declarations inside functions: these name a module
	// global that the function intends to write.
	if cfg.language == rules.LangPython {
		for _, fnNode := range funcNodes {
			body := cfg.extractFuncBody(fnNode)
			if body == nil {
				continue
			}
			body.Walk(func(n *ast.Node) bool {
				if n.Type() == "global_statement" {
					for i := 0; i < n.ChildCount(); i++ {
						c := n.Child(i)
						if c.IsNamed() && c.Type() == "identifier" {
							out[c.Text()] = true
						}
					}
				}
				return true
			})
		}
	}
	return out
}

// isPlainIdent reports whether s is a single plain identifier (no dots, no
// brackets, no quotes) — used to filter module-global candidate names.
func isPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == '$' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}
