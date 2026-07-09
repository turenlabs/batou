package astflow

import (
	"sort"
	"strings"

	"github.com/turenlabs/batou-core/taint"
)

// taintState tracks the taint status of a single variable inside a function scope.
type taintState struct {
	varName    string
	source     *taint.SourceDef
	sourceLine int
	sanitized  map[taint.SinkCategory]bool
	confidence float64
	steps      []taint.FlowStep
}

// clone returns a deep copy with an appended flow step and confidence decay.
func (ts *taintState) clone(newVar string, line int, desc string, confDecay float64) *taintState {
	san := make(map[taint.SinkCategory]bool, len(ts.sanitized))
	for k, v := range ts.sanitized {
		san[k] = v
	}
	steps := make([]taint.FlowStep, len(ts.steps), len(ts.steps)+1)
	copy(steps, ts.steps)
	steps = append(steps, taint.FlowStep{
		Line:        line,
		Description: desc,
		VarName:     newVar,
	})
	return &taintState{
		varName:    newVar,
		source:     ts.source,
		sourceLine: ts.sourceLine,
		sanitized:  san,
		confidence: ts.confidence * confDecay,
		steps:      steps,
	}
}

// isTaintedFor returns true if the variable is tainted and NOT sanitized for cat.
func (ts *taintState) isTaintedFor(cat taint.SinkCategory) bool {
	if ts.source == nil {
		return false
	}
	return !ts.sanitized[cat]
}

// TaintMap tracks tainted variables within a single function scope.
type TaintMap struct {
	vars map[string]*taintState
	// matcher is the analysis-scoped catalog matcher. It lets exprIsTainted
	// resolve an UNBOUND inline source-call expression (e.g. the inner
	// `r.FormValue("x")` in `db.Query(r.FormValue("x"))`) by matching it as a
	// source directly, rather than only consulting already-bound variables.
	// The walker's source-seed (`__expr__`) is set as the walk descends, which
	// is too late for a sink (the outer call) checked on the same node before
	// its child source — so the sink/argument paths resolve inline sources by
	// matcher. May be nil (e.g. zero-value maps in tests); callers must
	// nil-check.
	matcher *CatalogMatcher

	// aliases records intra-function MUST-alias copies of object/struct refs:
	// a straight `b := a` (or `b = a`) where the RHS is a bare identifier names
	// the SAME underlying object under two variables, so a field write through
	// one (`b.Field = src`) is observable through a field read on the other
	// (`sink(a.Field)`). The edge is `aliasName -> targetName`. Resolution is
	// symmetric (aliasRoots walks both directions). It is must-alias, not
	// may-alias: ANY rebinding of an aliased name breaks its edges (breakAlias).
	// Scoped per function and reset alongside the rest of the map. This is the
	// astflow mirror of tsflow's taintMap.aliases — deliberately NOT
	// inter-procedural points-to.
	aliases map[string]string
}

// NewTaintMap creates an empty taint map.
func NewTaintMap() *TaintMap {
	return &TaintMap{vars: make(map[string]*taintState)}
}

// recordAlias records a must-alias copy `alias = target` (both bare idents
// naming the same object). Self-edges are ignored; a prior edge for alias is
// overwritten.
func (tm *TaintMap) recordAlias(alias, target string) {
	if alias == "" || target == "" || alias == target {
		return
	}
	if tm.aliases == nil {
		tm.aliases = make(map[string]string)
	}
	tm.aliases[alias] = target
}

// breakAlias removes any alias edges involving `name` as either endpoint.
// Called when `name` is rebound: the previous `b = a` copy no longer holds.
func (tm *TaintMap) breakAlias(name string) {
	if name == "" || len(tm.aliases) == 0 {
		return
	}
	delete(tm.aliases, name)
	for k, v := range tm.aliases {
		if v == name {
			delete(tm.aliases, k)
		}
	}
}

// aliasRoots returns the set of names must-alias-equivalent to root (including
// root). It follows alias edges in BOTH directions transitively, bounded by a
// visited set, and returns a deterministic (sorted) slice.
func (tm *TaintMap) aliasRoots(root string) []string {
	if root == "" {
		return nil
	}
	if len(tm.aliases) == 0 {
		return []string{root}
	}
	seen := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if t, ok := tm.aliases[cur]; ok && !seen[t] {
			seen[t] = true
			queue = append(queue, t)
		}
		for k, v := range tm.aliases {
			if v == cur && !seen[k] {
				seen[k] = true
				queue = append(queue, k)
			}
		}
	}
	roots := make([]string, 0, len(seen))
	for k := range seen {
		roots = append(roots, k)
	}
	sort.Strings(roots)
	return roots
}

// Set records taint state for a variable.
func (tm *TaintMap) Set(name string, ts *taintState) {
	tm.vars[name] = ts
}

// Get returns the taint state for a variable, or nil if not tracked.
func (tm *TaintMap) Get(name string) *taintState {
	return tm.vars[name]
}

// Has returns true if the variable is being tracked (tainted or derived).
func (tm *TaintMap) Has(name string) bool {
	_, ok := tm.vars[name]
	return ok
}

// fieldKey builds a shallow field-sensitive taint key of the form
// "varName.fieldName". Used when an assignment LHS or read targets
// obj.field rather than obj itself.
func fieldKey(varName, fieldName string) string {
	return varName + "." + fieldName
}

// AnyFieldTainted returns the first tainted *taintState whose key is of the
// form "varName.*" (any field of varName), or nil if none. Used at sinks
// that read the whole object — we conservatively over-approximate by
// assuming the sink might internally read any field.
func (tm *TaintMap) AnyFieldTainted(varName string) *taintState {
	prefix := varName + "."
	// Collect matching field keys and scan them in sorted order so which
	// tainted field is returned — and thus the source attributed to a sink that
	// reads the whole object — is deterministic, not Go map iteration order.
	var keys []string
	for k := range tm.vars {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if ts := tm.vars[k]; ts != nil && ts.source != nil {
			return ts
		}
	}
	return nil
}

// ClearFields removes all per-field taint entries for varName (keys of the
// form "varName.*"). Called when varName is rebound as a whole — the
// previous fields belong to the old binding.
func (tm *TaintMap) ClearFields(varName string) {
	prefix := varName + "."
	for k := range tm.vars {
		if strings.HasPrefix(k, prefix) {
			delete(tm.vars, k)
		}
	}
}
