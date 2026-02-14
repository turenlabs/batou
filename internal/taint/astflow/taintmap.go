package astflow

import "github.com/turenio/gtss/internal/taint"

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
}

// NewTaintMap creates an empty taint map.
func NewTaintMap() *TaintMap {
	return &TaintMap{vars: make(map[string]*taintState)}
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
