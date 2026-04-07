package tsflow

import "github.com/turenlabs/batou-core/taint"

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

// listTaintInfo tracks per-element taint for list/array variables.
// Elements are tracked by index; tainted[i] is non-nil if index i is tainted.
type listTaintInfo struct {
	elements []*taintState // per-index taint; nil = untainted/literal
	size     int           // current size (after add/remove operations)
}

// taintMap tracks tainted variables within a single function scope.
type taintMap struct {
	vars      map[string]*taintState
	lists     map[string]*listTaintInfo // per-index taint for list variables
	maps      map[string]*mapTaintInfo  // per-key taint for map variables
	consts    map[string]int64          // local integer constants (e.g., int num = 106)
	strConsts map[string]string         // local string constants (e.g., String guess = "ABC")
}

// newTaintMap creates an empty taint map.
func newTaintMap() *taintMap {
	return &taintMap{
		vars:      make(map[string]*taintState),
		lists:     make(map[string]*listTaintInfo),
		maps:      make(map[string]*mapTaintInfo),
		consts:    make(map[string]int64),
		strConsts: make(map[string]string),
	}
}

// listAdd records an element added to a list variable.
func (tm *taintMap) listAdd(listName string, ts *taintState) {
	li, ok := tm.lists[listName]
	if !ok {
		li = &listTaintInfo{}
		tm.lists[listName] = li
	}
	li.elements = append(li.elements, ts) // ts is nil for safe/literal elements
	li.size++
}

// listRemove removes the element at the given index, shifting subsequent elements.
func (tm *taintMap) listRemove(listName string, idx int) {
	li, ok := tm.lists[listName]
	if !ok || idx < 0 || idx >= li.size {
		return
	}
	if idx < len(li.elements) {
		li.elements = append(li.elements[:idx], li.elements[idx+1:]...)
	}
	li.size--
}

// listGet returns the taint state at a specific index, or nil if the index
// is untainted (literal element) or out of range.
func (tm *taintMap) listGet(listName string, idx int) *taintState {
	li, ok := tm.lists[listName]
	if !ok || idx < 0 || idx >= len(li.elements) {
		return nil
	}
	return li.elements[idx]
}

// mapTaintInfo tracks per-key taint for map/dict variables.
type mapTaintInfo struct {
	keys map[string]*taintState // key → taint state (nil = safe/literal)
}

// mapPut records a key-value pair in a map variable's taint tracker.
func (tm *taintMap) mapPut(mapName, key string, ts *taintState) {
	if tm.maps == nil {
		tm.maps = make(map[string]*mapTaintInfo)
	}
	mi, ok := tm.maps[mapName]
	if !ok {
		mi = &mapTaintInfo{keys: make(map[string]*taintState)}
		tm.maps[mapName] = mi
	}
	mi.keys[key] = ts
}

// mapGet returns the taint state for a specific key, or nil if the key
// is untainted. Returns (state, tracked) where tracked=true means we have
// per-key info for this map (so nil state means definitely safe).
func (tm *taintMap) mapGet(mapName, key string) (*taintState, bool) {
	if tm.maps == nil {
		return nil, false
	}
	mi, ok := tm.maps[mapName]
	if !ok {
		return nil, false
	}
	ts, exists := mi.keys[key]
	if !exists {
		return nil, false
	}
	return ts, true
}

// set records taint state for a variable.
func (tm *taintMap) set(name string, ts *taintState) {
	tm.vars[name] = ts
}

// get returns the taint state for a variable, or nil if not tracked.
func (tm *taintMap) get(name string) *taintState {
	return tm.vars[name]
}

// cloneMap returns a shallow copy of the taint map. Each entry still points
// to the same taintState (immutable in practice), but deleting or overwriting
// an entry in the clone does not affect the original.
func (tm *taintMap) cloneMap() *taintMap {
	cp := &taintMap{
		vars:      make(map[string]*taintState, len(tm.vars)),
		lists:     make(map[string]*listTaintInfo, len(tm.lists)),
		maps:      make(map[string]*mapTaintInfo, len(tm.maps)),
		consts:    make(map[string]int64, len(tm.consts)),
		strConsts: make(map[string]string, len(tm.strConsts)),
	}
	for k, v := range tm.vars {
		cp.vars[k] = v
	}
	for k, v := range tm.lists {
		elems := make([]*taintState, len(v.elements))
		copy(elems, v.elements)
		cp.lists[k] = &listTaintInfo{elements: elems, size: v.size}
	}
	for k, v := range tm.maps {
		keys := make(map[string]*taintState, len(v.keys))
		for kk, vv := range v.keys {
			keys[kk] = vv
		}
		cp.maps[k] = &mapTaintInfo{keys: keys}
	}
	for k, v := range tm.consts {
		cp.consts[k] = v
	}
	for k, v := range tm.strConsts {
		cp.strConsts[k] = v
	}
	return cp
}

// delete removes a variable from the taint map.
func (tm *taintMap) delete(name string) {
	delete(tm.vars, name)
}

// mergeFrom unions another taint map into this one. A variable is tainted
// if it is tainted in either map (conservative: assumes either branch could
// execute). When both maps have taint for the same variable, the one with
// higher confidence wins.
func (tm *taintMap) mergeFrom(other *taintMap) {
	for name, otherTs := range other.vars {
		existing := tm.vars[name]
		if existing == nil {
			tm.vars[name] = otherTs
		} else if otherTs.confidence > existing.confidence {
			tm.vars[name] = otherTs
		}
	}
}

// branchSingleWeight is the confidence multiplier applied to variables
// tainted in only one branch of an if/else. Variables tainted in both
// branches keep their full confidence.
const branchSingleWeight = 0.6

// replaceFrom overwrites this taint map with the contents of other.
func (tm *taintMap) replaceFrom(other *taintMap) {
	tm.vars = make(map[string]*taintState, len(other.vars))
	for k, v := range other.vars {
		tm.vars[k] = v
	}
}

// flowBuilder accumulates taint flows detected during analysis.
type flowBuilder struct {
	flows    []taint.TaintFlow
	filePath string
}

func newFlowBuilder(filePath string) *flowBuilder {
	return &flowBuilder{filePath: filePath}
}

// mergeBranchFlows merges flows from two branches. Flows that appear in
// both branches (same sink line + CWE) are kept at full confidence.
// Flows only in one branch get decayed confidence (branchSingleWeight).
func mergeBranchFlows(ifFlows, elseFlows []taint.TaintFlow) []taint.TaintFlow {
	type flowKey struct {
		SinkLine int
		CWE      string
	}

	// Index else-branch flows by (sinkLine, CWE).
	elseIdx := make(map[flowKey]bool, len(elseFlows))
	for _, f := range elseFlows {
		elseIdx[flowKey{f.SinkLine, f.Sink.CWEID}] = true
	}

	// Index if-branch flows by (sinkLine, CWE).
	ifIdx := make(map[flowKey]bool, len(ifFlows))
	for _, f := range ifFlows {
		ifIdx[flowKey{f.SinkLine, f.Sink.CWEID}] = true
	}

	var merged []taint.TaintFlow

	// Process if-branch flows.
	for _, f := range ifFlows {
		key := flowKey{f.SinkLine, f.Sink.CWEID}
		if elseIdx[key] {
			// Flow in both branches — keep full confidence.
			merged = append(merged, f)
		} else {
			// Only in if-branch — decay confidence.
			f.Confidence *= branchSingleWeight
			merged = append(merged, f)
		}
	}

	// Process else-branch flows not already in if-branch.
	for _, f := range elseFlows {
		key := flowKey{f.SinkLine, f.Sink.CWEID}
		if !ifIdx[key] {
			// Only in else-branch — decay confidence.
			f.Confidence *= branchSingleWeight
			merged = append(merged, f)
		}
	}

	return merged
}

func (fb *flowBuilder) addFlow(ts *taintState, sink *taint.SinkDef, sinkLine int, scopeName string) {
	flow := taint.TaintFlow{
		Source:     *ts.source,
		Sink:       *sink,
		SourceLine: ts.sourceLine,
		SinkLine:   sinkLine,
		Steps:      ts.steps,
		FilePath:   fb.filePath,
		ScopeName:  scopeName,
		Confidence: ts.confidence,
	}
	fb.flows = append(fb.flows, flow)
}
