package tsflow

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

	// urlParsedFrom records the original tainted variable name when this
	// state was produced by a URL parser (urllib.parse.urlparse,
	// urllib.parse.urlsplit, …). When a downstream guard validates one of
	// the URL parts (`url.netloc not in [...]` etc.) the engine can
	// back-propagate the URL-injection sanitization to that origin
	// variable, since validating one side of a URL parse / unparse pair
	// guarantees the parsed input is well-formed for that category.
	urlParsedFrom string

	// pathDerivedFrom records the original tainted variable name when this
	// state was produced by a Python path canonicaliser (os.path.normpath,
	// os.path.realpath, os.path.abspath, pathlib.Path(...).resolve()).
	// Those calls only canonicalise — they are not sanitizers on their own.
	// When a downstream containment guard validates the canonicalised value
	// (`x.startswith(BASE)`, `x.is_relative_to(BASE)`,
	// `commonpath([BASE, x]) == BASE`, …) the engine back-propagates the
	// path-category sanitisation to this origin so a later use of the
	// original tainted variable in a file sink is also cleared. Mirrors
	// urlParsedFrom for the path-traversal domain (PR-HHpy / Go PR-HH).
	pathDerivedFrom string

	// fromFieldAssign marks a taint entry as having been produced by an
	// explicit field assignment (`obj.attr = source()` or equivalent).
	// Distinguishes "a field of obj now carries a tainted value" from the
	// pre-existing pattern where source-attribute keys (e.g. `request.args`)
	// are stored to make sink lookups recognise the source. Only entries
	// with fromFieldAssign=true are surfaced by anyFieldTainted, so bare
	// `request` reads don't over-trigger on every `request.<source>` match.
	fromFieldAssign bool

	// setUnconditionally marks a bare-variable taint entry that was assigned
	// by a statement which runs on every path through its enclosing function
	// (not nested in any if/for/while/try/with/match arm). It is the prior
	// half of the Python strong-update gate: a later UNCONDITIONAL assignment
	// of an untainted value is allowed to clear this entry (last-write-wins)
	// only when the prior taint was itself set unconditionally. This kills the
	// OWASP dict/list-shuffle SAFE pattern (`bar = map['keyB']; bar =
	// map['keyA']`) without disturbing match-statement TPs whose arms are
	// conditional. See isUnconditionalAssign in walker.go.
	setUnconditionally bool
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
		varName:            newVar,
		source:             ts.source,
		sourceLine:         ts.sourceLine,
		sanitized:          san,
		confidence:         ts.confidence * confDecay,
		steps:              steps,
		urlParsedFrom:      ts.urlParsedFrom,
		pathDerivedFrom:    ts.pathDerivedFrom,
		fromFieldAssign:    ts.fromFieldAssign,
		setUnconditionally: ts.setUnconditionally,
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
	// containerWriters records receiver variables that were created via a
	// known stateful container constructor (e.g. configparser.ConfigParser()).
	// When a downstream three-argument `.set(section, key, tainted)` lands
	// on one of these receivers, taint the receiver as a whole — a later
	// `.get(section, key)` will then propagate. Gating on this set keeps
	// the .set tracking precise enough to avoid over-tainting generic
	// `widget.set('attr', value)` patterns.
	containerWriters map[string]bool

	// constContainers records variables bound to a literal dict / set / list
	// whose values / elements are themselves constants. A subsequent indexing
	// or `.get(<tainted>)` on such a container returns one of the constant
	// values — the tainted key was used only as a selector, so the result is
	// not user-controlled. Used to suppress taint propagation through
	// `expr = ALLOWED_OPS.get(op_name)`-style constant lookup tables (see
	// CVE-2023-50447 Pillow ImageMath safe pattern).
	constContainers map[string]bool

	// freshLocalEmpty records local variables declared with an empty
	// container RHS (`const obj = {}`, `let arr = []`, `Object.create(null)`,
	// `new Object()`). When a downstream merge-style prototype-pollution
	// sink (`Object.assign`, `_.merge`, `_.defaultsDeep`, `Hoek.merge`, …)
	// uses one of these variables as its destination (arg 0), the call
	// cannot pollute the global prototype chain: the fresh local object's
	// prototype is Object.prototype but any writes via __proto__ would
	// affect the local object only — the original CVE bait shape (e.g.
	// `_.set(obj, "__proto__.x", v)` with a user-controlled path) is
	// handled separately and NOT suppressed by this map.
	// Cleared on any subsequent assignment to the same name so reassigned
	// locals don't accidentally remain "fresh".
	freshLocalEmpty map[string]bool

	// hardenedReceivers records receiver variables on which a
	// receiver-state-hardening sanitizer call was observed earlier in the
	// same function body. Some sanitization patterns don't return a new
	// value but instead modify the receiver — examples in Java:
	//   xs.allowTypes(new Class[]{Foo.class})       // SnkDeserialize
	//   xs.addPermission(NoTypePermission.NONE)    // SnkDeserialize
	//   factory.setFeature("...disallow-doctype-decl", true)  // SnkXPath (XXE)
	//   factory.setFeature(FEATURE_SECURE_PROCESSING, true)  // SnkXPath (XXE)
	// When a downstream sink call uses one of these receivers, the call is
	// safe for the recorded categories. The catalog already lists these as
	// sanitizers (java.xstream.allowtypes, java.dbf.disallow.doctype, …)
	// but they previously had no effect because the call has no LHS to
	// receive the sanitized value. Populated by the same matchSanitizer
	// path that handles assignment-RHS sanitizers; consulted in
	// processCallInterproc before firing a sink.
	hardenedReceivers map[string]map[taint.SinkCategory]bool

	// bodyCategorySuppress records sink categories that should be suppressed
	// across the whole function body because the body contains a clear
	// hardening guard for that category (e.g. an SSRF host-allowlist check).
	// Used when the safety is encoded as a flow-control guard rather than as
	// a per-call sanitizer — the developer's intent is clear from the guard's
	// presence, even if individual sink calls precede or are unreachable
	// from the guard at flow-sensitive analysis. Currently populated only by
	// seedJavaBodyHardening for SnkURLFetch / SnkRedirect.
	bodyCategorySuppress map[taint.SinkCategory]bool

	// aliases records intra-function MUST-alias copies of object/struct
	// references: a direct `b = a` (or `let b = a`) where the RHS is a bare
	// identifier names the SAME underlying object under two variables, so a
	// field write through one name (`b.field = src`) is observable through a
	// field read on the other (`sink(a.field)`). The edge is `aliasName ->
	// targetName` (`aliases["b"] == "a"`). Membership is symmetric for the
	// purpose of field-key resolution (aliasRoots walks both forward and
	// reverse edges) because a must-alias copy makes the two names
	// interchangeable for the object they both bind.
	//
	// This is deliberately NOT inter-procedural points-to / Andersen analysis:
	// it only tracks the syntactic `b = a` copy within one function scope, it
	// is must-alias (not may-alias), and ANY reassignment of an aliased name
	// breaks its edge (the new RHS may bind a different object — see
	// breakAlias). The alias map is reset per function scope alongside the
	// rest of the taint map.
	aliases map[string]string
}

// newTaintMap creates an empty taint map.
func newTaintMap() *taintMap {
	return &taintMap{
		vars:                 make(map[string]*taintState),
		lists:                make(map[string]*listTaintInfo),
		maps:                 make(map[string]*mapTaintInfo),
		consts:               make(map[string]int64),
		strConsts:            make(map[string]string),
		containerWriters:     make(map[string]bool),
		constContainers:      make(map[string]bool),
		freshLocalEmpty:      make(map[string]bool),
		hardenedReceivers:    make(map[string]map[taint.SinkCategory]bool),
		bodyCategorySuppress: make(map[taint.SinkCategory]bool),
		aliases:              make(map[string]string),
	}
}

// markBodySuppressCategory records that the given sink category should be
// suppressed across the whole function body. Use sparingly — only for
// categories where the presence of a hardening guard implies the developer's
// intent to validate (e.g. SSRF host-allowlist check anywhere in the body
// implies any URI-derived sink in the body is being validated).
func (tm *taintMap) markBodySuppressCategory(cat taint.SinkCategory) {
	if tm.bodyCategorySuppress == nil {
		tm.bodyCategorySuppress = make(map[taint.SinkCategory]bool)
	}
	tm.bodyCategorySuppress[cat] = true
}

// isBodySuppressedCategory returns true if any body-scope guard previously
// marked this category as suppressed.
func (tm *taintMap) isBodySuppressedCategory(cat taint.SinkCategory) bool {
	if tm.bodyCategorySuppress == nil {
		return false
	}
	return tm.bodyCategorySuppress[cat]
}

// markReceiverHardened records that the given receiver variable was hardened
// against the given sink categories by a side-effecting sanitizer call
// earlier in the current function body. A subsequent sink call on the same
// receiver will be suppressed for those categories. Used for receiver-state
// hardening shapes the catalog cannot express via the regular
// assignment-RHS sanitizer mechanism (e.g. `xs.allowTypes(...)` in Java).
func (tm *taintMap) markReceiverHardened(receiver string, cats []taint.SinkCategory) {
	if receiver == "" || len(cats) == 0 {
		return
	}
	if tm.hardenedReceivers == nil {
		tm.hardenedReceivers = make(map[string]map[taint.SinkCategory]bool)
	}
	m, ok := tm.hardenedReceivers[receiver]
	if !ok {
		m = make(map[taint.SinkCategory]bool, len(cats))
		tm.hardenedReceivers[receiver] = m
	}
	for _, c := range cats {
		m[c] = true
	}
}

// isReceiverHardened returns true if the receiver was previously hardened
// against the given sink category in the current function body.
func (tm *taintMap) isReceiverHardened(receiver string, cat taint.SinkCategory) bool {
	if receiver == "" || tm.hardenedReceivers == nil {
		return false
	}
	m, ok := tm.hardenedReceivers[receiver]
	if !ok {
		return false
	}
	return m[cat]
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
		vars:                 make(map[string]*taintState, len(tm.vars)),
		lists:                make(map[string]*listTaintInfo, len(tm.lists)),
		maps:                 make(map[string]*mapTaintInfo, len(tm.maps)),
		consts:               make(map[string]int64, len(tm.consts)),
		strConsts:            make(map[string]string, len(tm.strConsts)),
		containerWriters:     make(map[string]bool, len(tm.containerWriters)),
		constContainers:      make(map[string]bool, len(tm.constContainers)),
		freshLocalEmpty:      make(map[string]bool, len(tm.freshLocalEmpty)),
		hardenedReceivers:    make(map[string]map[taint.SinkCategory]bool, len(tm.hardenedReceivers)),
		bodyCategorySuppress: make(map[taint.SinkCategory]bool, len(tm.bodyCategorySuppress)),
		aliases:              make(map[string]string, len(tm.aliases)),
	}
	for k, v := range tm.containerWriters {
		cp.containerWriters[k] = v
	}
	for k, v := range tm.constContainers {
		cp.constContainers[k] = v
	}
	for k, v := range tm.freshLocalEmpty {
		cp.freshLocalEmpty[k] = v
	}
	for k, v := range tm.hardenedReceivers {
		cats := make(map[taint.SinkCategory]bool, len(v))
		for kk, vv := range v {
			cats[kk] = vv
		}
		cp.hardenedReceivers[k] = cats
	}
	for k, v := range tm.bodyCategorySuppress {
		cp.bodyCategorySuppress[k] = v
	}
	for k, v := range tm.aliases {
		cp.aliases[k] = v
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

// Shallow field-sensitive helpers.
//
// Field keys are stored alongside plain variable keys in tm.vars. A field key
// is any key matching the prefix `<varName>.` — produced by extractAssignLHS
// returning full text for `attribute`/`member_expression` LHS (e.g. Python's
// `s.q` → key "s.q"). The taint map itself is language-agnostic; the
// extraction layer is responsible for emitting `varName.fieldName` keys.
//
// `obj.attr` taint is distinct from `obj` taint: assigning to one does not
// affect the other, except when the bare object is rebound (which invalidates
// all of its field entries — see clearFieldsOf).
//
// Subscript keys (e.g. `d['k']` stored as full text "d['k']") and method
// calls (`obj.method()` is a call, not a read) are out of scope for this
// shallow field-sensitive pass — see python_field_sensitive_test.go for the
// supported shape.

// isFieldKey reports whether a taint map key looks like a shallow field
// access `<base>.<field>` (where base is a plain identifier). Returns the
// base name when true. Keys with subscripts (`d['k']`) or deeper paths
// (`a.b.c`) are intentionally treated as the same first-level field of `a` —
// callers that care about deeper paths must handle them separately.
func isFieldKey(k string) (base string, ok bool) {
	dot := strings.IndexByte(k, '.')
	if dot <= 0 {
		return "", false
	}
	// Reject keys whose base part isn't a plain identifier (e.g. starts with
	// a quote or contains a bracket before the dot).
	base = k[:dot]
	for i := 0; i < len(base); i++ {
		c := base[i]
		if c == '_' || c == '$' ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return "", false
	}
	return base, true
}

// maxAccessPathDepth bounds the number of field segments tracked after the
// root identifier of an access path. A depth of 5 lets the engine distinguish
// sibling fields up to five levels deep (e.g. `a.b.c.d.id` from `a.b.c.d.name`,
// both depth 5) while keeping the per-function taint-map state bounded — paths
// deeper than the cap collapse to their depth-5 prefix, so `a.b.c.d.e.f` is
// tracked as `a.b.c.d.e`. This is the field-sensitivity analog of mature SAST
// tools' bounded access-path abstractions: precise enough to avoid spuriously
// tainting sibling fields, coarse enough that the key set cannot grow without
// bound.
//
// Raised 3->5 (CH4-access-path-depth): real nested DTO/config/request shapes
// (`ctx.request.body.user.id`, `event.detail.payload.order.total`) routinely
// reach depth 4-5 before the leaf field, where a depth-3 cap collapsed distinct
// siblings to a shared `root+3` prefix and could over-taint a clean sibling.
// Raising the cap can only ADD tracked depth (more precise sibling distinction);
// it never drops a real flow, because a shorter seeded prefix still prefix-taints
// every deeper read (prefixTainted walks read paths down to the root, so a
// depth-3 seed still taints a depth-5 read of the same prefix). The per-function
// state-size impact is bounded and qualitatively small: only access paths that
// are genuinely 4-5 segments deep create extra distinct keys, and each such key
// REPLACES — does not add to — what was previously a single collapsed key, so
// growth is at most linear in the number of distinct deep paths a function
// actually writes (typically a handful), not combinatorial.
const maxAccessPathDepth = 5

// boundAccessPath truncates a dotted access path to root + maxAccessPathDepth
// field segments. The root (segment 0) plus up to maxAccessPathDepth trailing
// segments are kept; deeper segments are dropped, collapsing the path to its
// bounded prefix. Subscripts/quotes are not split — boundAccessPath operates
// only on plain `a.b.c` identifier chains (callers pass attribute full-text).
//
//	boundAccessPath("req.body.user.id")     == "req.body.user"      (root + 3)
//	boundAccessPath("req.body.user.id.sub") == "req.body.user"      (collapsed)
//	boundAccessPath("req.body")             == "req.body"           (unchanged)
//	boundAccessPath("x")                    == "x"                  (unchanged)
func boundAccessPath(path string) string {
	segs := strings.Split(path, ".")
	// root + maxAccessPathDepth fields = maxAccessPathDepth+1 segments.
	if len(segs) <= maxAccessPathDepth+1 {
		return path
	}
	return strings.Join(segs[:maxAccessPathDepth+1], ".")
}

// recordAlias records a must-alias copy `alias = target` (both are bare
// identifiers naming the same object). A prior alias edge for `alias` is
// overwritten — the copy rebinds it. Self-edges (`a = a`) are ignored.
func (tm *taintMap) recordAlias(alias, target string) {
	if alias == "" || target == "" || alias == target {
		return
	}
	if tm.aliases == nil {
		tm.aliases = make(map[string]string)
	}
	tm.aliases[alias] = target
}

// breakAlias removes any alias edges that involve `name` as either endpoint.
// Called when `name` is rebound to a new value: the previous must-alias copy
// no longer holds because `name` may now point at a different object. Removing
// both the forward edge (`name -> X`) and any reverse edges (`Y -> name`)
// keeps the relation a sound MUST-alias: after `b = other`, neither `a`'s
// fields reflect on `b` nor vice versa.
func (tm *taintMap) breakAlias(name string) {
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

// aliasRoots returns the set of variable names that are must-alias-equivalent
// to root (including root itself). It follows alias edges in BOTH directions
// (forward `root -> X` and reverse `Y -> root`) transitively, because a
// must-alias copy makes the names interchangeable. The visited set bounds the
// walk so a malformed/cyclic alias graph cannot loop. The returned slice is
// deterministic (sorted) so field-key resolution order does not depend on map
// iteration.
func (tm *taintMap) aliasRoots(root string) []string {
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
		// Forward edge: cur was copied from t (cur = t).
		if t, ok := tm.aliases[cur]; ok && !seen[t] {
			seen[t] = true
			queue = append(queue, t)
		}
		// Reverse edges: some k was copied from cur (k = cur).
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

// prefixTainted reports whether reading the access path `path` should be
// considered tainted given the per-path taint entries currently in tm.vars.
//
// A read of `path` is tainted if ANY proper prefix of `path` (including `path`
// itself, down to the bare root identifier) is recorded as a tainted access
// path. This is the read-side dual of seeding the maximal access path on the
// write side: tainting `req.body.user` taints reads of `req.body.user`,
// `req.body.user.id`, `req.body.user.name`, … (all sub-paths) but NOT the
// sibling `req.body.other` — because `req.body` was never seeded as tainted on
// its own, only the more specific `req.body.user` was.
//
// The walk strips trailing `.segment` components one at a time, so it is
// bounded by the number of dots in the path. The bare root check (no dots
// left) preserves the existing bare-variable receiver fallback: `b = req.body;
// sink(b.x)` taints because `b` is a tainted root.
//
// Must-alias resolution: when a prefix has a dotted shape (`<root>.<rest>`) and
// `<root>` participates in an intra-function must-alias copy (`b = a`), the same
// `.<rest>` suffix is also probed under every alias-equivalent root, so a field
// written through one alias (`b.field = src`) is seen when read through another
// (`sink(a.field)`). Only the root segment is substituted; the field suffix is
// identical, so this never taints a sibling field.
func (tm *taintMap) prefixTainted(path string) *taintState {
	p := path
	for {
		if ts := tm.vars[p]; ts != nil && ts.source != nil {
			return ts
		}
		// Must-alias root substitution for dotted paths.
		if dot := strings.IndexByte(p, '.'); dot > 0 && len(tm.aliases) > 0 {
			root := p[:dot]
			suffix := p[dot:] // includes leading '.'
			for _, ar := range tm.aliasRoots(root) {
				if ar == root {
					continue
				}
				if ts := tm.vars[ar+suffix]; ts != nil && ts.source != nil {
					return ts
				}
			}
		}
		dot := strings.LastIndexByte(p, '.')
		if dot <= 0 {
			return nil
		}
		p = p[:dot]
	}
}

// sourceFieldTrackedInScope reports whether some local variable in this scope
// was already assigned a taint state DERIVED FROM the same catalog source `src`
// (compared by ID). It is the discriminator that lets a normally field-sensitive
// sink category (SQL) opt into inline attribute/subscript source resolution ONLY
// when no SIBLING field of that source is being tracked. The canonical false
// positive it prevents is the field-sensitivity contract:
//
//	const x = req.body.a;          // x's taint state derives from req.body
//	db.query("..." + req.body.b);  // sibling field — must stay clean
//
// In an assignment, `findSourceInExpr(rhs)` seeds the SOURCE under the LHS local
// (`x`), not under the access path `req.body.a` — so a path-prefix scan of the
// map cannot see the sibling. But the LHS state's `source` is the very same
// catalog SourceDef the inline `req.body.b` resolves to. So: if any tracked
// state shares the inline source's ID, a sibling field of the same request
// source is already in play and the resolution is suppressed (preserving the
// TestMultiLevelField_* / sibling-distinctness contract). When NOTHING in scope
// derives from that source — the inline use is the only one, as in the Juice
// Shop `db.query(`...${req.body.email}...`)` shape — it returns false and the
// resolver fires.
//
// Source-attribute marker entries that processAttr seeds under their own access
// path (a standalone `req.body.x` read elsewhere, keyed `req.body.x`) also share
// the ID and are correctly treated as a tracked sibling.
func (tm *taintMap) sourceFieldTrackedInScope(src *taint.SourceDef) bool {
	if src == nil {
		return false
	}
	for _, ts := range tm.vars {
		if ts == nil || ts.source == nil {
			continue
		}
		if ts.source.ID == src.ID {
			return true
		}
	}
	return false
}

// anyFieldTainted returns the first taintState whose key is of the form
// "varName.*" AND was produced by an explicit field assignment
// (`obj.attr = source()` or propagation thereof). Returns nil otherwise.
// Used at sinks that read the whole object — we conservatively
// over-approximate by assuming the sink might internally read any field.
//
// Source-attribute markers (e.g. `request.args`, `redis.hGetAll`) carry
// fromFieldAssign=false and are NOT surfaced here — bubbling them up to a
// bare-object read would over-taint any object whose method happens to be a
// catalog source.
func (tm *taintMap) anyFieldTainted(varName string) *taintState {
	if varName == "" {
		return nil
	}
	prefix := varName + "."
	// Return the tainted field with the lexicographically smallest key so the
	// choice (and the source attributed to a whole-object sink) is
	// deterministic, not Go map iteration order. A single O(N) pass that tracks
	// the smallest QUALIFYING key is identical to "collect all matching keys,
	// sort, return the first qualifying" — the original iterated sorted order
	// and returned the first key satisfying the predicate, i.e. the smallest
	// qualifying key — but avoids the keys-slice allocation and the O(N log N)
	// sort on this hot path (called per bare-identifier read at a sink).
	var bestKey string
	var best *taintState
	for k, ts := range tm.vars {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if ts == nil || ts.source == nil || !ts.fromFieldAssign {
			continue
		}
		if best == nil || k < bestKey {
			bestKey = k
			best = ts
		}
	}
	return best
}

// clearFieldsOf removes all per-field taint entries (and per-key map / list
// entries) for varName. Called when varName is rebound as a whole — the
// previous fields belong to the old binding.
func (tm *taintMap) clearFieldsOf(varName string) {
	if varName == "" {
		return
	}
	prefix := varName + "."
	for k := range tm.vars {
		if strings.HasPrefix(k, prefix) {
			delete(tm.vars, k)
		}
	}
	// Also drop whole-variable container state. tm.maps / tm.lists hold
	// per-key and per-index taint keyed by the BARE variable name, and on a
	// full rebind (`x = <fresh>`) that old container content belongs to the
	// previous binding. The docstring already promised this, but the body
	// never did it — leaving stale `x["k"]` / `x[i]` taint to propagate to a
	// sink after x was reassigned to a clean value (a latent false positive).
	delete(tm.maps, varName)
	delete(tm.lists, varName)
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
	// cliScript marks the file as a CLI entrypoint (e.g. Python
	// `if __name__ == "__main__":` block). When true, addFlow demotes
	// confidence for flows whose source is a CLI argument and whose sink
	// is a file I/O sink — argparse → pathlib in a CLI tool is idiomatic,
	// not a traversal vulnerability.
	cliScript bool
}

func newFlowBuilder(filePath string) *flowBuilder {
	return &flowBuilder{filePath: filePath}
}

// cliFileSinkDemote is the multiplier applied to a flow's confidence when
// it matches the SrcCLIArg → file-sink pattern in a CLI script. 0.5 drops a
// Critical finding's RiskScore below the 0.7 block threshold so it reports
// as a hint instead of blocking the write.
const cliFileSinkDemote = 0.5

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
	// Prototype pollution (CWE-1321) is a KEY-namespace threat: it requires the
	// attacker to control object KEYS such as __proto__/constructor/prototype.
	// JS database-read sources (findOne/find/query/findById/...) are catalogued
	// as SrcDatabase for second-order VALUE taint (stored XSS/SQLi); a DB
	// document's key namespace is the schema, not attacker-controlled, so
	// merging a query result into a target (e.g. `_.merge(target, await
	// Model.findOne())`) cannot pollute the prototype. Drop those flows here —
	// demotion-only, and JS/TS-only by construction since SnkPrototype is only
	// registered in javascript_sinks.go.
	//
	// S3 getObject is the deliberate exception: an attacker-uploaded object can
	// be arbitrary JSON carrying __proto__ keys, so S3-object-content -> proto
	// stays a real flow. DynamoDB/RDS/Athena/HANA are schema'd databases (their
	// own ObjectTypes) and remain suppressed alongside the ORM query sources.
	if sink.Category == taint.SnkPrototype && ts.source != nil &&
		ts.source.Category == taint.SrcDatabase && ts.source.ObjectType != "aws-sdk.S3" {
		return
	}
	conf := ts.confidence
	if fb.cliScript && isUserInputToFileSinkPattern(ts.source, sink) {
		conf *= cliFileSinkDemote
	}
	flow := taint.TaintFlow{
		Source:     *ts.source,
		Sink:       *sink,
		SourceLine: ts.sourceLine,
		SinkLine:   sinkLine,
		Steps:      ts.steps,
		FilePath:   fb.filePath,
		ScopeName:  scopeName,
		Confidence: conf,
	}
	fb.flows = append(fb.flows, flow)
}

// isUserInputToFileSinkPattern reports whether a flow is the "CLI tool takes a
// file path argument" shape — any user-provided data (argparse, sys.argv, or
// stdin via input()) flowing into a file read/write sink.
//
// We match both SrcCLIArg AND SrcUserInput because the tsflow matcher can
// classify an argparse-derived value as SrcUserInput when the `input(`
// builtin pattern fires on the same file. The demotion is only applied when
// flowBuilder.cliScript is true — which already excludes web handlers — so
// the broader match is safe.
func isUserInputToFileSinkPattern(src *taint.SourceDef, sink *taint.SinkDef) bool {
	if src == nil || sink == nil {
		return false
	}
	userish := src.Category == taint.SrcCLIArg || src.Category == taint.SrcUserInput
	fileSink := sink.Category == taint.SnkFileRead || sink.Category == taint.SnkFileWrite
	return userish && fileSink
}
