package ssaflow

import (
	"go/types"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"golang.org/x/tools/go/ssa"
)

// catalogMatcher resolves an ssa.Call against the Go taint catalog. The
// matcher only handles statically resolvable calls (Common().StaticCallee()
// not nil); interface dispatch is intentionally out of scope for this PR.
type catalogMatcher struct {
	sinks        []taint.SinkDef
	sanitizers   []taint.SanitizerDef
	writeSources []taint.SourceDef // sources with non-empty WritesArg (subset of full catalog)

	// Pre-indexed lookups keyed by final method name (e.g. "Query", "Exec")
	// so the per-call cost is O(1 + duplicates) rather than scanning every
	// catalog entry. Compound method names ("Query/Param/PostForm") are
	// split and indexed under each component, matching astflow's behaviour.
	sinksByName        map[string][]int // value is index into c.sinks
	sanitizersByName   map[string][]int
	writeSourcesByName map[string][]int // value is index into c.writeSources
}

func newCatalogMatcher(sinks []taint.SinkDef, sanitizers []taint.SanitizerDef) *catalogMatcher {
	return newCatalogMatcherWithSources(sinks, sanitizers, nil)
}

// newCatalogMatcherWithSources builds a matcher that, in addition to sinks
// and sanitizers, knows about sources whose WritesArg field is non-empty
// (i.e. bind-style methods that mutate a pointer-arg's pointee with
// untrusted data). Sources without WritesArg are intentionally omitted —
// they contribute no SSA-level information beyond what the source-typed
// parameter detector already provides.
func newCatalogMatcherWithSources(
	sinks []taint.SinkDef,
	sanitizers []taint.SanitizerDef,
	sources []taint.SourceDef,
) *catalogMatcher {
	m := &catalogMatcher{
		sinks:              sinks,
		sanitizers:         sanitizers,
		sinksByName:        make(map[string][]int),
		sanitizersByName:   make(map[string][]int),
		writeSourcesByName: make(map[string][]int),
	}
	for i := range sinks {
		for _, name := range methodComponents(sinks[i].MethodName) {
			m.sinksByName[name] = append(m.sinksByName[name], i)
		}
	}
	for i := range sanitizers {
		for _, name := range methodComponents(sanitizers[i].MethodName) {
			m.sanitizersByName[name] = append(m.sanitizersByName[name], i)
		}
	}
	for i := range sources {
		if len(sources[i].WritesArg) == 0 {
			continue
		}
		m.writeSources = append(m.writeSources, sources[i])
		idx := len(m.writeSources) - 1
		for _, name := range methodComponents(sources[i].MethodName) {
			m.writeSourcesByName[name] = append(m.writeSourcesByName[name], idx)
		}
	}
	return m
}

// matchWriteSource returns the SourceDef whose WritesArg describes a
// pointee mutation performed by this call, plus the SSA-adjusted argument
// positions (receiver-shifted for method calls). Returns (nil, nil) when
// no source with WritesArg matches.
//
// Only sources whose WritesArg field is non-empty are considered — the
// non-pointer-mutating sources are still tracked by paramSource() via the
// source-typed parameter mechanism. Returning the SourceDef lets callers
// build a synthetic flow source for the resulting tainted pointee.
func (m *catalogMatcher) matchWriteSource(call *ssa.Call) (*taint.SourceDef, []int) {
	callee := call.Common().StaticCallee()
	if callee == nil {
		return nil, nil
	}
	name := callee.Name()
	if name == "" {
		return nil, nil
	}
	for _, idx := range m.writeSourcesByName[name] {
		src := &m.writeSources[idx]
		if !calleeMatchesEntry(callee, src.ObjectType, src.MethodName) {
			continue
		}
		positions := adjustArgPositions(call.Common(), src.WritesArg)
		return src, positions
	}
	return nil, nil
}

// matchSink returns the catalog entry and dangerous arg positions for an SSA
// call. The match succeeds when (a) the callee can be resolved statically,
// (b) its short name matches one of the catalog's MethodName components, and
// (c) the receiver type (for method sinks) or package path (for package
// sinks) is compatible with the entry's ObjectType.
// matchSink takes a *ssa.CallCommon (rather than *ssa.Call) so it matches
// sinks invoked via any call-like instruction — regular calls, `go f(x)`
// goroutines (*ssa.Go), and `defer f(x)` (*ssa.Defer) — all of which embed
// a CallCommon. Callers extract it via ssa.CallInstruction.Common().
func (m *catalogMatcher) matchSink(common *ssa.CallCommon) (*taint.SinkDef, []int) {
	callee := common.StaticCallee()
	if callee == nil {
		return nil, nil
	}
	name := callee.Name()
	if name == "" {
		return nil, nil
	}
	for _, idx := range m.sinksByName[name] {
		sink := &m.sinks[idx]
		if !calleeMatchesEntry(callee, sink.ObjectType, sink.MethodName) {
			continue
		}
		// Adjust dangerous arg positions for method receivers: SSA represents
		// method calls with the receiver as Args[0] when Common().IsInvoke()
		// is false (regular method), so positional args from the catalog
		// (which are 0-indexed against the *source-level* argument list,
		// excluding the receiver) need to be shifted accordingly.
		positions := adjustArgPositions(common, sink.DangerousArgs)
		return sink, positions
	}
	return nil, nil
}

// callIsSanitizerFor returns true if call statically resolves to a known
// sanitizer that neutralizes the given sink category. Used during def-use
// traversal to prune chains that pass through a sanitizer's return.
func (m *catalogMatcher) callIsSanitizerFor(call *ssa.Call, cat taint.SinkCategory) bool {
	// Same-origin server-request-URL prune (CWE-601 only). A redirect target
	// rendered from a *net/http.Request's own URL field — req.URL.String() or
	// req.URL.RequestURI() — is same-origin in the common case: Go's net/http
	// server only populates Path/RawQuery on a server request URL, never
	// Scheme/Host, so the rendered string is a relative path on the current
	// host. Provenance-scoped to the *http.Request.URL field so an
	// attacker-constructed &url.URL{Host: …}.String() or a Header/query value
	// stays taintable. Canonical FP: gin's redirectRequest (req.URL.String()
	// -> http.Redirect), whose callers canonicalize req.URL.Path upstream.
	if cat == taint.SnkRedirect && callIsServerRequestURLRedirectSafe(call) {
		return true
	}

	callee := call.Common().StaticCallee()
	if callee == nil {
		return false
	}
	name := callee.Name()
	for _, idx := range m.sanitizersByName[name] {
		san := &m.sanitizers[idx]
		if !calleeMatchesEntry(callee, san.ObjectType, san.MethodName) {
			continue
		}
		for _, neut := range san.Neutralizes {
			if neut == cat {
				return true
			}
		}
	}
	return false
}

// callIsServerRequestURLRedirectSafe reports whether call renders a
// *net/http.Request's own URL — (*net/url.URL).String() or .RequestURI()
// whose receiver traces back to the .URL field of a *net/http.Request — and
// is therefore a same-origin relative path, not an open-redirect target.
// The check is provenance-scoped: a freshly constructed &url.URL{Host: …},
// a url.Parse(userInput) result, or a request Header/query value is NOT
// pruned, preserving genuine open-redirect detection.
func callIsServerRequestURLRedirectSafe(call *ssa.Call) bool {
	callee := call.Common().StaticCallee()
	if callee == nil {
		return false
	}
	switch callee.Name() {
	case "String", "RequestURI":
	default:
		return false
	}
	recv := receiverType(callee)
	if recv == nil || !typeIsNamed(recv, "net/url", "URL") {
		return false
	}
	args := call.Common().Args
	if len(args) == 0 {
		return false
	}
	return receiverTracesToRequestURLField(args[0])
}

// receiverTracesToRequestURLField walks back through SSA loads and field
// reads from a method receiver, returning true when it lands on a read of the
// "URL" field of a net/http.Request struct (i.e. req.URL). Bounded depth
// keeps the walk cheap and loop-safe.
func receiverTracesToRequestURLField(v ssa.Value) bool {
	for i := 0; i < 8 && v != nil; i++ {
		switch n := v.(type) {
		case *ssa.UnOp:
			v = n.X // load (`*p`) — follow the address
		case *ssa.FieldAddr:
			if fieldName(n.X.Type(), n.Field) == "URL" && typeIsNamed(n.X.Type(), "net/http", "Request") {
				return true
			}
			v = n.X
		case *ssa.Field:
			if fieldName(n.X.Type(), n.Field) == "URL" && typeIsNamed(n.X.Type(), "net/http", "Request") {
				return true
			}
			v = n.X
		default:
			return false
		}
	}
	return false
}

// typeIsNamed reports whether t (after dereferencing pointers) is the named
// type pkgPath.typeName — e.g. ("net/url", "URL") or ("net/http", "Request").
func typeIsNamed(t types.Type, pkgPath, typeName string) bool {
	named, ok := derefAll(t).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Name() != typeName {
		return false
	}
	pkg := obj.Pkg()
	return pkg != nil && pkg.Path() == pkgPath
}

// calleeMatchesEntry checks whether a statically resolved callee matches a
// catalog entry's ObjectType + MethodName. The catalog uses string identifiers
// like "*sql.DB" / "Query" or "" (package-level) / "exec.Command". We render
// SSA's typed representation back into the same canonical form for comparison.
func calleeMatchesEntry(callee *ssa.Function, objectType, methodName string) bool {
	// Method-name check: at least one component of the catalog method name
	// must equal the callee's short name.
	hit := false
	for _, comp := range methodComponents(methodName) {
		if comp == callee.Name() {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}

	if objectType == "" {
		// Package-level function: compare the callee's package path tail to
		// the methodName prefix (e.g. "exec.Command" → package "exec" with
		// method "Command"). When the catalog stores just "Command", any
		// matching short name passes.
		return packageCallMatches(callee, methodName)
	}

	// Method call: compare receiver type to objectType.
	recv := receiverType(callee)
	if recv == nil {
		return false
	}
	return typesAreCompatible(canonicalGoTypeString(recv), objectType)
}

// packageCallMatches checks if a non-method callee plausibly comes from the
// package implied by methodName. If methodName is bare ("Command"), any
// package-level function with that name matches; if methodName is qualified
// ("exec.Command"), the callee's package name must equal "exec".
func packageCallMatches(callee *ssa.Function, methodName string) bool {
	// Resolve the callee's package name once. SSA package-level funcs carry it
	// on .Pkg.Pkg; stdlib funcs resolved via the importer have a nil .Pkg but
	// carry the *types.Package on .Object().
	calleePkg := ""
	if pkg := callee.Pkg; pkg != nil && pkg.Pkg != nil {
		calleePkg = pkg.Pkg.Name()
	} else if obj := callee.Object(); obj != nil && obj.Pkg() != nil {
		calleePkg = obj.Pkg().Name()
	}
	return methodNamePackageMatches(callee.Name(), calleePkg, methodName)
}

// methodNamePackageMatches is the pure package-gate decision for a package-level
// (non-method) call. calleeShort is the callee's short name (e.g. "NewDecoder"),
// calleePkg is the callee's package name (e.g. "json"), and methodName is the
// catalog MethodName, a "/"-separated set of components each optionally
// package-qualified ("xml.NewDecoder").
//
// CRITICAL: split methodName on "/" but DO NOT strip the package qualifier the
// way methodComponents does — the qualifier is exactly what must be verified.
// Routing methodName through methodComponents here was the package-blind bug:
// it collapsed "xml.NewDecoder" to the bare "NewDecoder", so the len(parts)==1
// branch fired unconditionally and EVERY qualified package-level sink degraded
// to a package-blind bare-name match (json.NewDecoder mislabeled xml.NewDecoder,
// errors.New as md5.New, http.Client.Do as fasthttp.Do).
func methodNamePackageMatches(calleeShort, calleePkg, methodName string) bool {
	for _, comp := range strings.Split(methodName, "/") {
		comp = strings.TrimSpace(comp)
		if comp == "" {
			continue
		}
		parts := strings.Split(comp, ".")
		short := parts[len(parts)-1]
		if short == "" || short == "*" {
			continue
		}
		if short != calleeShort {
			continue
		}
		if len(parts) == 1 {
			return true // bare-name catalog entry: any package with this func name matches
		}
		expectedPkg := parts[len(parts)-2]
		if calleePkg != "" && calleePkg == expectedPkg {
			return true
		}
	}
	return false
}

// receiverType returns the receiver type of a method, or nil for a plain
// function. SSA stores the receiver as the first parameter on method funcs.
func receiverType(callee *ssa.Function) types.Type {
	sig := callee.Signature
	if sig == nil {
		return nil
	}
	if r := sig.Recv(); r != nil {
		return r.Type()
	}
	return nil
}

// typesAreCompatible mirrors astflow's typeMatches: exact match, pointer/non-
// pointer equivalence, or substring containment to handle "sql.DB" vs
// "*sql.DB" / aliased forms. This is intentionally lenient — false positives
// here are bounded by the def-use reachability check that precedes a flow.
func typesAreCompatible(have, want string) bool {
	if have == "" || want == "" {
		return false
	}
	if have == want {
		return true
	}
	stripped := strings.TrimPrefix(have, "*")
	wantStripped := strings.TrimPrefix(want, "*")
	if stripped == wantStripped {
		return true
	}
	if strings.Contains(want, stripped) || strings.Contains(have, wantStripped) {
		return true
	}
	return false
}

// adjustArgPositions translates catalog argument positions to ssa.Call arg
// positions. SSA Call.Common().Args contains the receiver as Args[0] for
// non-invoke method calls; the catalog's DangerousArgs index counts source-
// level args (receiver excluded). When the call is a method call we add 1.
func adjustArgPositions(common *ssa.CallCommon, catalogPositions []int) []int {
	out := make([]int, 0, len(catalogPositions))
	offset := 0
	if !common.IsInvoke() && common.Signature() != nil && common.Signature().Recv() != nil {
		offset = 1
	}
	for _, p := range catalogPositions {
		if p < 0 {
			// -1 in the catalog means "any" — expand to every actual arg.
			for i := offset; i < len(common.Args); i++ {
				out = append(out, i)
			}
			continue
		}
		out = append(out, p+offset)
	}
	return out
}

// methodComponents splits a catalog MethodName field (which may be a
// "Query/Param/PostForm"-style compound) into its individual method names,
// stripping any leading package qualifier so each component is a bare name.
func methodComponents(s string) []string {
	parts := strings.Split(s, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		dotParts := strings.Split(p, ".")
		name := dotParts[len(dotParts)-1]
		if name != "" && name != "*" {
			out = append(out, name)
		}
	}
	return out
}
