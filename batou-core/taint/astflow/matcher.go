package astflow

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/turenlabs/batou-core/taint"
)

// CatalogMatcher indexes catalog entries by method name for O(1) lookup
// and matches *ast.CallExpr against SourceDef/SinkDef/SanitizerDef.
type CatalogMatcher struct {
	sourcesByMethod    map[string][]*taint.SourceDef
	sinksByMethod      map[string][]*taint.SinkDef
	sanitizersByMethod map[string][]*taint.SanitizerDef
	typeEnv            *TypeEnv
}

// NewCatalogMatcher builds an indexed matcher from catalog entries.
// Compound method names like "Query/Param/PostForm" are split and indexed
// under each component.
func NewCatalogMatcher(
	sources []taint.SourceDef,
	sinks []taint.SinkDef,
	sanitizers []taint.SanitizerDef,
	typeEnv *TypeEnv,
) *CatalogMatcher {
	m := &CatalogMatcher{
		sourcesByMethod:    make(map[string][]*taint.SourceDef),
		sinksByMethod:      make(map[string][]*taint.SinkDef),
		sanitizersByMethod: make(map[string][]*taint.SanitizerDef),
		typeEnv:            typeEnv,
	}

	for i := range sources {
		src := &sources[i]
		for _, name := range extractMethodNames(src.MethodName) {
			m.sourcesByMethod[name] = append(m.sourcesByMethod[name], src)
		}
	}
	for i := range sinks {
		sink := &sinks[i]
		for _, name := range extractMethodNames(sink.MethodName) {
			m.sinksByMethod[name] = append(m.sinksByMethod[name], sink)
		}
	}
	for i := range sanitizers {
		san := &sanitizers[i]
		for _, name := range extractMethodNames(san.MethodName) {
			m.sanitizersByMethod[name] = append(m.sanitizersByMethod[name], san)
		}
	}

	return m
}

// extractMethodNames splits compound method names on "/" and extracts the
// final component after any "." for each part.
// "Query/Param/PostForm" -> ["Query", "Param", "PostForm"]
// "os.Args" -> ["Args"]
// "FormValue" -> ["FormValue"]
// "URL.Query" -> ["Query"]
// "slog.Info" -> ["Info"]
func extractMethodNames(methodName string) []string {
	parts := strings.Split(methodName, "/")
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Take the last dot-separated component.
		dotParts := strings.Split(p, ".")
		name := dotParts[len(dotParts)-1]
		// Skip wildcard-like patterns.
		if name != "" && name != "*" {
			names = append(names, name)
		}
	}
	return names
}

// MatchSource checks if a call expression matches a known taint source.
func (m *CatalogMatcher) MatchSource(call *ast.CallExpr) *taint.SourceDef {
	methodName := extractCallMethodName(call)
	if methodName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[methodName]
	for _, src := range candidates {
		if m.matchesCall(call, src.ObjectType, src.MethodName) {
			// A file read whose path is derived from the application's own
			// operator config or a constant build directory is not an
			// attacker-controlled entry point — the operator chooses the
			// path, not a request. Treat these as internal so we don't seed
			// taint from, e.g., os.ReadFile(cfg.StaticRootPath+"/boot.js")
			// or os.ReadFile(s.ClientCertFilePath). Conservative: only the
			// clearly-internal selector/literal shapes are gated; a path
			// built from a request value (os.ReadFile(req.FormValue("p")))
			// is not, so real path-traversal still seeds.
			if src.Category == taint.SrcFileRead && fileReadPathIsInternal(call) {
				return nil
			}
			return src
		}
	}

	return nil
}

// configPathFieldSuffixes are field-name suffixes that, on a struct field used
// as a file path, mark the value as operator-supplied configuration rather than
// request input. e.g. `s.ClientCertFilePath`, `cfg.KeyFile`, `info.RootCAFile`.
var configPathFieldSuffixes = []string{
	"filepath", "filepaths", "keyfile", "certfile", "cafile",
	"rootcafilepaths", "staticrootpath", "provisioningpath",
}

// configRootIdents are receiver/identifier names that denote the application's
// own configuration object. A path argument rooted at one of these is
// operator-controlled.
var configRootIdents = map[string]bool{
	"cfg": true, "config": true, "conf": true,
	"setting": true, "settings": true,
	"opts": true, "options": true,
}

// fileReadPathIsInternal reports whether the path argument of a file-read call
// (os.ReadFile / os.Open / ioutil.ReadFile / ...) is derived from the
// application's own config or a constant build path, rather than from untrusted
// input. It is deliberately conservative: it only returns true for argument
// shapes it can positively attribute to config/constants, so anything it cannot
// prove internal (plain idents, request-derived calls) still seeds taint.
func fileReadPathIsInternal(call *ast.CallExpr) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	return pathExprIsInternal(call.Args[0])
}

// pathExprIsInternal inspects a single path expression for config/constant
// derivation. filepath.Join / path.Join / string concatenation are recursed
// into: the whole path is internal only if every dynamic component is.
func pathExprIsInternal(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		// A string literal path is a constant — never attacker input.
		return e.Kind == token.STRING
	case *ast.ParenExpr:
		return pathExprIsInternal(e.X)
	case *ast.SelectorExpr:
		return selectorIsConfigDerived(e)
	case *ast.BinaryExpr:
		// String concatenation: every operand must be internal.
		if e.Op != token.ADD {
			return false
		}
		return pathExprIsInternal(e.X) && pathExprIsInternal(e.Y)
	case *ast.CallExpr:
		// filepath.Join(...) / path.Join(...) / filepath.Clean(...) /
		// filepath.Abs(...): internal iff every argument is internal. A
		// literal-only Join with no dynamic part is internal; a Join that
		// mixes a config selector with literals (the boot.js shape) is
		// internal because the only dynamic component is config-derived.
		if !isPathJoinLikeCall(e) {
			return false
		}
		if len(e.Args) == 0 {
			return false
		}
		for _, a := range e.Args {
			if !pathExprIsInternal(a) {
				return false
			}
		}
		return true
	}
	return false
}

// isPathJoinLikeCall reports whether a call is filepath/path Join/Clean/Abs —
// path-composition helpers that preserve the internal/external nature of their
// arguments.
func isPathJoinLikeCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg := identName(sel.X)
	if pkg != "filepath" && pkg != "path" {
		return false
	}
	switch sel.Sel.Name {
	case "Join", "Clean", "Abs", "FromSlash", "ToSlash":
		return true
	}
	return false
}

// selectorIsConfigDerived reports whether a selector chain reads a field off
// the application's own configuration object. True when any component of the
// chain is a config root identifier (cfg/config/settings/...) or a config-typed
// intermediate field (Cfg/Config/Settings), or when the leaf field name carries
// a config-path suffix (FilePath/KeyFile/CertFile/...). Receiver-less package
// selectors like os.Args are not treated as config.
func selectorIsConfigDerived(sel *ast.SelectorExpr) bool {
	if sel == nil || sel.Sel == nil {
		return false
	}

	// Leaf-field suffix check: `s.ClientCertFilePath`, `cfg.KeyFile`.
	leaf := strings.ToLower(sel.Sel.Name)
	for _, suf := range configPathFieldSuffixes {
		if strings.HasSuffix(leaf, suf) {
			return true
		}
	}

	// Walk the chain root→leaf looking for a config root ident or a
	// config-typed intermediate field (e.g. `s.Cfg.JWTAuth.TlsClientCa`).
	cur := ast.Expr(sel)
	for {
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			fname := strings.ToLower(e.Sel.Name)
			if configRootIdents[fname] {
				return true
			}
			cur = e.X
		case *ast.StarExpr:
			cur = e.X
		case *ast.ParenExpr:
			cur = e.X
		case *ast.Ident:
			return configRootIdents[strings.ToLower(e.Name)]
		default:
			return false
		}
	}
}

// MatchSelectorSource checks if a non-call selector expression matches a
// known taint source. This handles primitive request-field reads like
// `r.URL.Path`, `r.Body`, `r.Host`, `r.RemoteAddr` — where the AST node is
// a *ast.SelectorExpr that is NOT the Fun of a CallExpr. Method-call sources
// (e.g. `r.FormValue("x")`) are still handled by MatchSource.
//
// Selector sources are catalog entries whose MethodName describes a
// dot-separated field path (e.g. "URL.Path", "Body") and whose ObjectType is
// the receiver type (e.g. "*http.Request"). The receiver root is resolved
// via TypeEnv when available, falling back to the receiver-name heuristic.
func (m *CatalogMatcher) MatchSelectorSource(sel *ast.SelectorExpr) *taint.SourceDef {
	if sel == nil || sel.Sel == nil {
		return nil
	}
	methodName := sel.Sel.Name
	if methodName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[methodName]
	for _, src := range candidates {
		// Only entries with a receiver type are eligible — package-level
		// sources (ObjectType == "") aren't selector-shaped on a receiver.
		if src.ObjectType == "" {
			continue
		}
		if m.matchesSelector(sel, src.ObjectType, src.MethodName) {
			return src
		}
	}
	return nil
}

// matchesSelector checks if a selector expression matches a catalog entry
// with the given objectType and methodName. The MethodName may be a
// dot-separated path like "URL.Path" — in that case the selector chain must
// also walk the matching intermediate fields back to a receiver whose type
// is objectType.
func (m *CatalogMatcher) matchesSelector(sel *ast.SelectorExpr, objectType, methodName string) bool {
	// Pick the candidate field path whose final component matches sel.Sel.Name.
	leaf := sel.Sel.Name
	var path []string
	for _, candidate := range strings.Split(methodName, "/") {
		candidate = strings.TrimSpace(candidate)
		parts := strings.Split(candidate, ".")
		if len(parts) == 0 {
			continue
		}
		if parts[len(parts)-1] != leaf {
			continue
		}
		path = parts
		break
	}
	if path == nil {
		return false
	}

	// Walk the selector chain leaf -> root, matching each intermediate field
	// against the path components (excluding the leaf, which we already
	// validated). The remaining innermost expression must be a plain ident
	// (or *ident / (*ident) / paren) whose type is objectType.
	cur := sel.X
	for i := len(path) - 2; i >= 0; i-- {
		inner, ok := cur.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if inner.Sel == nil || inner.Sel.Name != path[i] {
			return false
		}
		cur = inner.X
	}

	recvName := identName(cur)
	if recvName == "" {
		return false
	}

	// Prefer precise type info from TypeEnv; otherwise fall back to the
	// receiver-name heuristic.
	if m.typeEnv != nil {
		if knownType := m.typeEnv.VarType(recvName); knownType != "" {
			return typeMatches(knownType, objectType)
		}
	}
	return matchesReceiverType(recvName, objectType)
}

// MatchSink checks if a call expression matches a known sink.
// Returns the sink and the dangerous argument expressions.
func (m *CatalogMatcher) MatchSink(call *ast.CallExpr) (*taint.SinkDef, []ast.Expr) {
	methodName := extractCallMethodName(call)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sinksByMethod[methodName]
	for _, sink := range candidates {
		// Module binding gate: when a sink declares RequireModule, the
		// matched call's package alias must resolve to the named module.
		// Suppresses bare-name collisions like `bytes.decode` matching
		// `pickle.loads`, or `nox.Session.run` matching `subprocess.run`.
		if sink.RequireModule && !m.callBindsToModule(call, sink.Module) {
			continue
		}
		if m.matchesCall(call, sink.ObjectType, sink.MethodName) {
			// Special case: fmt.Fprintf/Fprint/Fprintln to ResponseWriter.
			if sink.Category == taint.SnkHTMLOutput && isFmtWriteFunc(sink.MethodName) {
				if len(call.Args) > 0 {
					firstArg := identName(call.Args[0])
					if !matchesReceiverType(firstArg, "http.ResponseWriter") {
						continue
					}
				}
				// The reflected-XSS / tainted-format danger is EVERY arg after
				// the io.Writer — the format string AND its variadic values —
				// not the catalog's static DangerousArgs=[1] (the format slot
				// only). Without this, fmt.Fprintf(w, "%s", q) with a tainted q
				// at index 2 produces no flow (the idiomatic Go reflected-XSS
				// shape). The downstream taint check still gates on an
				// actually-tainted arg, so widening here adds no false positive.
				if len(call.Args) > 1 {
					return sink, call.Args[1:]
				}
				return sink, nil
			}

			dangerous := collectDangerousArgs(call, sink.DangerousArgs)
			return sink, dangerous
		}
	}

	return nil, nil
}

// callBindsToModule returns true when the call expression's package alias
// resolves to the named module. Module is the bare last component of an
// import path (e.g. "subprocess", "pickle", "exec"). Matches when:
//   - the call is a SelectorExpr `X.Method` and X's identifier name == module, OR
//   - X's identifier resolves via TypeEnv.ResolveImport to a path whose
//     final component equals module.
//
// Returns false for bare identifier calls (no package prefix) — a sink that
// requires a module necessarily refuses unqualified calls.
func (m *CatalogMatcher) callBindsToModule(call *ast.CallExpr, module string) bool {
	if module == "" {
		return true
	}
	selExpr, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgAlias := identName(selExpr.X)
	if pkgAlias == "" {
		return false
	}
	if pkgAlias == module {
		return true
	}
	if m.typeEnv != nil {
		if importPath := m.typeEnv.ResolveImport(pkgAlias); importPath != "" {
			parts := strings.Split(importPath, "/")
			if parts[len(parts)-1] == module {
				return true
			}
		}
	}
	return false
}

// MatchSanitizer checks if a call expression matches a known sanitizer.
// Returns the sanitizer and the expression being sanitized (first arg).
func (m *CatalogMatcher) MatchSanitizer(call *ast.CallExpr) (*taint.SanitizerDef, ast.Expr) {
	methodName := extractCallMethodName(call)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sanitizersByMethod[methodName]
	for _, san := range candidates {
		if m.matchesCall(call, san.ObjectType, san.MethodName) {
			if len(call.Args) > 0 {
				return san, call.Args[0]
			}
			return san, nil
		}
	}

	return nil, nil
}

// matchesCall checks if a call expression plausibly matches a catalog entry
// with the given objectType and methodName.
func (m *CatalogMatcher) matchesCall(call *ast.CallExpr, objectType, methodName string) bool {
	// Package-level function: exec.Command, os.Getenv, etc.
	if objectType == "" {
		return m.matchesPackageCall(call, methodName)
	}

	// Method call on receiver: r.FormValue, db.Query, etc.
	return m.matchesMethodCall(call, objectType, methodName)
}

// matchesPackageCall checks if a call matches a package-level function.
func (m *CatalogMatcher) matchesPackageCall(call *ast.CallExpr, methodName string) bool {
	sel := selectorString(call.Fun)
	if sel == "" {
		return false
	}

	// Direct match: "exec.Command" == "exec.Command"
	if sel == methodName {
		return true
	}

	// Match by final method name with package verification via imports.
	selExpr, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	callMethod := selExpr.Sel.Name

	// Check each component of compound method names.
	for _, candidate := range strings.Split(methodName, "/") {
		candidate = strings.TrimSpace(candidate)
		dotParts := strings.Split(candidate, ".")
		finalMethod := dotParts[len(dotParts)-1]

		if callMethod != finalMethod {
			continue
		}

		// If methodName has a package prefix, verify it.
		if len(dotParts) >= 2 {
			pkgAlias := identName(selExpr.X)
			expectedPkg := dotParts[0]
			if pkgAlias == expectedPkg {
				return true
			}
			// Check if import alias resolves to expected package.
			if m.typeEnv != nil {
				importPath := m.typeEnv.ResolveImport(pkgAlias)
				if importPath != "" {
					pathParts := strings.Split(importPath, "/")
					if pathParts[len(pathParts)-1] == expectedPkg {
						return true
					}
				}
			}
		}

		// Simple method name match (single component like "Command"):
		// A genuine package-level call (catalog ObjectType=="") has the package
		// alias as receiver (`http.Post`, `os.Create`) or, for a package-level
		// variable's method, a pure selector chain rooted at a package
		// (`base64.StdEncoding.EncodeToString`). In neither case is the receiver
		// the RESULT OF A CALL. A fluent/builder chain such as `builder().Post(u)`
		// or `m.Combo("/x").Get(H).Post(...)` has a call-rooted receiver —
		// matching it on the bare leaf name alone is receiver-blind and
		// misattributes the call to the package sink (false SSRF/file-write
		// blocks on routers and builders). Reject a call-rooted receiver before
		// accepting the bare-name match.
		if len(dotParts) == 1 {
			if receiverIsCallRooted(selExpr.X) {
				continue
			}
			// Accept only when the receiver is not a known local variable;
			// otherwise the call is a method call on a typed receiver, not a
			// package call.
			if m.typeEnv != nil {
				recv := identName(selExpr.X)
				if recv != "" && m.typeEnv.VarType(recv) != "" {
					continue
				}
			}
			return true
		}
	}

	return false
}

// receiverIsCallRooted reports whether a selector receiver expression is
// derived from the result of a function/method call — i.e. the head of the
// chain is a *ast.CallExpr. A genuine package-level reference (a package alias
// `http`/`os` or a package-level variable chain `base64.StdEncoding`) is never
// rooted in a call, so a call-rooted receiver (`builder().Post`,
// `m.Combo("/x").Get(H).Post`, `foo().bar.Baz`) cannot be a package call and
// must not match a bare-name package sink. Walks through selector/pointer/
// paren/index wrappers down to the receiver's root.
func receiverIsCallRooted(expr ast.Expr) bool {
	for {
		switch e := expr.(type) {
		case *ast.CallExpr:
			return true
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		default:
			return false
		}
	}
}

// matchesMethodCall checks if a call matches a method call on a receiver.
func (m *CatalogMatcher) matchesMethodCall(call *ast.CallExpr, objectType, methodName string) bool {
	selExpr, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	callMethod := selExpr.Sel.Name

	// Check if the method name matches any component. When the matched
	// candidate describes a required call chain (e.g. "Response().Header().Set"),
	// verify the receiver actually walks that chain — otherwise a bare field
	// access `.Set` on an unrelated receiver (e.g. an in-memory `c.cache.Set(...)`)
	// would be misattributed to the framework sink purely because its leaf
	// method name and receiver-name heuristic happen to collide.
	matched := false
	for _, candidate := range strings.Split(methodName, "/") {
		candidate = strings.TrimSpace(candidate)
		dotParts := strings.Split(candidate, ".")
		finalMethod := dotParts[len(dotParts)-1]
		if callMethod != finalMethod {
			continue
		}
		if strings.Contains(candidate, "()") && !chainReceiverMatches(selExpr.X, dotParts) {
			continue
		}
		matched = true
		break
	}
	if !matched {
		return false
	}

	// Try TypeEnv for precise type match. When TypeEnv has a definitive
	// type for the receiver, trust it — either accept or reject — so the
	// name-based fallback does not misattribute calls across frameworks
	// (e.g. "ctx" → *gin.Context when the real type is *fasthttp.RequestCtx).
	recvName := identName(selExpr.X)
	if recvName != "" && m.typeEnv != nil {
		knownType := m.typeEnv.VarType(recvName)
		if knownType != "" {
			return typeMatches(knownType, objectType)
		}
	}

	// Fallback: receiver name heuristic (only when type is unknown).
	if recvName != "" && matchesReceiverType(recvName, objectType) {
		return true
	}

	// Handle chained calls: r.URL.Query().Get(...)
	if innerSel, ok := selExpr.X.(*ast.SelectorExpr); ok {
		innerRecv := identName(innerSel.X)
		if innerRecv != "" && matchesReceiverType(innerRecv, objectType) {
			return true
		}
	}

	// Handle call chains: r.URL.Query().Get(...)
	if innerCall, ok := selExpr.X.(*ast.CallExpr); ok {
		innerRecv := deepReceiverName(innerCall.Fun)
		if innerRecv != "" && matchesReceiverType(innerRecv, objectType) {
			return true
		}
	}

	return false
}

// chainReceiverMatches verifies that recv structurally matches the call-chain
// prefix described by dotParts (excluding the leaf method). A catalog MethodName
// component like "Response().Header().Set" splits into
// ["Response()", "Header()", "Set"]; the leaf ".Set"'s receiver must therefore
// be the call chain `X.Response().Header()`. Each "()"-suffixed segment must
// correspond to an actual *ast.CallExpr whose selector method equals the segment
// name. This rejects collisions like `c.cache.Set(...)` — a plain field access,
// not a call chain — that would otherwise match purely on the leaf name "Set"
// plus a permissive receiver-name heuristic.
func chainReceiverMatches(recv ast.Expr, dotParts []string) bool {
	// Walk the required chain segments from innermost (just before the leaf)
	// outward, peeling matching CallExpr layers off recv.
	for i := len(dotParts) - 2; i >= 0; i-- {
		seg := dotParts[i]
		if !strings.HasSuffix(seg, "()") {
			// A non-call intermediate segment (plain field) is not a chain
			// requirement we model here; leave it to the receiver-type checks.
			continue
		}
		segName := strings.TrimSuffix(seg, "()")
		callExpr, ok := unwrapCall(recv)
		if !ok {
			return false
		}
		segSel, ok := callExpr.Fun.(*ast.SelectorExpr)
		if !ok || segSel.Sel == nil || segSel.Sel.Name != segName {
			return false
		}
		recv = segSel.X
	}
	return true
}

// typeMatches checks if a known type matches a catalog object type.
func typeMatches(knownType, catalogType string) bool {
	if knownType == catalogType {
		return true
	}
	// Handle pointer/non-pointer differences.
	if strings.TrimPrefix(knownType, "*") == strings.TrimPrefix(catalogType, "*") {
		return true
	}
	// Handle partial match: "sql.DB" matches "*sql.DB".
	return strings.Contains(catalogType, strings.TrimPrefix(knownType, "*")) ||
		strings.Contains(knownType, strings.TrimPrefix(catalogType, "*"))
}

// extractCallMethodName extracts the final method/function name from a call.
func extractCallMethodName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// collectDangerousArgs returns argument expressions at the dangerous positions.
func collectDangerousArgs(call *ast.CallExpr, dangerousArgs []int) []ast.Expr {
	var dangerous []ast.Expr
	for _, argIdx := range dangerousArgs {
		if argIdx == -1 {
			dangerous = append(dangerous, call.Args...)
			break
		}
		if argIdx >= 0 && argIdx < len(call.Args) {
			dangerous = append(dangerous, call.Args[argIdx])
		}
	}
	return dangerous
}

// isFmtWriteFunc checks if a method name is a fmt write function.
func isFmtWriteFunc(name string) bool {
	return name == "Fprintf" || name == "Fprint" || name == "Fprintln"
}

// pkgQualifiedTypeContains reports whether objType contains the package-qualified
// type `want` (e.g. "http.Request") with a real package boundary — i.e. the
// character immediately preceding the match is not an identifier character.
//
// A plain strings.Contains is unsound here: the catalog ObjectType
// "github.com/valyala/fasthttp.RequestCtx" (and ...RequestHeader) contains the
// substring "http.Request" as part of "fas[thttp.Request]Ctx", so the net/http
// receiver-name case (r/req/request) would wrongly fire for those fasthttp
// types, seeding e.g. `req.URL.String()` on a *net/url.URL as fasthttp external
// input (the gin CWE-601 open-redirect false positive). Requiring a
// non-identifier boundary before the match keeps net/http's "http.Request"
// matching while rejecting "fasthttp.Request*".
func pkgQualifiedTypeContains(objType, want string) bool {
	from := 0
	for {
		i := strings.Index(objType[from:], want)
		if i < 0 {
			return false
		}
		idx := from + i
		if idx == 0 || !isIdentByte(objType[idx-1]) {
			return true
		}
		from = idx + 1
	}
}

// isIdentByte reports whether b can appear within a Go identifier or package-path
// component (letters, digits, underscore). Path separators ('/', '.') and other
// punctuation are treated as boundaries.
func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// matchesReceiverType checks if a receiver variable name plausibly corresponds
// to a given type using naming conventions (fallback heuristic).
func matchesReceiverType(varName string, objType string) bool {
	lower := strings.ToLower(varName)

	switch {
	case pkgQualifiedTypeContains(objType, "http.Request"):
		return lower == "r" || lower == "req" || lower == "request" ||
			lower == "httpreq" || lower == "httprequest"
	case pkgQualifiedTypeContains(objType, "http.ResponseWriter"):
		return lower == "w" || lower == "resp" || lower == "response" ||
			lower == "rw" || lower == "writer"
	case strings.Contains(objType, "gin.Context"):
		return lower == "c" || lower == "ctx" || lower == "ginctx"
	case strings.Contains(objType, "echo.Context"):
		return lower == "c" || lower == "ctx" || lower == "echoctx"
	case strings.Contains(objType, "fiber.Ctx"):
		return lower == "c" || lower == "ctx" || lower == "fctx"
	case strings.Contains(objType, "macaron.Context"),
		strings.Contains(objType, "gitea/modules/context"):
		// Gitea wraps Macaron's Context; both expose FormString / Query /
		// Params / Redirect on receivers idiomatically named `ctx` (sometimes
		// `c` in inner helpers). APIContext is a sub-context for /api/v1.
		return lower == "ctx" || lower == "c" || lower == "apictx" ||
			lower == "webctx"
	case strings.Contains(objType, "sql.DB"):
		return lower == "db" || lower == "conn" || lower == "database"
	case strings.Contains(objType, "sql.Tx"):
		return lower == "tx" || lower == "txn"
	case strings.Contains(objType, "sql.Rows"):
		return lower == "rows" || lower == "row" || lower == "result"
	case strings.Contains(objType, "sql.Stmt"):
		return lower == "stmt" || lower == "statement"
		// NOTE: a name-based receiver heuristic for Gitea's db.Engine/db.Session
		// (binding `e`/`x`/`db`/`sess` locals + inline db.GetEngine(ctx).Where(...)
		// chains) was evaluated and deliberately NOT added: it produced ZERO new
		// findings on Gitea (which uses parameterized queries / builder.Eq
		// throughout, so no tainted raw SQL reaches these sinks) while adding
		// cross-repo false-positive risk on the OSS scanner from the generic
		// `e`/`x`/`db` names. The go.gitea.db.engine.*/db.session.* sinks remain
		// bound via TypeEnv on the typed `e db.Engine` / `sess db.Session` params,
		// which is FP-safe. Revisit if the engine gains interface-aware receiver
		// typing for db.GetEngine(ctx).
	case strings.Contains(objType, "bufio.Scanner"):
		return lower == "scanner" || lower == "s" || lower == "sc"
	case strings.Contains(objType, "net.Conn"):
		return lower == "conn" || lower == "c" || lower == "connection"
	case strings.Contains(objType, "ldap.Conn"):
		return lower == "conn" || lower == "l" || lower == "ldap" || lower == "ldapconn"
	case strings.Contains(objType, "gorm.DB"):
		return lower == "db" || lower == "conn" || lower == "gdb" || lower == "gorm"
	case strings.Contains(objType, "redis.Client"):
		return lower == "rdb" || lower == "client" || lower == "redis"
	case strings.Contains(objType, "mongo.Collection"):
		return lower == "collection" || lower == "coll" || lower == "col"
	case strings.Contains(objType, "dynamodb.Client"), strings.Contains(objType, "dynamodb.DynamoDB"):
		return lower == "svc" || lower == "client" || lower == "ddb" ||
			lower == "dynamo" || lower == "dynamoclient" || lower == "dynclient" ||
			lower == "db"
	case strings.Contains(objType, "kinesis.Client"), strings.Contains(objType, "kinesis.Kinesis"):
		// aws-sdk-go-v2 *kinesis.Client / legacy v1 *kinesis.Kinesis are
		// conventionally `:=` locals from kinesis.NewFromConfig()/kinesis.New()
		// with no static type info — resolve the common stream-consumer
		// receiver names so the GetRecords read sources fire.
		return lower == "svc" || lower == "kc" || lower == "kinesis" ||
			lower == "kinesisclient" || lower == "kclient" || lower == "client"
	case strings.Contains(objType, "json.Decoder"):
		return lower == "dec" || lower == "decoder"
	case strings.Contains(objType, "zap.Logger"):
		return lower == "logger" || lower == "log" || lower == "zap" || lower == "sugar"
	case strings.Contains(objType, "template.Template"):
		return lower == "tmpl" || lower == "tpl" || lower == "t" || lower == "template"
	case strings.Contains(objType, "jwt.Parser"):
		// golang-jwt parser handle, conventionally a `:=` local from
		// jwt.NewParser() with no static type info — resolve the common
		// receiver names so the ParseUnverified signature-bypass sink fires.
		return lower == "parser" || lower == "p" || lower == "jwtparser"
	case strings.Contains(objType, "gomail.Message"):
		// gomail message handle, conventionally a `:=` local from
		// gomail.NewMessage(); resolve the common receiver names so the
		// SetHeader / SetAddressHeader email-injection sinks fire.
		return lower == "m" || lower == "msg" || lower == "message" || lower == "mail"
	case strings.Contains(objType, "bluemonday.Policy"):
		return lower == "p" || lower == "policy" || lower == "sanitizer"
	case strings.Contains(objType, "validator.Validate"):
		return lower == "validate" || lower == "v" || lower == "validator"
	case strings.Contains(objType, "docker.Client"):
		return lower == "cli" || lower == "client" || lower == "docker"
	case strings.Contains(objType, "kafka.Writer"):
		return lower == "writer" || lower == "w" || lower == "producer"
	case strings.Contains(objType, "scs.SessionManager"):
		return lower == "sessionmanager" || lower == "sm" || lower == "session" || lower == "sess"
	case strings.Contains(objType, "sessions.Session"):
		return lower == "session" || lower == "sess"
	case strings.Contains(objType, "fiber.Session"):
		return lower == "sess" || lower == "session" || lower == "fsess"
	case strings.Contains(objType, "memcache.Client"):
		return lower == "mc" || lower == "memcache" || lower == "memclient"
	case strings.Contains(objType, "gocql.Iter"):
		// gocql result iterator is conventionally a `:=` local from
		// session.Query(...).Iter(), so it has no static type info — resolve
		// the common receiver names so the second-order read sources fire.
		return lower == "iter" || lower == "it"
	case strings.Contains(objType, "gocql.Query"):
		// gocql query handle when bound to a named local before .Scan/.MapScan.
		return lower == "query" || lower == "q"
	case strings.Contains(objType, "bigcache.BigCache"):
		// allegro/bigcache local is conventionally a `:=` value from
		// bigcache.New()/NewBigCache(), so it has no static type info — resolve
		// the common receiver names so the second-order read sources fire.
		return lower == "cache" || lower == "bigcache" || lower == "bc"
	case strings.Contains(objType, "freecache.Cache"):
		// coocood/freecache local is conventionally a `:=` value from
		// freecache.NewCache(); same untyped-receiver resolution as bigcache.
		return lower == "cache" || lower == "freecache" || lower == "fc"
	case strings.Contains(objType, "tar.Reader"):
		return lower == "tr" || lower == "tarreader" || lower == "tarr"
	case strings.Contains(objType, "zip.Reader") || strings.Contains(objType, "zip.ReadCloser"):
		return lower == "zr" || lower == "zipreader" || lower == "rc" || lower == "zrc"
	case strings.Contains(objType, "zip.File"):
		return lower == "zf" || lower == "zipfile" || lower == "zipentry"
	case strings.Contains(objType, "elasticsearch.Client"):
		return lower == "es" || lower == "client" || lower == "esclient" ||
			lower == "esclt" || lower == "elastic"
	case strings.Contains(objType, "opensearch.Client"):
		return lower == "client" || lower == "osclient" ||
			lower == "osclt" || lower == "opensearch"
	case strings.Contains(objType, "ssh.Session"):
		// golang.org/x/crypto/ssh: the *ssh.Session value is conventionally a
		// `:=` local from client.NewSession(), so it has no static type info —
		// resolve the common receiver names so Run/Start/Output sinks fire.
		return lower == "session" || lower == "sess" || lower == "sshsession"
	case strings.Contains(objType, "clientv3.Client"):
		// go.etcd.io/etcd/client/v3: the *clientv3.Client is conventionally a
		// `:=` local from clientv3.New(), so the read-source receiver has no
		// static type — resolve etcd-specific names so Get fires. "client" is
		// deliberately excluded to avoid colliding with http.Client.Get.
		return lower == "cli" || lower == "etcd" || lower == "etcdcli" ||
			lower == "etcdclient"
	case strings.Contains(objType, "api.KV"):
		// github.com/hashicorp/consul/api: the *api.KV handle from client.KV()
		// is conventionally bound to `kv`, typically a `:=` local with no static
		// type, so resolve that name for the Get/List/Keys read sources.
		return lower == "kv" || lower == "consulkv"
	}

	return false
}
