package tsflow

import (
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// tsMatcher indexes catalog entries by method name for O(1) lookup
// and matches tree-sitter nodes against source/sink/sanitizer definitions.
type tsMatcher struct {
	sourcesByMethod    map[string][]*taint.SourceDef
	sinksByMethod      map[string][]*taint.SinkDef
	sanitizersByMethod map[string][]*taint.SanitizerDef
	allSources         []*taint.SourceDef // flat list for Pattern-based matching (Shell expansions)
	cfg                *langConfig

	// swiftArgLabels gates Swift catalog entries written in the Apple
	// argument-label form `Base(label:)` / `method(label:)`. The keys are
	// def pointers (interface{} holding *taint.SinkDef / *taint.SourceDef /
	// *taint.SanitizerDef); the value is the set of argument labels that the
	// entry requires the call to carry. This lets `String(contentsOfFile:)`
	// key under the bare callable name `String` (so it is reachable from the
	// tree-sitter call name) while still NOT matching `String(describing:)`
	// or `String(someInt)`. Only populated for Swift; nil/empty for every
	// other language, so their matching is byte-identical.
	swiftArgLabels map[interface{}][]string

	// patternCache compiles sanitizer Pattern regexes on demand. A sanitizer
	// entry with generic MethodName ("replace", "decode", …) can use Pattern
	// to require specific argument content (e.g. only `.replace("'", "&apos;")`)
	// so it doesn't sanitise every method-name-matching call.
	patternMu    sync.Mutex
	patternCache map[string]*regexp.Regexp
}

func newTSMatcher(sources []taint.SourceDef, sinks []taint.SinkDef, sanitizers []taint.SanitizerDef, cfg *langConfig) *tsMatcher {
	m := &tsMatcher{
		sourcesByMethod:    make(map[string][]*taint.SourceDef),
		sinksByMethod:      make(map[string][]*taint.SinkDef),
		sanitizersByMethod: make(map[string][]*taint.SanitizerDef),
		cfg:                cfg,
		patternCache:       make(map[string]*regexp.Regexp),
		swiftArgLabels:     make(map[interface{}][]string),
	}

	isSwift := cfg != nil && cfg.language == rules.LangSwift

	register := func(methodName string, def interface{}, index func(string)) {
		// Swift-only: catalog entries in the `Base(label:)` form key under
		// the bare callable base and record the required arg labels so the
		// gate in matchSink/Source/Sanitizer can verify the call carries one.
		// Slash-compounds (`nodes(forXPath:)/objectsForXQuery()`) are split
		// here so each part is classified independently.
		if isSwift {
			var allLabels []string
			anyLabelForm := false
			for _, part := range strings.Split(methodName, "/") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				if base, labels, ok := swiftCallableBaseAndLabels(part); ok {
					anyLabelForm = true
					index(base)
					allLabels = append(allLabels, labels...)
				} else {
					// Mixed compound: index this non-label part the generic way.
					for _, name := range extractMethodNames(part) {
						index(name)
					}
				}
			}
			if anyLabelForm {
				if len(allLabels) > 0 {
					m.swiftArgLabels[def] = allLabels
				}
				return
			}
		}
		for _, name := range extractMethodNames(methodName) {
			index(name)
		}
	}

	for i := range sources {
		src := &sources[i]
		m.allSources = append(m.allSources, src)
		register(src.MethodName, src, func(name string) {
			m.sourcesByMethod[name] = append(m.sourcesByMethod[name], src)
		})
	}
	for i := range sinks {
		sink := &sinks[i]
		register(sink.MethodName, sink, func(name string) {
			m.sinksByMethod[name] = append(m.sinksByMethod[name], sink)
		})
	}
	for i := range sanitizers {
		san := &sanitizers[i]
		register(san.MethodName, san, func(name string) {
			m.sanitizersByMethod[name] = append(m.sanitizersByMethod[name], san)
		})
	}

	return m
}

// swiftCallableBaseAndLabels parses a Swift catalog MethodName written in the
// Apple argument-label form `Base(label:)`, `Base(label1:label2:)`, or
// `method(label:)` and returns the bare callable base name plus the set of
// argument labels. Returns ok=false for names that are NOT in this form
// (bare names like `evaluateJavaScript`, slash-compounds like
// `arguments/launchPath`, dotted names like `AF.request`, or descriptive
// annotations like `getInstance(MD5)` where the parenthesised text is not a
// trailing-colon label list) — those fall through to the generic
// extractMethodNames path unchanged.
//
// Examples:
//
//	"String(contentsOfFile:)"   -> base "String", labels ["contentsoffile"]
//	"set(_:forKey:)"            -> base "set",    labels ["forkey"] ("_" ignored)
//	"nodes(forXPath:)"          -> base "nodes",  labels ["forxpath"]
//	"NSPredicate(format:)"      -> base "NSPredicate", labels ["format"]
//	"getInstance(MD5)"          -> ok=false (no trailing-colon labels)
//	"AF.request"                -> ok=false (no parens)
func swiftCallableBaseAndLabels(methodName string) (string, []string, bool) {
	// Reject slash-compounds: those mix forms and are handled generically.
	if strings.Contains(methodName, "/") {
		return "", nil, false
	}
	open := strings.IndexByte(methodName, '(')
	if open <= 0 || !strings.HasSuffix(strings.TrimSpace(methodName), ")") {
		return "", nil, false
	}
	base := strings.TrimSpace(methodName[:open])
	// The base must itself be a bare identifier (`String`, `nodes`,
	// `NSPredicate`) — a dotted base (`AF.request(...)`) is not the
	// argument-label idiom we target here.
	if base == "" || strings.ContainsAny(base, ". :>-") {
		return "", nil, false
	}
	inner := methodName[open+1:]
	if end := strings.LastIndexByte(inner, ')'); end >= 0 {
		inner = inner[:end]
	}
	// The Apple argument-label idiom always ends every label with ":".
	// `getInstance(MD5)` / `header(Location)` have no colon and are NOT
	// argument-label forms — defer to the generic path.
	if !strings.Contains(inner, ":") {
		return "", nil, false
	}
	var labels []string
	for _, raw := range strings.Split(inner, ":") {
		label := strings.TrimSpace(raw)
		// "_" is Swift's "no external label" marker (e.g. set(_:forKey:));
		// it carries no label at the call site, so skip it.
		if label == "" || label == "_" {
			continue
		}
		// Tokens after a label's colon that are enum-value defaults written
		// into the catalog name (`withAllowedCharacters: .urlQueryAllowed`,
		// `kind: .text`) start with "." — they are not argument labels, so
		// skip rather than reject.
		if strings.HasPrefix(label, ".") {
			continue
		}
		// Only keep simple identifier labels; bail to the generic path if
		// the inner text looks like free-form prose.
		if strings.ContainsAny(label, " ,") {
			return "", nil, false
		}
		labels = append(labels, strings.ToLower(label))
	}
	return base, labels, true
}

// extractMethodNames splits compound method names on "/" and extracts the
// final component after any "." or "::" for each part.
func extractMethodNames(methodName string) []string {
	// Normalize "::", "->", and ":" (Lua colon-call) to "." so all scope/member access is unified.
	methodName = strings.ReplaceAll(methodName, "::", ".")
	methodName = strings.ReplaceAll(methodName, "->", ".")
	methodName = strings.ReplaceAll(methodName, ":", ".")
	parts := strings.Split(methodName, "/")
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		dotParts := strings.Split(p, ".")
		name := dotParts[len(dotParts)-1]
		// Strip trailing "[]" so catalog entries that name a subscript form
		// (Ruby `params[]`, C `argv[]`) are reachable from a bare-identifier
		// lookup. The walker normalises `params[:url]` / `argv[0]` to the
		// bare `params` / `argv` token at the subscript step in
		// findSourceInExpr, so the keys must match.
		name = strings.TrimSuffix(name, "[]")
		if name != "" && name != "*" {
			names = append(names, name)
		}
	}
	return names
}

// swiftCallArgLabels returns the lower-cased argument labels present on a
// Swift call node. The grammar wraps each argument in a `value_argument`
// node whose optional `value_argument_label` child holds the label
// identifier (e.g. `contentsOfFile` in `String(contentsOfFile: path)`).
// Used only by the Swift arg-label gate.
func swiftCallArgLabels(n *ast.Node) []string {
	if n == nil {
		return nil
	}
	var labels []string
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "value_argument_label" {
			// The label text is the identifier under value_argument_label.
			txt := strings.TrimSpace(child.Text())
			if txt != "" {
				labels = append(labels, strings.ToLower(txt))
			}
			return false
		}
		return true
	})
	return labels
}

// swiftArgLabelGateOK reports whether a Swift catalog entry's required
// argument labels (recorded at matcher-construction time for `Base(label:)`
// forms) are satisfied by the call node. Returns true when the entry has no
// recorded label requirement (every non-Swift entry, and Swift entries that
// were keyed generically), so it is a no-op outside the targeted idiom.
// When the entry DOES require labels, the call must carry at least one of
// them — this is what keeps `String(contentsOfFile:)` from matching
// `String(describing:)` even though both key under `String`.
func (m *tsMatcher) swiftArgLabelGateOK(def interface{}, n *ast.Node) bool {
	required := m.swiftArgLabels[def]
	if len(required) == 0 {
		return true
	}
	have := swiftCallArgLabels(n)
	if len(have) == 0 {
		return false
	}
	for _, want := range required {
		for _, h := range have {
			if h == want {
				return true
			}
		}
	}
	return false
}

// groovyShellReceiverMatch reports whether a call receiver names a GroovyShell
// instance. The GroovyShell.evaluate()/parse() sinks (CWE-94 RCE) are anchored
// on the GroovyShell CONSTRUCTOR rather than a fixed variable name, so their
// catalog entries historically carried an empty ObjectType — which made the
// tsflow matcher register the bare method names `evaluate`/`parse` as
// match-anything wildcard sinks. Those names are ubiquitous benign calls
// (`SimpleDateFormat.parse(s)`, `StatusLine.parse(line)`, `expr.evaluate()`),
// so the wildcard fired CWE-94 at conf 1.0 (a hard BLOCK) on completely safe
// code (verified on okhttp). This helper restores the intended receiver anchor:
// accept only a fresh `GroovyShell()` / `GroovyShell("…")` constructor receiver
// or a conventionally-named shell handle (`shell`, `groovyShell`, `gshell`,
// `gs`), matching the `shell.evaluate(`/`GroovyShell().evaluate(` shapes the
// sibling groovy/java catalogs anchor on — and reject unrelated receivers like
// `dateFormat`. Token-scoped to the GroovyShell sinks via the "groovyshell"
// ObjectType, so no other catalog entry's matching changes.
func groovyShellReceiverMatch(receiver string) bool {
	r := strings.ToLower(strings.TrimSpace(receiver))
	r = strings.TrimPrefix(r, "$")
	// Strip a trailing call-suffix so the constructor form `GroovyShell()` /
	// `GroovyShell("x")` reduces to its callee name `groovyshell`.
	if i := strings.IndexByte(r, '('); i > 0 {
		r = r[:i]
	}
	// Reduce a qualified receiver (`this.shell`, `a.b.groovyShell`) to its last
	// component.
	r = strings.ReplaceAll(r, "->", ".")
	if i := strings.LastIndexByte(r, '.'); i >= 0 {
		r = r[i+1:]
	}
	switch r {
	case "groovyshell", "shell", "groovyshell_", "gshell", "gs":
		return true
	}
	return false
}

// unqualifyName extracts the last component of a qualified name.
// e.g., "java.io.File" → "File", "Runtime" → "Runtime".
func unqualifyName(name string) string {
	name = strings.ReplaceAll(name, "::", ".")
	name = strings.ReplaceAll(name, "->", ".")
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// matchSourceCall checks if a call node matches a known taint source.
func (m *tsMatcher) matchSourceCall(n *ast.Node) *taint.SourceDef {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[methodName]
	// Also check unqualified name for qualified calls like java.io.File
	short := unqualifyName(methodName)
	if short != methodName {
		candidates = append(candidates, m.sourcesByMethod[short]...)
	}
	receiver := m.cfg.extractCallReceiver(n)
	for _, src := range candidates {
		if labels := m.swiftArgLabels[src]; len(labels) > 0 {
			if m.swiftArgLabelGateOK(src, n) {
				return src
			}
			continue
		}
		if matchesCatalogEntry(receiver, methodName, src.ObjectType, src.MethodName) {
			return src
		}
	}
	return nil
}

// matchSourceAttr checks if an attribute access node matches a known source.
// This handles sources like request.args, request.body that are property accesses.
func (m *tsMatcher) matchSourceAttr(n *ast.Node) *taint.SourceDef {
	attrName := m.cfg.extractAttrName(n)
	if attrName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[attrName]
	receiver := m.cfg.extractAttrReceiver(n)
	for _, src := range candidates {
		if matchesCatalogEntry(receiver, attrName, src.ObjectType, src.MethodName) {
			return src
		}
		// C#-scoped dotted-suffix match for prefixed ASP.NET request chains.
		// The ASP.NET request sources are registered with a dotted MethodName
		// (e.g. "Request.Query") and an implicit `this.Request` receiver, so the
		// receiver heuristic in matchesCatalogEntry only accepts the BARE
		// Request.Query[...] / Request.Query form (receiver == "request"). The
		// dominant modern ASP.NET Core shapes PREFIX the chain —
		// context.Request.Query[...], _httpContextAccessor.HttpContext.Request.Query[...]
		// — whose reconstructed receiver ("context.Request",
		// "_httpContextAccessor.HttpContext.Request") fails that exact heuristic
		// and was therefore dead. Accept when the reconstructed member-access
		// path (receiver + "." + attrName) equals the catalog MethodName or ends
		// with it on a DOT boundary, so "context.Request.Query" matches
		// "Request.Query" but "MyRequest.Query" does not. Gated to C# AND dotted
		// MethodNames: a single-component MethodName (e.g. "GetString") is never
		// suffix-loosened (that would match any x.GetString), and no other
		// language's source matching is touched (proved by OWASP byte-identical /
		// CVE no-drop). This is a narrow access-path suffix match, NOT the
		// receiver-strip generalization rejected in #1259.
		if m.cfg != nil && m.cfg.language == rules.LangCSharp &&
			strings.Contains(src.MethodName, ".") &&
			csharpAttrPathHasDottedSuffix(receiver, attrName, src.MethodName) {
			return src
		}
		// SLICE B (C#-scoped): the HttpRequest.Item indexer reached through a
		// member-access holder — `context.Request["x"]`, `this.Request["x"]`,
		// `httpContext.Request["x"]`, `filterContext.HttpContext.Request["x"]`.
		// The source is registered with the SINGLE-component MethodName "Request"
		// (so the dotted-suffix path above does not apply) and ObjectType
		// "HttpRequest"; matchesCatalogEntry's generic request-receiver allowlist
		// only accepts a BARE `request`/`req` receiver, so these idiomatic ASP.NET
		// holders were dead. Accept them only when the attribute is exactly
		// `Request` (capital R = the Page/Controller/HttpContext property) and the
		// holder is an HttpContext-shaped receiver. Gated to C# AND the
		// capital-Request convention so a non-HttpRequest `.Request` member or a
		// lowercase chain does not match. The bare `Request["x"]` form (no holder)
		// is a lone identifier that never reaches here; it is handled by the
		// walker's element-access case.
		if m.cfg != nil && m.cfg.language == rules.LangCSharp &&
			attrName == "Request" && src.MethodName == "Request" &&
			strings.EqualFold(src.ObjectType, "HttpRequest") &&
			csharpHTTPContextReceiverOK(receiver) {
			return src
		}
	}
	return nil
}

// csharpHTTPContextReceiverOK reports whether `receiver` is an idiomatic holder
// of the ASP.NET HttpRequest property (`<holder>.Request`). Accepts the page /
// controller `this`, the bare `context` / `httpContext` handler argument, and
// any chain ending in `.HttpContext` (e.g. `filterContext.HttpContext`,
// `_httpContextAccessor.HttpContext`). Whitespace from a multi-line fluent chain
// is stripped first. Used only for the HttpRequest.Item indexer source, gated to
// C# at the call site.
func csharpHTTPContextReceiverOK(receiver string) bool {
	lower := strings.ToLower(stripASCIIWhitespace(receiver))
	switch lower {
	case "this", "context", "httpcontext":
		return true
	}
	return strings.HasSuffix(lower, ".httpcontext")
}

// csharpRequestItemSource returns the registered HttpRequest.Item indexer source
// (MethodName "Request", ObjectType "HttpRequest"), or nil if the C# catalog is
// not loaded. Used by the walker's bare-`Request[...]` element-access case,
// whose indexed object is a lone identifier that never reaches matchSourceAttr.
func (m *tsMatcher) csharpRequestItemSource() *taint.SourceDef {
	for _, src := range m.sourcesByMethod["Request"] {
		if src.MethodName == "Request" && strings.EqualFold(src.ObjectType, "HttpRequest") {
			return src
		}
	}
	return nil
}

// csharpAttrPathHasDottedSuffix reports whether the reconstructed C#
// member-access path `receiver.attrName` equals the catalog MethodName or ends
// with it on a dot boundary. Whitespace (from a fluent chain spanning multiple
// source lines) is stripped first — C# identifiers cannot contain whitespace,
// so this is loss-less for the comparison. The dot-boundary requirement is what
// keeps "MyRequest.Query" from matching "Request.Query" (the character before
// the suffix must be ".", or the suffix must be the whole path).
func csharpAttrPathHasDottedSuffix(receiver, attrName, methodName string) bool {
	if receiver == "" {
		return false
	}
	path := stripASCIIWhitespace(receiver + "." + attrName)
	return path == methodName || strings.HasSuffix(path, "."+methodName)
}

// stripASCIIWhitespace removes spaces, tabs, carriage returns, and newlines
// from s.
func stripASCIIWhitespace(s string) string {
	if !strings.ContainsAny(s, " \t\r\n") {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// matchSourceExpansion matches a Shell variable-expansion node
// (simple_expansion `$1`/`$VAR`, expansion `${1}`/`${VAR}`) against the
// shell catalog sources by regex Pattern. Shell positional parameters and
// CGI environment variables are not call/attribute nodes, so the normal
// call/attr matchers never see them; this resolver lets the tsflow engine
// seed taint from `name="$1"` and `q=$QUERY_STRING` the same way the regex
// engine would. Only consulted for Shell (config language gate at call site).
//
// The expansion's full text (e.g. "$1", "${HTTP_USER_AGENT}") is tested
// against each candidate source's compiled Pattern.
func (m *tsMatcher) matchSourceExpansion(n *ast.Node) *taint.SourceDef {
	if n == nil {
		return nil
	}
	text := n.Text()
	if text == "" {
		return nil
	}
	for i := range m.allSources {
		src := m.allSources[i]
		if src.Pattern == "" {
			continue
		}
		re := m.compileSourcePattern(src)
		if re == nil {
			continue
		}
		if re.MatchString(text) {
			return src
		}
	}
	return nil
}

// weakSinkPatternOK re-validates a WEAK (wildcard/global) sink candidate
// against its own catalog Pattern before letting it fire. The tsflow structural
// matcher keys sinks on the unqualified method/command NAME (via
// extractMethodNames), so an empty-ObjectType ("") or "@global" sink whose
// catalog MethodName is actually qualified or constrained — `IPC::Run::run`
// (Perl), `ngx.pipe.spawn` (Lua), `git` clone/fetch/pull/ls-remote (Shell),
// `setInterval("…")` (JS) — matches ANY same-named call and produces hard-block
// false positives (commands->run, ngx.thread.spawn, `git rev-parse`,
// setInterval(fn,ms)). The author already encoded the precise form in the
// Pattern; this honours it by requiring the call's source text to match the
// Pattern before a weak match is accepted. Only applied to weak matches (empty
// or @global ObjectType) and only when a Pattern exists — strong receiver-typed
// matches and pattern-less sinks are unchanged. This generalises the GroovyShell
// receiver-anchor fix to every Pattern-bearing bare-name sink collision.
func (m *tsMatcher) weakSinkPatternOK(sink *taint.SinkDef, n *ast.Node) bool {
	if sink.Pattern == "" {
		return true
	}
	// Skip "loose" Patterns of the form `Type.*\.method(` (e.g.
	// `GroovyClassLoader.*\.parseClass`, `QSqlQuery.*\.exec`,
	// `sqlite3pp::database.*\.execute`). Their leading token is the receiver's
	// declared TYPE, which appears at the variable declaration, not in the call
	// node text — so matching such a Pattern against `loader.parseClass(x)` /
	// `query.exec(sql)` would wrongly reject a genuine sink. Only call-anchored
	// Patterns (qualified names, subcommands, arg-literals — no `.*`/`.+`
	// wildcard) are reliable against the call node text.
	if strings.Contains(sink.Pattern, ".*") || strings.Contains(sink.Pattern, ".+") {
		return true
	}
	re := m.compileSinkPattern(sink)
	if re == nil {
		return true // uncompilable Pattern → fall back to prior (accept) behaviour
	}
	return re.MatchString(n.Text())
}

// compileSinkPattern returns the cached compiled Pattern regex for a sink,
// compiling it on first use. Returns nil if uncompilable.
func (m *tsMatcher) compileSinkPattern(sink *taint.SinkDef) *regexp.Regexp {
	m.patternMu.Lock()
	defer m.patternMu.Unlock()
	key := "snk:" + sink.ID
	if re, ok := m.patternCache[key]; ok {
		return re
	}
	re, err := regexp.Compile(sink.Pattern)
	if err != nil {
		m.patternCache[key] = nil
		return nil
	}
	m.patternCache[key] = re
	return re
}

// compileSourcePattern returns the cached compiled Pattern regex for a
// source, compiling it on first use. Returns nil if uncompilable.
func (m *tsMatcher) compileSourcePattern(src *taint.SourceDef) *regexp.Regexp {
	m.patternMu.Lock()
	defer m.patternMu.Unlock()
	key := "src:" + src.ID
	if re, ok := m.patternCache[key]; ok {
		return re
	}
	re, err := regexp.Compile(src.Pattern)
	if err != nil {
		m.patternCache[key] = nil
		return nil
	}
	m.patternCache[key] = re
	return re
}

// matchSinkCall checks if a call node matches a known sink.
// Returns the sink and the dangerous argument nodes.
//
// When multiple catalog entries share a method name (e.g. `find` is used by
// MongoDB collections, Spring LdapTemplate, and Spring MongoTemplate), the
// first matching entry wins in catalog order — but a wildcard-ObjectType
// fallback yields to a later entry that strongly identifies the receiver
// (direct or last-component name equality). This keeps `ldapTemplate.find(...)`
// classified as an LDAP sink even when a generic `\.find\(` entry is listed
// earlier in the catalog.
func (m *tsMatcher) matchSinkCall(n *ast.Node) (*taint.SinkDef, []*ast.Node) {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sinksByMethod[methodName]
	short := unqualifyName(methodName)
	if short != methodName {
		candidates = append(candidates, m.sinksByMethod[short]...)
	}
	receiver := m.cfg.extractCallReceiver(n)

	// PHP global-builtin disambiguation: a handful of PHP built-in function
	// names (file, fopen, readfile, …) are also common user-defined METHOD
	// names (`$finfo->file($tmp)` reads MIME, `$repo->file($path)` fetches a
	// model). The catalog models the GLOBAL builtin (empty ObjectType) and its
	// Pattern excludes the `->`/`::` member form, but the tsflow matcher keys
	// purely on method name and would otherwise flag the method call as a
	// path-traversal file-read sink. When this PHP call is a member/scoped
	// call (`$obj->file(...)` / `Class::file(...)`), drop wildcard-ObjectType
	// candidates whose method name is a known global-only builtin.
	isPHPMemberCall := m.cfg.language == rules.LangPHP &&
		(n.Type() == "member_call_expression" || n.Type() == "scoped_call_expression")

	var weak *taint.SinkDef
	for _, sink := range candidates {
		if isPHPMemberCall && sink.ObjectType == "" && phpGlobalOnlyBuiltin(sink.MethodName) {
			continue
		}
		// PHP assert() argument-shape gate: the `php.assert` sink models the
		// historical string-eval form `assert("phpinfo()")` (CWE-94 RCE,
		// removed in PHP 8.0). Modern PHP uses `assert()` purely as a runtime
		// type/state assertion whose argument is a BOOLEAN expression
		// (`assert(is_string($x))`, `assert($node !== null)`,
		// `assert($x instanceof Foo)`). Those never evaluate code. Drop the
		// sink only when arg 0 is unambiguously a boolean expression; a string
		// literal, bare variable, or string-concatenation still fires (the
		// genuine `assert($taintedCode)` / `assert("…")` RCE form is preserved).
		if m.cfg.language == rules.LangPHP && sink.ID == "php.assert" &&
			phpAssertArgIsBoolean(n) {
			continue
		}
		// Argument-shape gate (POST-MATCH candidate drop): a handful of
		// bare-keyed sinks distinguish their dangerous form from a safe
		// same-named API purely by the SHAPE of an argument. The default
		// (ArgShapeAny) is a no-op; only sinks that explicitly opt in via
		// RequiresArgShape are inspected. Mirrors the phpAssertArgIsBoolean
		// drop above — it SUPPRESSES a candidate after the structural method
		// match, never loosening matchesCatalogEntry / receiver matching.
		if sink.RequiresArgShape != taint.ArgShapeAny && !argShapeGateOK(n, sink, m.cfg) {
			continue
		}
		// Module binding gate: when a sink declares RequireModule, the
		// call's receiver name (or its base before the first ".") must
		// equal the named module case-insensitively. Tree-sitter walkers
		// don't have import-resolution, so this is a coarser check than
		// astflow's — sufficient for the dominant FP shape (`bytes.decode`
		// matching `pickle.loads`, `nox.session.run` matching `subprocess.run`).
		if sink.RequireModule && !receiverBindsToModule(receiver, sink.Module) {
			continue
		}
		// Swift arg-label entries (`String(contentsOfFile:)`, `nodes(forXPath:)`,
		// …) are keyed under the bare callable base and gated purely on the
		// argument label. The label (e.g. `forXPath`, `contentsOfFile`) is a
		// stronger and more precise identifier than the receiver heuristic —
		// and `matchesCatalogEntry` would otherwise reject them because its
		// method-name check sees the mangled `)` final component — so when the
		// gate applies we accept on the label alone and skip the generic
		// receiver/object-type check. No-op for every non-label entry.
		if labels := m.swiftArgLabels[sink]; len(labels) > 0 {
			if !m.swiftArgLabelGateOK(sink, n) {
				continue
			}
			// Label match is a strong, precise identification — accept now
			// and skip the receiver/wildcard deferral below.
			args := m.cfg.extractCallArgs(n)
			dangerous := collectDangerousArgs(args, sink.DangerousArgs)
			return sink, dangerous
		} else if !matchesCatalogEntry(receiver, methodName, sink.ObjectType, sink.MethodName) {
			continue
		}
		// Wildcard ObjectType ("") matches anything but is the weakest
		// signal; defer it so a strongly-identifying later entry can win.
		// Strong = direct name-equal or last-component name-equal between
		// receiver and ObjectType.
		if sink.ObjectType == "" {
			// Re-validate against the catalog Pattern: a bare-name match on a
			// Pattern-anchored wildcard sink (IPC::Run::run, ngx.pipe.spawn,
			// git clone/fetch, send) must satisfy the Pattern or it is a
			// same-name collision, not the sink.
			if !m.weakSinkPatternOK(sink, n) {
				continue
			}
			if weak == nil {
				weak = sink
			}
			continue
		}
		if !receiverStronglyMatchesType(receiver, sink.ObjectType, sink.MethodName) {
			// Non-wildcard but heuristic match (e.g. abbreviation or
			// receiver-pattern hit). Treat as weak too — a strongly-named
			// later entry should still win. For the "@global" wildcard
			// (a true global builtin called with no receiver, e.g.
			// setInterval/setTimeout), the Pattern carries the real
			// precondition (string first-arg), so re-validate it here too.
			if sink.ObjectType == "@global" && !m.weakSinkPatternOK(sink, n) {
				continue
			}
			if weak == nil {
				weak = sink
			}
			continue
		}
		args := m.cfg.extractCallArgs(n)
		dangerous := collectDangerousArgs(args, sink.DangerousArgs)
		return sink, dangerous
	}
	if weak != nil {
		args := m.cfg.extractCallArgs(n)
		dangerous := collectDangerousArgs(args, weak.DangerousArgs)
		return weak, dangerous
	}
	return nil, nil
}

// phpGlobalOnlyBuiltin reports whether a catalog MethodName names a PHP
// built-in function that only exists as a GLOBAL function (never a member
// method), yet has a method name that frequently collides with user-defined
// object methods. Used to suppress a wildcard-ObjectType sink match when the
// call is actually `$obj->name(...)` / `Class::name(...)`. The list is scoped
// to short, collision-prone builtins; long/unambiguous names (move_uploaded_file,
// simplexml_load_string, mysqli_query) never appear as object methods and need
// no exclusion. The dominant case is `$finfo->file($tmp)` (MIME detection)
// colliding with the global `file()` path-traversal sink.
func phpGlobalOnlyBuiltin(catMethodName string) bool {
	switch catMethodName {
	case "file", "fopen", "readfile", "fread", "fgets",
		"include", "require", "include_once", "require_once",
		"copy", "rename", "unlink", "scandir", "glob",
		// `header`/`setcookie` are global response-header functions, but
		// `header` in particular is an extremely common user-defined method
		// name for accessing structured metadata (e.g. Grav's
		// `$page->header()` returns the page front-matter object, `$this->header($response)`
		// is a framework dispatch helper). The global HTTP-header functions are
		// never invoked as `$obj->header(...)` / `Class::header(...)`, so a
		// member/scoped call by these names is a same-name collision, not the sink.
		"header", "setcookie",
		// `extract` is the global variable-injection sink (`extract($_POST)`,
		// CWE-621), but `->extract()`/`::extract()` is an extremely common
		// framework method that returns field values and never touches local
		// scope (Cake's `$entity->extract([...])` / `$node->extract($fields)`,
		// `Hash::extract(...)`, Collection `->extract()`). A member/scoped call
		// by this name is a same-name collision, not the global sink.
		"extract":
		return true
	}
	return false
}

// phpBooleanPredicateFns names PHP built-in functions that return bool and are
// the idiomatic argument to a defensive assert() — `assert(is_string($x))`. A
// call to one of these as assert()'s first argument cannot be string code-eval.
var phpBooleanPredicateFns = map[string]bool{
	"is_string": true, "is_int": true, "is_integer": true, "is_long": true,
	"is_float": true, "is_double": true, "is_bool": true, "is_array": true,
	"is_object": true, "is_null": true, "is_numeric": true, "is_scalar": true,
	"is_callable": true, "is_iterable": true, "is_countable": true,
	"is_a": true, "is_subclass_of": true, "is_resource": true,
	"isset": true, "empty": true, "in_array": true, "array_key_exists": true,
	"method_exists": true, "property_exists": true, "class_exists": true,
	"interface_exists": true, "function_exists": true, "defined": true,
	"ctype_digit": true, "ctype_alpha": true, "ctype_alnum": true,
	"ctype_xdigit": true, "ctype_space": true, "str_contains": true,
	"str_starts_with": true, "str_ends_with": true, "preg_match": true,
}

// phpAssertArgIsBoolean reports whether the first argument of a PHP assert()
// call node is unambiguously a BOOLEAN expression (and therefore NOT a
// string-evaluable code argument). PHP's assert() only evaluates code when its
// first argument is a string (the legacy form removed in PHP 8.0); a comparison,
// logical, instanceof, negation, or boolean-predicate call is a pure runtime
// assertion. Returns false (i.e. keeps the sink) for string literals, bare
// variables, string concatenation, and any shape it does not recognise — so the
// genuine `assert($code)` / `assert("phpinfo()")` RCE form is never suppressed.
func phpAssertArgIsBoolean(call *ast.Node) bool {
	args := phpExtractCallArgs(call)
	if len(args) == 0 {
		return false
	}
	inner := args[0]
	if inner.Type() == "argument" {
		if kids := inner.NamedChildren(); len(kids) > 0 {
			inner = kids[0]
		}
	}
	switch inner.Type() {
	case "binary_expression":
		// Comparison / logical operators yield a boolean; string concatenation
		// (`.`) or arithmetic does NOT — keep flagging those.
		op := ""
		if o := inner.ChildByFieldName("operator"); o != nil {
			op = o.Text()
		}
		switch op {
		case "===", "!==", "==", "!=", "<>", "<", ">", "<=", ">=", "<=>",
			"&&", "||", "and", "or", "xor", "instanceof":
			return true
		}
		return false
	case "unary_op_expression":
		// Logical negation `!$x` is boolean; only treat `!`-prefixed unaries as
		// boolean (arithmetic `-`/`+`/`~` are not).
		if o := inner.ChildByFieldName("operator"); o != nil && o.Text() == "!" {
			return true
		}
		// Some grammars expose the operator as the first anonymous child.
		if inner.ChildCount() > 0 && inner.Child(0).Text() == "!" {
			return true
		}
		return false
	case "function_call_expression":
		// `assert(is_string($x))` — a boolean-predicate builtin call.
		name := phpCallBaseName(inner)
		return phpBooleanPredicateFns[strings.ToLower(name)]
	}
	return false
}

// phpCallBaseName returns the lowercase-insensitive callee name of a PHP
// function_call_expression (the leading `name` child), or "" if not a plain
// function call.
func phpCallBaseName(call *ast.Node) string {
	if fn := call.ChildByFieldName("function"); fn != nil {
		if fn.Type() == "name" {
			return fn.Text()
		}
		return ""
	}
	// Fallback: first named child if it is a bare name.
	if kids := call.NamedChildren(); len(kids) > 0 && kids[0].Type() == "name" {
		return kids[0].Text()
	}
	return ""
}

// receiverStronglyMatchesType reports whether the receiver name is an
// explicit (case-insensitive) match for the ObjectType — either equal or
// equal to the last "."-separated component. Used to prefer specifically
// named catalog entries over wildcard fallbacks.
//
// The third parameter is the catalog MethodName: when the receiver matches a
// non-final component of the method name (e.g. receiver "Redirect" for
// method "Redirect::found"), that also counts as a strong identification
// for the Rust/C++ struct-method idiom. We exclude the final component to
// avoid spuriously upgrading matches that only fired because of the
// "receiver text accidentally equals method name" fallback in
// matchesCatalogEntry (which can happen when extractCallReceiver returns the
// method identifier instead of the actual receiver — e.g. Groovy nested
// dotted_identifier nodes).
func receiverStronglyMatchesType(receiver, catObjectType, catMethodName string) bool {
	if receiver == "" {
		return false
	}
	r := strings.ToLower(strings.TrimPrefix(receiver, "$"))
	r = strings.ReplaceAll(r, "->", ".")

	// jQuery sink: a `$`-sigil receiver (`$`, `$(...)`, `$el`, `jQuery(...)`) is a
	// STRONG, framework-specific identification of a jQuery object — accept it as a
	// strong match so the jQuery DOM-XSS sink wins deterministically over any
	// wildcard `.html`/`.append` entry. Keyed on the JS-unique "jquery" ObjectType.
	if strings.EqualFold(catObjectType, "jquery") {
		rr := strings.TrimSpace(receiver)
		if rr == "$" || strings.HasPrefix(rr, "$(") || strings.HasPrefix(rr, "$.") ||
			strings.HasPrefix(rr, "jQuery(") || strings.HasPrefix(rr, "jquery(") {
			return true
		}
		if len(rr) >= 2 && rr[0] == '$' {
			c := rr[1]
			if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}

	// GroovyShell RCE sink: the receiver is the GroovyShell constructor or a
	// conventionally-named shell handle (see groovyShellReceiverMatch). Accept
	// as a STRONG identification so the real `GroovyShell().parse(tainted)` /
	// `shell.evaluate(tainted)` flows win, while a benign `dateFormat.parse(s)`
	// is rejected. Keyed on the GroovyShell-unique ObjectType token.
	if strings.Contains(strings.ToLower(catObjectType), "groovyshell") {
		if groovyShellReceiverMatch(receiver) {
			return true
		}
	}

	if catObjectType != "" {
		t := strings.ToLower(strings.ReplaceAll(catObjectType, "::", "."))
		if r == t {
			return true
		}
		parts := strings.Split(t, ".")
		if r == parts[len(parts)-1] {
			return true
		}
	}

	if catMethodName != "" {
		m := strings.ToLower(strings.ReplaceAll(catMethodName, "::", "."))
		m = strings.ReplaceAll(m, "->", ".")
		parts := strings.Split(m, ".")
		// Skip the final component — that's the method name itself, and
		// matching it via receiver indicates a fallback path, not a strong
		// type identification.
		for i, part := range parts {
			if i == len(parts)-1 {
				continue
			}
			if r == part {
				return true
			}
		}
	}
	return false
}

// isSanitizerMethodName reports whether the given call method name is the
// method of ANY registered sanitizer for this language — a deliberately loose
// check (no receiver/object-type heuristic, no Pattern). It is used only as a
// conservative GATE on the broadened chained-receiver taint propagation: when a
// receiver chain contains a call whose method name belongs to a sanitizer (e.g.
// `replace`, `to_i`, `build` for a safe builder), the broadened propagation
// declines and falls back to the prior (pre-broadening) behavior. Because the
// gate only suppresses ADDED propagation, a loose name match is safe: it can
// only revert to baseline, never fabricate new flows or new sanitization.
func (m *tsMatcher) isSanitizerMethodName(n *ast.Node) bool {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return false
	}
	if len(m.sanitizersByMethod[methodName]) > 0 {
		return true
	}
	if short := unqualifyName(methodName); short != methodName {
		if len(m.sanitizersByMethod[short]) > 0 {
			return true
		}
	}
	return false
}

// allSanitizerCategories returns the union of Neutralizes categories across
// EVERY catalog sanitizer entry whose method name matches this call. Used when
// a single builtin name is registered under multiple entries with different
// Neutralizes lists (PHP `basename` → file-read AND file-write); matchSanitizer
// returns only the first, so this collects them all. Receiver/object-type
// heuristics are intentionally skipped — the caller has already established
// that this call is a sanitizer of the relevant value; we only need the full
// neutralized-category set.
func (m *tsMatcher) allSanitizerCategories(n *ast.Node) []taint.SinkCategory {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil
	}
	candidates := m.sanitizersByMethod[methodName]
	if short := unqualifyName(methodName); short != methodName {
		candidates = append(candidates, m.sanitizersByMethod[short]...)
	}
	var cats []taint.SinkCategory
	seen := make(map[taint.SinkCategory]bool)
	for _, san := range candidates {
		for _, c := range san.Neutralizes {
			if !seen[c] {
				seen[c] = true
				cats = append(cats, c)
			}
		}
	}
	return cats
}

// matchSanitizer checks if a call node matches a known sanitizer.
// Returns the sanitizer and the first argument node.
func (m *tsMatcher) matchSanitizer(n *ast.Node) (*taint.SanitizerDef, *ast.Node) {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sanitizersByMethod[methodName]
	short := unqualifyName(methodName)
	if short != methodName {
		candidates = append(candidates, m.sanitizersByMethod[short]...)
	}
	receiver := m.cfg.extractCallReceiver(n)
	for _, san := range candidates {
		if !m.sanitizerCandidateMatches(san, receiver, methodName, n) {
			continue
		}
		args := m.cfg.extractCallArgs(n)
		if len(args) > 0 {
			return san, args[0]
		}
		return san, nil
	}
	return nil, nil
}

// matchSanitizerForCategory finds the first sanitizer matching this call
// whose Neutralizes list contains the given sink category. Unlike
// matchSanitizer (which returns the first call-matching entry regardless of
// what it neutralizes), this is what callers should use when checking
// whether a *specific* sink category is being sanitized — several
// sanitizers can share a method name and only one may neutralise the
// relevant category. Example: `bar.replace("\r", "")` matches both
// py.header.crlf.filter (SnkHeader) and py.log.crlf.replace (SnkLog); when
// the caller is checking an XPath sink, neither applies, but my
// py.str.replace.xpath_apos entry (SnkXPath) does.
func (m *tsMatcher) matchSanitizerForCategory(n *ast.Node, cat taint.SinkCategory) (*taint.SanitizerDef, *ast.Node) {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil, nil
	}
	candidates := m.sanitizersByMethod[methodName]
	short := unqualifyName(methodName)
	if short != methodName {
		candidates = append(candidates, m.sanitizersByMethod[short]...)
	}
	receiver := m.cfg.extractCallReceiver(n)
	for _, san := range candidates {
		neutralizes := false
		for _, c := range san.Neutralizes {
			if c == cat {
				neutralizes = true
				break
			}
		}
		if !neutralizes {
			continue
		}
		if !m.sanitizerCandidateMatches(san, receiver, methodName, n) {
			continue
		}
		args := m.cfg.extractCallArgs(n)
		if len(args) > 0 {
			return san, args[0]
		}
		return san, nil
	}
	return nil, nil
}

// sanitizerCandidateMatches gates a sanitizer against a call node. Handles
// the standard (receiver, methodName, ObjectType) check and the opt-in
// "@argpattern" mode that requires the call text to match san.Pattern.
func (m *tsMatcher) sanitizerCandidateMatches(san *taint.SanitizerDef, receiver, methodName string, n *ast.Node) bool {
	if san.ObjectType == "@argpattern" {
		if san.Pattern == "" {
			return false
		}
		re := m.compileSanitizerPattern(san)
		if re == nil {
			return false
		}
		return re.MatchString(n.Text())
	}
	// Swift arg-label sanitizer entries (`unarchivedObject(ofClass:)`,
	// `NSPredicate(format:argumentArray:)`, …) are keyed under the bare
	// callable base and gated on the argument label, mirroring the sink path.
	if labels := m.swiftArgLabels[san]; len(labels) > 0 {
		return m.swiftArgLabelGateOK(san, n)
	}
	return matchesCatalogEntry(receiver, methodName, san.ObjectType, san.MethodName)
}

// compileSanitizerPattern returns the cached compiled Pattern regex for a
// sanitizer, compiling it on first use. Returns nil if the pattern is
// uncompilable (logged at register time elsewhere; we silently skip here).
func (m *tsMatcher) compileSanitizerPattern(san *taint.SanitizerDef) *regexp.Regexp {
	m.patternMu.Lock()
	defer m.patternMu.Unlock()
	if re, ok := m.patternCache[san.ID]; ok {
		return re
	}
	re, err := regexp.Compile(san.Pattern)
	if err != nil {
		m.patternCache[san.ID] = nil
		return nil
	}
	m.patternCache[san.ID] = re
	return re
}

// receiverBindsToModule returns true when the receiver string starts with
// `module` (case-insensitive). The receiver may be a chain like
// `pickle.SomeClass` or `subprocess` or `nox.Session` — we compare against
// the first dotted segment. Empty receiver fails (a sink that requires a
// module rejects unqualified calls). Empty module passes (no requirement).
func receiverBindsToModule(receiver, module string) bool {
	if module == "" {
		return true
	}
	if receiver == "" {
		return false
	}
	base := receiver
	if idx := strings.Index(receiver, "."); idx >= 0 {
		base = receiver[:idx]
	}
	return strings.EqualFold(base, module)
}

// matchesCatalogEntry checks if a receiver+method pair plausibly matches
// a catalog entry's objectType+methodName.
func matchesCatalogEntry(receiver, callMethod, catObjectType, catMethodName string) bool {
	// Normalize "::", "->", and ":" (Lua colon-call) to "." so all scope/member access is unified.
	catMethodName = strings.ReplaceAll(catMethodName, "::", ".")
	catMethodName = strings.ReplaceAll(catMethodName, "->", ".")
	catMethodName = strings.ReplaceAll(catMethodName, ":", ".")

	// Check method name matches one of the compound parts
	matched := false
	for _, candidate := range strings.Split(catMethodName, "/") {
		candidate = strings.TrimSpace(candidate)
		dotParts := strings.Split(candidate, ".")
		finalMethod := dotParts[len(dotParts)-1]
		if callMethod == finalMethod || unqualifyName(callMethod) == finalMethod || finalMethod == "*" {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// No object type required — always match
	if catObjectType == "" {
		return true
	}

	// Sentinel "@global" means "match only when the call has NO receiver".
	// Used to distinguish bare fetch() (Fetch API) from obj.fetch() (ORM),
	// URL() from new URL(), etc. Set ObjectType to "@global" in the catalog
	// when the function is a true global built-in, not a method on any object.
	if catObjectType == "@global" {
		return receiver == ""
	}

	// Check receiver heuristic
	if receiver == "" {
		// Constructor pattern: callMethod IS the type (e.g., "FileOutputStream" or "java.io.FileOutputStream").
		// Match when the unqualified call method matches the ObjectType.
		shortCall := unqualifyName(callMethod)
		catLastPart := unqualifyName(catObjectType)
		return strings.EqualFold(shortCall, catLastPart)
	}

	lower := strings.ToLower(receiver)
	// Strip PHP $ prefix and normalize -> to . for consistent matching.
	lower = strings.TrimPrefix(lower, "$")
	lower = strings.ReplaceAll(lower, "->", ".")
	catLower := strings.ToLower(catObjectType)

	// Direct name match
	if lower == catLower {
		return true
	}

	// GroovyShell RCE sink: anchored on the GroovyShell constructor / a
	// conventionally-named shell handle rather than a fixed variable, so the
	// generic prefix/abbreviation heuristics below miss `GroovyShell()` and
	// `shell`. Token-scoped to the GroovyShell-unique ObjectType.
	if strings.Contains(catLower, "groovyshell") && groovyShellReceiverMatch(receiver) {
		return true
	}

	// Common receiver name patterns
	if strings.Contains(catLower, "request") {
		if lower == "request" || lower == "req" || lower == "r" || lower == "self.request" {
			return true
		}
	}
	if strings.Contains(catLower, "response") {
		if lower == "response" || lower == "res" || lower == "resp" {
			return true
		}
	}
	if strings.Contains(catLower, "cursor") {
		if lower == "cursor" || lower == "cur" || lower == "c" || lower == "db" {
			return true
		}
	}
	if strings.Contains(catLower, "connection") || strings.Contains(catLower, "conn") {
		if lower == "conn" || lower == "connection" || lower == "db" {
			return true
		}
	}
	if strings.Contains(catLower, "statement") {
		if lower == "stmt" || lower == "statement" || lower == "ps" || lower == "pstmt" {
			return true
		}
	}
	if strings.Contains(catLower, "runtime") {
		if lower == "runtime" || strings.Contains(lower, "runtime") {
			return true
		}
	}
	if strings.Contains(catLower, "session") {
		if lower == "session" || lower == "sess" || lower == "s" {
			return true
		}
	}
	if strings.Contains(catLower, "dircontext") || strings.Contains(catLower, "ldapcontext") || strings.Contains(catLower, "initialdircontext") {
		if lower == "ctx" || lower == "idc" || lower == "dirctx" || lower == "ldapctx" || lower == "context" {
			return true
		}
	}
	if strings.Contains(catLower, "database") || catLower == "pdo" || catLower == "mysqli" {
		if lower == "db" || lower == "database" || lower == "sqlite" || lower == "sqlitedb" || strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".database") {
			return true
		}
	}
	// Cache abstractions (e.g. ASP.NET Core IDistributedCache / IMemoryCache,
	// Guava Cache, ActiveSupport::Cache) are conventionally injected as fields
	// named `_cache`, `cache`, `distributedCache`, or `memoryCache`. None of
	// these is a prefix of the interface type name ("idistributedcache" /
	// "imemorycache"), so the generic abbreviation heuristic below misses them.
	if strings.Contains(catLower, "cache") {
		switch lower {
		case "cache", "_cache", "distributedcache", "_distributedcache",
			"memorycache", "_memorycache", "rediscache", "_rediscache":
			return true
		}
	}
	if strings.Contains(catLower, "context") && !strings.Contains(catLower, "dircontext") && !strings.Contains(catLower, "ldapcontext") {
		if lower == "c" || lower == "ctx" || lower == "context" {
			return true
		}
	}
	if strings.Contains(catLower, "reply") {
		if lower == "reply" || lower == "rep" {
			return true
		}
	}
	if strings.Contains(catLower, "applicationcall") {
		if lower == "call" || lower == "call.request" || strings.HasPrefix(lower, "call.") {
			return true
		}
	}
	// Angular DomSanitizer is injected as a constructor parameter and
	// conventionally bound to `sanitizer`, `domSanitizer`, `_sanitizer`, or
	// `_domSanitizer` (Angular's own docs and virtually all real components use
	// `sanitizer`/`domSanitizer`). `sanitizer` is a SUFFIX, not a prefix, of
	// "domsanitizer", so the generic prefix/abbreviation heuristics below miss it
	// — meaning the bypassSecurityTrust* sinks never bind to the idiomatic
	// receiver. The token "domsanitizer" is Angular-unique, so this alias is
	// framework-scoped. Handles a `this.`-qualified receiver via the last
	// dotted component.
	if strings.Contains(catLower, "domsanitizer") {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		switch recvLast {
		case "sanitizer", "domsanitizer", "_sanitizer", "_domsanitizer", "sanitiser", "ds":
			return true
		}
	}
	// node-expat SAX parser. The parser object returned by `new expat.Parser()`
	// is conventionally bound to `parser` (node-expat's own README uses
	// `var parser = new expat.Parser('UTF-8')`). "parser"/"expat" are neither a
	// prefix nor the last component of the catalog ObjectType "node-expat" (which
	// normalizes to last-component "node-expat"), so the generic heuristics miss
	// them. The catalog Pattern already requires the `parser.`/`expat.` receiver,
	// so this alias just makes the structural matcher agree. JS-scoped via the
	// "node-expat" token.
	if catLower == "node-expat" {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		if recvLast == "parser" || recvLast == "expat" || recvLast == "xmlparser" || recvLast == "saxparser" {
			return true
		}
	}
	// AWS Lambda / API Gateway proxy event. The handler's first argument is
	// conventionally named `event` (AWS's own docs and the @types/aws-lambda
	// APIGatewayProxyEvent typing). "event" is not a prefix of "apigatewayevent",
	// so the generic heuristic misses it. The token "apigatewayevent" is
	// AWS-unique, so this alias is framework-scoped; the source Pattern further
	// requires an API-Gateway-specific field (pathParameters / queryStringParameters
	// / …) so a DOM `event.target` never matches.
	if strings.Contains(catLower, "apigatewayevent") {
		if lower == "event" || lower == "evt" || lower == "apigatewayevent" {
			return true
		}
	}
	// gRPC server handler argument (grpc-node ServerUnaryCall /
	// ServerWritableStream). grpc-node's generated stubs and docs name this
	// argument `call`; the request message and metadata are read as
	// `call.request.<field>` / `call.metadata`. Neither is a prefix of
	// "serverunarycall", so the generic heuristic misses it. The token
	// "serverunarycall" is JS/gRPC-unique, so this alias is language-scoped.
	if strings.Contains(catLower, "serverunarycall") {
		if lower == "call" || strings.HasPrefix(lower, "call.") {
			return true
		}
	}
	// jQuery HTML-manipulation receiver. jQuery objects are produced by the
	// `$(...)` / `jQuery(...)` function and conventionally bound to a `$`-prefixed
	// variable (`$el`, `$content`, `$node`). The matcher must accept ONLY these
	// jQuery-sigil shapes — never a bare `array`/`stream`/`el` — so that
	// `array.append(x)` / `stream.wrap(x)` do not mislabel as jQuery DOM-XSS. The
	// receiver text for `$(el).html(x)` is the call expression `$(el)` (starts with
	// `$`); for `$el.html(x)` it is `$el`. Accept when the receiver is the bare `$`
	// sigil, begins with `$(` / `$.`, is a `$`-prefixed identifier, or is a
	// literal `jQuery(...)` call. The token "jquery" is JS-unique → language-scoped.
	if catLower == "jquery" {
		recv := strings.TrimSpace(receiver)
		if recv == "$" || strings.HasPrefix(recv, "$(") || strings.HasPrefix(recv, "$.") ||
			strings.HasPrefix(recv, "jQuery(") || strings.HasPrefix(recv, "jquery(") {
			return true
		}
		// `$`-prefixed variable (`$el`, `$content`) — the jQuery naming
		// convention. Require the `$` sigil followed by a letter/underscore so a
		// bare `$` (handled above) and a plain identifier without `$` are both
		// rejected.
		if len(recv) >= 2 && recv[0] == '$' {
			c := recv[1]
			if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}
	// graphql-java / Netflix DGS / Spring GraphQL `DataFetchingEnvironment`
	// is conventionally bound to `env`, `dfe`, or `environment` in
	// resolver methods. The catalog's ObjectType ("DataFetchingEnvironment")
	// doesn't otherwise prefix-match these short receiver names, so a
	// resolver like `fetchUser(DataFetchingEnvironment env) { env.getArgument(...) }`
	// would not associate `env.getArgument` with the catalog source
	// without this explicit alias. Without the alias, the GraphQL
	// resolver tests would only fire indirectly via the `isWebHandlerFunc`
	// substring path (which the handler-gate intentionally tightens).
	if strings.Contains(catLower, "datafetchingenvironment") {
		if lower == "env" || lower == "dfe" || lower == "environment" {
			return true
		}
	}
	// Symfony ExpressionLanguage is conventionally bound to `$expressionLanguage`,
	// `$expression`, or the short `$el`. The generic prefix heuristic matches the
	// first two ("expressionlanguage" is prefixed by them) but NOT `el`
	// ("expressionlanguage" does not start with "el"). The token
	// "expressionlanguage" is Symfony-unique, so this alias is framework-scoped;
	// it only widens the receiver set for the EL evaluate/compile sinks.
	if catLower == "expressionlanguage" {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		switch recvLast {
		case "el", "expressionlanguage", "expression", "expressionengine":
			return true
		}
	}
	// Doctrine ORM/DBAL QueryBuilder is conventionally bound to `$qb`,
	// `$queryBuilder`, or `$builder`. The generic prefix heuristic matches
	// `$queryBuilder` ("querybuilder" prefix) but not the short `$qb`/`$builder`
	// ("querybuilder" is not prefixed by either). The token "querybuilder" is
	// Doctrine-unique, so this alias is framework-scoped to the QueryBuilder
	// where()/having() fragment sinks.
	if catLower == "querybuilder" {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		switch recvLast {
		case "qb", "querybuilder", "builder":
			return true
		}
	}

	// Drupal Form API: the FormStateInterface user-input source
	// (`$form_state->getValue()/getValues()/getUserInput()`) is conventionally
	// bound to a parameter named `$form_state` (the name Drupal's own API docs
	// and virtually all module code use; sometimes `$formState`). "form_state"
	// is not a prefix of the interface type "formstateinterface", so the generic
	// abbreviation heuristic below misses it. Without this alias the source only
	// ever fired indirectly via the `isWebHandlerFunc` substring path (a method
	// declared `function submitForm(...)` matching the `Form(` handler marker) —
	// exactly the collision the handler-gate now tightens. Keying on the
	// Drupal-exclusive ObjectType keeps this branch language-/framework-scoped.
	if strings.Contains(catLower, "formstate") {
		switch lower {
		case "form_state", "formstate", "formstateinterface":
			return true
		}
	}

	// java.lang.ProcessBuilder is conventionally bound to `pb` (the OWASP
	// Benchmark and most real code use `ProcessBuilder pb = new ProcessBuilder();
	// pb.command(args);`). The abbreviation `pb` is not a prefix of
	// "processbuilder", so the generic prefix heuristic below misses it,
	// leaving `pb.command(...)` / `pb.start()` unassociated with the command
	// sink. The catalog's own regex Pattern already lists `pb` as an expected
	// receiver, so this alias only makes the tsflow structural matcher agree
	// with that intent.
	if strings.Contains(catLower, "processbuilder") {
		if lower == "pb" || lower == "processbuilder" {
			return true
		}
	}

	// Perl DBI database handles are conventionally bound to `$dbh` (the name
	// DBI's own POD and virtually all real code use), not `$dbi`. The catalog's
	// ObjectType ("DBI") only direct-matches a `$dbi` receiver; "dbh"/"dbc" are
	// neither equal to nor a prefix of "dbi", so the generic heuristics below
	// miss them.
	if catLower == "dbi" {
		if lower == "dbh" || lower == "dbi" || lower == "dbc" || lower == "dbhandle" {
			return true
		}
	}

	// ADO.NET DbDataReader / SqlDataReader (and provider readers like
	// NpgsqlDataReader, MySqlDataReader, SqliteDataReader) are conventionally
	// bound to `reader`, `dr`, or `rdr`. None of these short names is a prefix
	// of "...datareader", so the generic abbreviation heuristic below misses
	// them, leaving idiomatic second-order reads —
	// `var name = reader.GetString(0)` after `cmd.ExecuteReader()` — entirely
	// undetected. The alias is gated on the catalog ObjectType containing
	// "datareader", so it applies only to ADO.NET reader sources and has no
	// cross-language effect.
	if strings.Contains(catLower, "datareader") {
		if lower == "reader" || lower == "dr" || lower == "rdr" || lower == "datareader" {
			return true
		}
	}

	// System.Net.Http.HttpClient / System.Net.WebClient SSRF sinks. The core
	// HttpClient (GetAsync/PostAsync/SendAsync/GetStringAsync/DeleteAsync) and
	// WebClient (DownloadString/DownloadData) sinks carry a fully-qualified
	// ObjectType ("HttpClient" / "System.Net.WebClient") that NO real receiver
	// variable prefix-matches: HttpClient is idiomatically bound to `client`,
	// `httpClient`, `http`, or a field `_httpClient`/`_client`; WebClient to
	// `wc`/`webClient`/`client`. None of these is a prefix of "httpclient" or
	// "webclient", so the generic abbreviation heuristic below misses them and
	// the idiomatic `client.GetAsync(url)` / `wc.DownloadString(url)` SSRF forms
	// go entirely undetected even though the catalog entry exists (the newer
	// Upload*/AsJson* SSRF sinks already use an empty ObjectType + call-anchored
	// Pattern to dodge this; the core sinks predate that and still use the FQN).
	// Keyed on the HTTP-client-exclusive ObjectType tokens so the alias stays
	// C#-scoped. SINK MATCH only — a finding still requires a tainted URL in the
	// dangerous arg (arg 0), so a const/literal URL produces no flow, and a
	// non-HTTP receiver (`cache.GetAsync(key)`) is not in the alias set.
	if strings.Contains(catLower, "httpclient") || strings.Contains(catLower, "webclient") {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		recvLast = strings.TrimPrefix(recvLast, "_")
		switch recvLast {
		case "client", "httpclient", "http", "webclient", "wc", "httpclientinstance":
			return true
		}
	}

	// MBrace.FsPickler serializers (FsPicklerSerializer / BinarySerializer /
	// JsonSerializer / XmlSerializer obtained from FsPickler.Create*Serializer())
	// are conventionally bound to `pickler` or `serializer`. Neither is a prefix
	// of "fspicklerserializer", so the generic abbreviation heuristic misses the
	// `pickler.Deserialize<T>(stream)` RCE sink. Keyed on the FsPickler-exclusive
	// ObjectType token so the alias stays framework-scoped (no cross-language
	// bleed). Only a SINK MATCH — a finding still requires a tainted stream arg.
	if strings.Contains(catLower, "fspickler") {
		if lower == "pickler" || lower == "fspickler" || lower == "fspicklerserializer" {
			return true
		}
	}

	// System.Data.DataSet / DataTable .ReadXml deserialization gadget. The
	// receiver is conventionally `ds`/`dataset`/`dt`/`datatable`/`table` (or an
	// inline `new DataSet()`), none of which is a prefix of the FQN's last
	// component "dataset". Keyed on the DataSet-exclusive ObjectType token so the
	// alias stays C#-scoped. Only a SINK MATCH — a finding still requires a
	// tainted XML argument reaching ReadXml.
	if strings.Contains(catLower, "system.data.dataset") {
		switch lower {
		case "ds", "dataset", "dt", "datatable", "table", "dataset()", "datatable()":
			return true
		}
		if strings.Contains(lower, "new datatable") || strings.Contains(lower, "new dataset") {
			return true
		}
	}

	// System.Xml.Xsl.XslCompiledTransform stylesheet loader. The receiver is
	// conventionally `xslt`, `transform`, `xsl`, or `xslTransform`; none is a
	// prefix of the FQN's last component "xslcompiledtransform". Keyed on the
	// XslCompiledTransform-exclusive ObjectType token so the alias stays
	// C#-scoped. SINK MATCH only — a finding still requires a tainted stylesheet
	// argument reaching Load.
	if strings.Contains(catLower, "xslcompiledtransform") {
		switch lower {
		case "xslt", "transform", "xsl", "xsltransform", "xslttransform", "xform":
			return true
		}
	}

	// Rust std::process::Command builder. The idiomatic shape is a fluent
	// chain — `Command::new("sh").arg("-c").arg(tainted).output()` — so the
	// tree-sitter receiver of `.arg`/`.args`/`.output`/`.spawn`/`.status` is
	// the WHOLE inner chain text (e.g. `Command::new("sh").arg("-c")`), and the
	// variable form binds to `cmd`/`command`. Neither shape matches the generic
	// type-name/abbreviation heuristics above, so the command sink would never
	// associate with the chained call. The ObjectType "std::process::Command" /
	// "std::process" is Rust-exclusive (no other catalog uses it), so keying on
	// it keeps this branch language-scoped. FP-safe: this only reports a SINK
	// MATCH — a finding still requires a TAINTED argument, and the common clap
	// false-positive `Command::new(...).arg(Arg::new("name"))` passes a constant
	// builder, not user input, so it produces no flow.
	//
	// Match the FULLY-QUALIFIED "std::process" (Rust path syntax), not a bare
	// "process" substring: other languages have process/exec sinks whose
	// ObjectType also contains "process" (e.g. C++ boost::process), and the
	// `cmd`/`command`/`command::new` receiver heuristic below would otherwise
	// flip their findings' categories. "std::process" appears only in the Rust
	// catalog.
	if strings.Contains(catLower, "std::process") {
		// Direct variable binding (`let mut cmd = Command::new(..); cmd.arg(t)`)
		// or constructor chain text (`Command::new("sh").arg("-c")`).
		if lower == "cmd" || lower == "command" ||
			strings.Contains(lower, "command::new") ||
			strings.Contains(lower, "command.new") {
			return true
		}
		// Variable-bound builder chain: `cmd.arg("-c").arg(tainted)` — the
		// receiver of the outer `.arg` is `cmd.arg("-c")`, whose first dotted
		// component is the builder variable. Accept when that base is the
		// conventional Command binding name.
		if base := strings.SplitN(lower, ".", 2)[0]; base == "cmd" || base == "command" {
			return true
		}
	}

	// Perl CGI.pm objects are conventionally bound to `$q` or `$query` (the
	// names CGI.pm's own POD uses), not just `$cgi`. The catalog's ObjectType
	// ("CGI") doesn't prefix-match these short receiver names, so an idiomatic
	// `my $q = CGI->new; $q->param(...)` would not associate `$q->param` with
	// the catalog source without this explicit alias.
	if strings.Contains(catLower, "cgi") {
		if lower == "q" || lower == "query" || lower == "cgi" || lower == "cgiobj" || lower == "cgiquery" {
			return true
		}
	}

	// Swift WKWebView is conventionally bound to `webView` / `webview` (and
	// `wkWebView`). The "WK" prefix on the type means the receiver name is not
	// a prefix of the type, so the generic abbreviation heuristic below misses
	// it, leaving `webView.evaluateJavaScript(...)` / `.loadHTMLString(...)`
	// unassociated with the WKWebView XSS/eval sinks. The token "wkwebview" is
	// Swift-unique so this alias is safe across languages.
	if strings.Contains(catLower, "wkwebview") {
		if lower == "webview" || lower == "wkwebview" || strings.HasSuffix(lower, ".webview") {
			return true
		}
	}

	// JPA / Hibernate / Doctrine persistence context. The JPA-standard
	// `EntityManager` (and Doctrine's `$em`) is idiomatically bound to `em` or
	// `entityManager`; neither is a prefix of "entitymanager" (the abbreviation
	// `em` diverges at the 2nd character), so the generic abbreviation heuristic
	// below misses them, leaving `em.createNativeQuery(sql)` and
	// `$em->createQuery(dql)` unassociated with their catalog SQL-injection
	// sinks/sources. Hibernate's `org.hibernate.Session` (ObjectType "Session")
	// EXTENDS `jakarta.persistence.EntityManager`, sharing the
	// createQuery/createNativeQuery/find API — and the Hibernate query sinks
	// already list `entityManager` in their regex Pattern — so map these
	// receivers to the exact "Session" type as well. Scoped to the JPA-specific
	// receiver spellings (`em`/`entityManager`/`entityMgr`) so it cannot bleed
	// into unrelated *Session types (Cassandra, Neo4j, websocket Session) that
	// are never bound to those names. Handles a `this.`-qualified receiver by
	// matching on the final dotted component.
	if strings.Contains(catLower, "entitymanager") || catLower == "session" {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		if recvLast == "em" || recvLast == "entitymanager" || recvLast == "entitymgr" {
			return true
		}
	}

	// JDO (DataNucleus/JPOX) javax.jdo.PersistenceManager is, by the JDO spec's
	// own examples and virtually all real code, the field/local `pm` (sometimes
	// `persistenceManager`/`pmgr`). The abbreviation `pm` diverges from the type
	// last component "persistencemanager" at the 2nd character, so the generic
	// prefix heuristic below misses it and the JDO newQuery SQLi sink never
	// binds. Keyed on the JDO-exclusive ObjectType so it stays framework-scoped.
	// A receiver-name match alone is only a SINK MATCH — a finding still
	// requires a tainted (concatenated) query argument, and the parameterized
	// declareParameters/setParameters path is neutralized by the JDO sanitizer.
	if strings.Contains(catLower, "persistencemanager") {
		recvLast := lower
		if i := strings.LastIndex(recvLast, "."); i >= 0 {
			recvLast = recvLast[i+1:]
		}
		if recvLast == "pm" || recvLast == "persistencemanager" || recvLast == "pmgr" {
			return true
		}
	}

	// jOOQ DSLContext (org.jooq.DSLContext) is, by jOOQ's own documentation and
	// nearly all real code, the injected field `create` (the name jOOQ's
	// tutorials use), `dsl`, `ctx`, or `dslContext`. Only `dsl`/`dslcontext`
	// prefix-match the type's last component "dslcontext"; `create`/`ctx` do
	// not, so the generic heuristic below misses them and the jOOQ plain-SQL
	// String-overload sinks never bind. Keying on the jOOQ-exclusive
	// ObjectType keeps this alias framework-scoped. The receiver name alone is
	// only a SINK MATCH — a finding still requires a tainted SQL argument, and
	// the typed-DSL safe path is neutralized by the DSL.* sanitizers.
	recvLastDot := lower
	if i := strings.LastIndex(recvLastDot, "."); i >= 0 {
		recvLastDot = recvLastDot[i+1:]
	}
	if catLower == "org.jooq.dslcontext" {
		switch recvLastDot {
		case "create", "dsl", "ctx", "dslcontext", "jooq":
			return true
		}
	}

	// MyBatis-Plus AbstractWrapper
	// (com.baomidou.mybatisplus.core.conditions.AbstractWrapper) is
	// conventionally bound to `wrapper`, `qw` / `queryWrapper`,
	// `uw` / `updateWrapper`, or `lqw` (LambdaQueryWrapper). None of the
	// abbreviations prefix-match the type's last component "abstractwrapper",
	// so the generic heuristic misses them. The alias is keyed on the
	// MyBatis-Plus-exclusive ObjectType.
	if catLower == "com.baomidou.mybatisplus.core.conditions.abstractwrapper" {
		switch recvLastDot {
		case "wrapper", "qw", "querywrapper", "uw", "updatewrapper", "lqw", "luw", "lambdaquerywrapper":
			return true
		}
	}

	// Archive entry types (java.util.zip.ZipEntry / java.util.jar.JarEntry /
	// org.apache.commons.compress.archivers.ArchiveEntry) are conventionally
	// bound to `entry`, `e`, `ze` (zip entry), or `zipEntry`/`archiveEntry`
	// during extraction loops. None of `entry`/`e`/`ze` prefix-matches the
	// type's last component, so the generic heuristic misses the Zip-Slip
	// `entry.getName()` read. Keyed on the archive-entry ObjectTypes so the
	// alias stays scoped to the Zip-Slip source (CWE-22).
	if strings.HasSuffix(catLower, "zipentry") || strings.HasSuffix(catLower, "jarentry") ||
		strings.HasSuffix(catLower, "archiveentry") {
		switch recvLastDot {
		case "entry", "e", "ze", "zipentry", "jarentry", "archiveentry":
			return true
		}
	}

	// Spring JdbcTemplate (org.springframework.jdbc.core.JdbcTemplate). A Spring
	// app frequently autowires MULTIPLE JdbcTemplate beans that must each carry a
	// distinct, qualified field name — `applicationJdbcTemplate`,
	// `appJdbcTemplate`, `readOnlyJdbcTemplate`, `primaryJdbcTemplate`, … — so the
	// receiver in `applicationJdbcTemplate.query(sql, rowMapper)` is NOT the bare
	// `jdbcTemplate`. The generic abbreviation heuristic only fires when the
	// receiver is a PREFIX of the type's last component ("jdbc" → "jdbctemplate"),
	// never when the type's last component is a SUFFIX of a qualifier-prefixed
	// receiver — so every `*JdbcTemplate`-named field misses the JdbcTemplate
	// CWE-89 sinks (query/update/execute/queryForList/…). Accept a receiver whose
	// last dotted component ENDS WITH "jdbctemplate" (covers `this.jdbcTemplate`
	// via recvLastDot too). The token "jdbctemplate" is Spring-JDBC-unique, so the
	// alias stays framework-scoped; this is only a SINK MATCH — a finding still
	// requires a tainted, concatenation-built SQL argument reaching arg 0 (the
	// parameterized `query(sql, params, mapper)` form carries no taint and stays
	// clean). Mirrors the catalog's own intent: NamedParameterJdbcTemplate already
	// enumerates its receiver-name variants in the sink Pattern for the same
	// reason. Keyed on the bare ObjectType "JdbcTemplate" (last component
	// "jdbctemplate"); the namedparam FQN ("...namedparam.namedparameterjdbctemplate")
	// also ends with "jdbctemplate" but its sinks are already receiver-anchored in
	// their Pattern, so no behavior change there.
	if strings.HasSuffix(catLower, "jdbctemplate") && strings.HasSuffix(recvLastDot, "jdbctemplate") {
		return true
	}

	// Partial match: "Request" matches "flask.Request", "express.Request", etc.
	normalized := strings.ReplaceAll(catObjectType, "::", ".")
	typeParts := strings.Split(normalized, ".")
	lastPart := strings.ToLower(typeParts[len(typeParts)-1])
	if lower == lastPart {
		return true
	}

	// Abbreviation heuristic: receiver is a prefix of the type name
	// (e.g., "stmt" is a prefix of "statement", "req" is a prefix of "request",
	// "r" is a prefix of "runtime")
	if len(lower) >= 1 && strings.HasPrefix(lastPart, lower) {
		return true
	}

	// Qualified receiver heuristic: receiver contains dots (e.g., "java.security.MessageDigest")
	// — check if the last component of the receiver matches the type.
	if strings.Contains(lower, ".") {
		recvParts := strings.Split(lower, ".")
		recvLast := recvParts[len(recvParts)-1]
		if recvLast == lastPart {
			return true
		}
		// Also check abbreviation: "jdbctemplate" prefix of "jdbctemplate"
		if len(recvLast) >= 2 && strings.HasPrefix(lastPart, recvLast) {
			return true
		}
		// Check if any component of receiver contains the type (e.g., "DatabaseHelper.JDBCtemplate" contains "jdbctemplate")
		for _, rp := range recvParts {
			if strings.EqualFold(rp, lastPart) {
				return true
			}
		}
	}

	// Chained call receiver: receiver text contains method calls that return
	// the expected object type.
	if strings.Contains(lower, "getsession") && strings.Contains(catLower, "session") {
		return true
	}
	// Servlet PrintWriter obtained from the response. Java spells it
	// `response.getWriter().write(...)` (a method call → receiver contains
	// "getwriter"); Kotlin's idiomatic property-access syntax spells the
	// same getter `response.writer.write(...)`, so the receiver of the write
	// is `response.writer` — a navigation chain ending in `.writer`. Both
	// resolve to a PrintWriter, so bridge a receiver ending in `.writer`
	// (or being the bare `writer`) to a writer-typed sink, same as getWriter().
	if strings.Contains(catLower, "writer") &&
		(strings.Contains(lower, "getwriter") || lower == "writer" || strings.HasSuffix(lower, ".writer")) {
		return true
	}
	if strings.Contains(lower, "getconnection") && (strings.Contains(catLower, "connection") || strings.Contains(catLower, "conn")) {
		return true
	}
	// Getter-chain heuristics: ctx.response(), ctx.request(), ctx.body()
	if strings.HasSuffix(lower, ".response()") && strings.Contains(catLower, "response") {
		return true
	}
	if strings.HasSuffix(lower, ".request()") && strings.Contains(catLower, "request") {
		return true
	}
	if strings.HasSuffix(lower, ".body()") && strings.Contains(catLower, "body") {
		return true
	}

	// Rust/C++ struct-method heuristic: receiver matches a component of the
	// method name (e.g., receiver "Command" matches catMethodName "Command::new").
	normalizedMethod := strings.ReplaceAll(catMethodName, "::", ".")
	for _, part := range strings.Split(normalizedMethod, ".") {
		if strings.EqualFold(lower, part) {
			return true
		}
	}

	return false
}

// collectDangerousArgs returns argument nodes at the dangerous positions.
func collectDangerousArgs(args []*ast.Node, dangerousArgs []int) []*ast.Node {
	var dangerous []*ast.Node
	for _, argIdx := range dangerousArgs {
		if argIdx == -1 {
			dangerous = append(dangerous, args...)
			break
		}
		if argIdx >= 0 && argIdx < len(args) {
			dangerous = append(dangerous, args[argIdx])
		}
	}
	return dangerous
}
