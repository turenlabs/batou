// Package phpast — BATOU-OWNCLOUD-001
//
// Detects ownCloud / Nextcloud AppFramework controller methods that are
// exposed as PUBLIC, UNAUTHENTICATED HTTP routes (via @PublicPage docblock
// or #[PublicPage] PHP 8 attribute) whose parameters flow to HTTP-client /
// file-system / process-execution sinks.
//
// Background
// ----------
// In the OCP AppFramework, a controller method annotated with @PublicPage
// becomes callable by unauthenticated remote callers. Treating the method's
// formal parameters as attacker-controlled is therefore correct. When such
// a parameter flows directly into an outbound HTTP request, a file read or
// write, or a shell command, that's a classic public-route sink:
//
//   - HTTP client  → SSRF (CWE-918)
//   - file_get_contents / fopen / include → LFI / path traversal (CWE-22)
//   - file_put_contents / fwrite / unlink → arbitrary file write (CWE-22)
//   - exec / shell_exec / system / popen / `…$param…` → RCE (CWE-78)
//
// The headline real-world miss this rule catches is
// apps/files_sharing/.../Controllers/ExternalSharesController::testRemote($remote)
// in ownCloud core, where `$remote` flows unvalidated into the federated
// share probe (issued via the IClientService HTTP client).
//
// Scope
// -----
// This is an intentionally focused, single-rule heuristic that emulates a
// "this param is a tainted source" entry-point inside its own scope. It is
// NOT wired into the taint engine — see E9-T1 for the general entry-point
// catalog that will subsume it.
package phpast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// PublicPageSinkAnalyzer flags @PublicPage / #[PublicPage] controller
// methods whose parameters flow into dangerous sinks.
type PublicPageSinkAnalyzer struct{}

func init() {
	rules.Register(&PublicPageSinkAnalyzer{})
}

func (p *PublicPageSinkAnalyzer) ID() string   { return "BATOU-OWNCLOUD-AST-001" }
func (p *PublicPageSinkAnalyzer) Name() string { return "ownCloud @PublicPage parameter to dangerous sink" }
func (p *PublicPageSinkAnalyzer) Description() string {
	return "Detects ownCloud / Nextcloud AppFramework controller methods marked @PublicPage (or #[PublicPage]) whose attacker-controlled parameters flow to HTTP clients (SSRF), filesystem sinks (LFI / arbitrary file write), or process execution (RCE)."
}
func (p *PublicPageSinkAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (p *PublicPageSinkAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

// sinkCategory classifies the kind of dangerous sink a parameter reached.
type sinkCategory int

const (
	sinkUnknown sinkCategory = iota
	sinkHTTPClient
	sinkFileRead
	sinkFileWrite
	sinkProcessExec
)

// sinkMeta carries the per-category metadata that lands in the finding.
type sinkMeta struct {
	category    sinkCategory
	categoryStr string // raw value for Finding.SinkCategory
	cwe         string
	owasp       string
	titleNoun   string // "HTTP client (SSRF)" etc — slotted into the title
	fixHint     string
}

func (m sinkMeta) tag() string {
	switch m.category {
	case sinkHTTPClient:
		return "ssrf"
	case sinkFileRead, sinkFileWrite:
		return "lfi"
	case sinkProcessExec:
		return "rce"
	}
	return "publicpage"
}

// Built-in bare-name function sinks. Tree-sitter exposes these as
// function_call_expression with a "name" child.
var (
	fileReadFuncs = map[string]bool{
		"file_get_contents":   true, // also a network sink, but we treat as file unless URL detected
		"fopen":               true,
		"readfile":            true,
		"file":                true,
		"parse_ini_file":      true,
		"simplexml_load_file": true,
		"glob":                true,
		"scandir":             true,
		"is_file":             true,
		"is_dir":              true,
		"is_readable":         true,
		"file_exists":         true,
		"realpath":            true,
	}
	fileWriteFuncs = map[string]bool{
		"file_put_contents":  true,
		"fwrite":             true,
		"move_uploaded_file": true,
		"rename":             true,
		"unlink":             true,
		"mkdir":              true,
		"rmdir":              true,
		"touch":              true,
		"chmod":              true,
		"copy":               true,
		"link":               true,
		"symlink":            true,
	}
	processExecFuncs = map[string]bool{
		"exec":       true,
		"shell_exec": true,
		"system":     true,
		"passthru":   true,
		"popen":      true,
		"proc_open":  true,
		"pcntl_exec": true,
	}
	// Methods invoked on an HTTP-client-looking object (Guzzle, IClient,
	// curl wrappers, etc.).
	httpClientMethods = map[string]bool{
		"get":       true,
		"post":      true,
		"put":       true,
		"delete":    true,
		"patch":     true,
		"head":      true,
		"options":   true,
		"request":   true,
		"send":      true,
		"sendAsync": true,
	}
)

// receiverLooksHTTPClient returns true if the receiver chain text contains
// a recognisable HTTP-client identifier substring.
func receiverLooksHTTPClient(text string) bool {
	t := strings.ToLower(text)
	return strings.Contains(t, "client") ||
		strings.Contains(t, "http") ||
		strings.Contains(t, "guzzle") ||
		strings.Contains(t, "curl") ||
		strings.Contains(t, "fetch")
}

// callArgsLookHTTPClient returns true if any argument text contains an
// HTTP-client identifier substring (e.g. clientService passed alongside the
// param, as in testRemote → testRemoteUrl($this->clientService, $remote)).
func callArgsLookHTTPClient(args []string) bool {
	for _, a := range args {
		if receiverLooksHTTPClient(a) {
			return true
		}
	}
	return false
}

func (p *PublicPageSinkAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	// Cheap pre-filter: if the file has no @PublicPage / #[PublicPage] at
	// all, skip entirely. Keeps the per-file cost negligible.
	if !strings.Contains(ctx.Content, "PublicPage") {
		return nil
	}

	v := &publicPageVisitor{filePath: ctx.FilePath}
	v.walk(tree.Root())
	return v.findings
}

type publicPageVisitor struct {
	filePath string
	findings []rules.Finding
}

func (v *publicPageVisitor) walk(root *ast.Node) {
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "method_declaration" {
			v.checkMethod(n)
		}
		return true
	})
}

// checkMethod inspects one method_declaration node.
func (v *publicPageVisitor) checkMethod(method *ast.Node) {
	if !methodIsPublicPage(method) {
		return
	}
	params := extractParamNames(method) // e.g. ["$remote"]
	if len(params) == 0 {
		return
	}
	body := method.ChildByFieldName("body")
	if body == nil {
		return
	}

	// Intra-procedural single-pass taint propagation across local-variable
	// assignments. Two-step expansion suffices for the common
	//     $url = "https://" . $remote . "/path";
	//     $client->get($url);
	// pattern. Deeper aliasing chains are out of scope for this MVP —
	// flagged as a known-false-negative in the rule description.
	tainted := make(map[string]bool, len(params))
	for _, p := range params {
		tainted[p] = true
	}
	for pass := 0; pass < 3; pass++ {
		grew := false
		body.Walk(func(n *ast.Node) bool {
			if n.Type() != "assignment_expression" {
				return true
			}
			lhsNode := n.ChildByFieldName("left")
			rhsNode := n.ChildByFieldName("right")
			if lhsNode == nil || rhsNode == nil {
				return true
			}
			if lhsNode.Type() != "variable_name" {
				return true
			}
			lhs := lhsNode.Text()
			if tainted[lhs] {
				return true
			}
			rhsText := rhsNode.Text()
			for v := range tainted {
				if containsVariable(rhsText, v) {
					tainted[lhs] = true
					grew = true
					break
				}
			}
			return true
		})
		if !grew {
			break
		}
	}

	// Walk the body looking for calls that consume any tainted variable.
	taintedList := make([]string, 0, len(tainted))
	for t := range tainted {
		taintedList = append(taintedList, t)
	}
	body.Walk(func(call *ast.Node) bool {
		switch call.Type() {
		case "function_call_expression", "member_call_expression", "scoped_call_expression":
			v.checkCall(method, call, taintedList)
		}
		// continue descending — nested calls also count
		return true
	})
}

// methodIsPublicPage returns true iff `method` is annotated with @PublicPage
// (PHPDoc comment immediately above) or #[PublicPage] (PHP 8 attribute).
func methodIsPublicPage(method *ast.Node) bool {
	// Attribute style: #[PublicPage] sits as an "attribute_list" child of
	// the method (field "attributes" in tree-sitter-php).
	for i := 0; i < method.ChildCount(); i++ {
		c := method.Child(i)
		if c.Type() != "attribute_list" {
			continue
		}
		if attributeListHasPublicPage(c) {
			return true
		}
	}
	// Docblock style: the previous sibling at the parent (declaration_list)
	// level is a "comment" node containing "@PublicPage".
	parent := method.Parent()
	if parent == nil {
		return false
	}
	prev := previousNamedSibling(parent, method)
	if prev != nil && prev.Type() == "comment" && commentMentionsPublicPage(prev.Text()) {
		return true
	}
	return false
}

// attributeListHasPublicPage checks an attribute_list subtree for an
// attribute named "PublicPage" (bare or namespaced).
func attributeListHasPublicPage(list *ast.Node) bool {
	found := false
	list.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() == "attribute" {
			// `attribute` -> name (could be `name` or `qualified_name`)
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "name" || c.Type() == "qualified_name" {
					if attributeNameIsPublicPage(c.Text()) {
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

// attributeNameIsPublicPage handles bare ("PublicPage") and fully-qualified
// ("\\OCP\\AppFramework\\Http\\Attribute\\PublicPage") attribute names.
func attributeNameIsPublicPage(name string) bool {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "\\")
	// Compare the last namespace segment.
	if idx := strings.LastIndex(name, "\\"); idx >= 0 {
		name = name[idx+1:]
	}
	return name == "PublicPage"
}

// commentMentionsPublicPage returns true if a docblock contains @PublicPage
// (case-sensitive — ownCloud uses exact casing).
func commentMentionsPublicPage(comment string) bool {
	if !strings.Contains(comment, "@PublicPage") {
		return false
	}
	// Defend against accidental hits inside @param/@return descriptions —
	// require the token to appear at the start of a comment line after the
	// usual `*` or whitespace prefix.
	for _, line := range strings.Split(comment, "\n") {
		trimmed := strings.TrimLeft(line, " \t*/")
		if strings.HasPrefix(trimmed, "@PublicPage") {
			return true
		}
	}
	return false
}

// previousNamedSibling returns the named sibling node that immediately
// precedes `target` in `parent`'s child list, or nil if none.
func previousNamedSibling(parent, target *ast.Node) *ast.Node {
	var last *ast.Node
	for i := 0; i < parent.ChildCount(); i++ {
		c := parent.Child(i)
		if c == target {
			return last
		}
		if c.IsNamed() {
			last = c
		}
	}
	return nil
}

// extractParamNames returns the formal parameter names of the method as
// "$name" strings (with the leading sigil).
func extractParamNames(method *ast.Node) []string {
	params := method.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var out []string
	for i := 0; i < params.ChildCount(); i++ {
		c := params.Child(i)
		if c.Type() != "simple_parameter" &&
			c.Type() != "variadic_parameter" &&
			c.Type() != "property_promotion_parameter" {
			continue
		}
		name := c.ChildByFieldName("name")
		if name != nil {
			out = append(out, name.Text())
		}
	}
	return out
}

// checkCall inspects a single call expression for the public-page param
// flowing to a recognised sink. Emits a finding if so.
func (v *publicPageVisitor) checkCall(method, call *ast.Node, params []string) {
	args := callArgumentNodes(call)
	if len(args) == 0 {
		return
	}
	usedParam, _ := callUsesParam(args, params)
	if usedParam == "" {
		return
	}

	meta, ok := classifyCall(call, args)
	if !ok {
		return
	}

	// Resolve the method name for the description.
	methodName := ""
	if n := method.ChildByFieldName("name"); n != nil {
		methodName = n.Text()
	}

	line := int(call.StartRow()) + 1
	matchedText := truncate(call.Text(), 200)
	title := "Public route parameter flows to " + meta.titleNoun

	desc := "Controller method `" + methodName + "` is marked @PublicPage / #[PublicPage] (publicly accessible without authentication). Parameter " + usedParam + " flows into a " + meta.titleNoun + " sink without observable validation. Untrusted callers can supply arbitrary values, enabling exploitation appropriate to the sink (e.g. SSRF, path traversal, RCE)."

	suggestion := meta.fixHint

	v.findings = append(v.findings, rules.Finding{
		RuleID:          v.id(),
		Severity:        rules.Critical,
		SeverityLabel:   rules.Critical.String(),
		Title:           title,
		Description:     desc,
		FilePath:        v.filePath,
		LineNumber:      line,
		MatchedText:     matchedText,
		Suggestion:      suggestion,
		CWEID:           meta.cwe,
		OWASPCategory:   meta.owasp,
		Language:        rules.LangPHP,
		Confidence:      "high",
		ConfidenceScore: 0.85,
		SourceCategory:  "user_input",
		SinkCategory:    meta.categoryStr,
		Tags:            []string{"owncloud", "publicpage", meta.tag(), "ast"},
	})
}

// id is the stable rule ID emitted on every finding.
func (v *publicPageVisitor) id() string { return "BATOU-OWNCLOUD-AST-001" }

// callArgumentNodes returns the named children of the call's arguments
// node. For function_call_expression / member_call_expression both expose
// `arguments` as a field; scoped_call_expression also uses field "arguments".
func callArgumentNodes(call *ast.Node) []*ast.Node {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		// object_creation_expression has arguments as a positional child,
		// but we don't currently flag that shape.
		return nil
	}
	var out []*ast.Node
	for i := 0; i < args.ChildCount(); i++ {
		c := args.Child(i)
		if !c.IsNamed() {
			continue
		}
		if c.Type() == "argument" {
			// unwrap one level
			if inner := firstNamed(c); inner != nil {
				out = append(out, inner)
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// firstNamed returns the first named child of n, or nil.
func firstNamed(n *ast.Node) *ast.Node {
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			return c
		}
	}
	return nil
}

// callUsesParam returns the matching parameter name if any of `params`
// appears in `args` (as a direct variable_name or anywhere in the
// argument's text). Also returns the argument's text. Empty result means
// none of the params is used.
func callUsesParam(args []*ast.Node, params []string) (string, string) {
	for _, a := range args {
		text := a.Text()
		// Cheap text scan first — handles `$remote` direct, `$remote . "..."`,
		// `"https://" . $remote`, `$tmp = $remote; ... f($tmp)` is NOT handled
		// (intermediate vars are explicitly out of scope for this MVP rule).
		for _, p := range params {
			if containsVariable(text, p) {
				return p, text
			}
		}
	}
	return "", ""
}

// containsVariable returns true if `text` references the PHP variable
// `varName` (e.g. "$remote") as a whole token — i.e. not as a prefix of a
// longer identifier like "$remoteHost".
func containsVariable(text, varName string) bool {
	if !strings.HasPrefix(varName, "$") || len(varName) < 2 {
		return false
	}
	for {
		idx := strings.Index(text, varName)
		if idx < 0 {
			return false
		}
		end := idx + len(varName)
		if end < len(text) {
			next := text[end]
			if (next >= 'a' && next <= 'z') ||
				(next >= 'A' && next <= 'Z') ||
				(next >= '0' && next <= '9') ||
				next == '_' {
				// it's the prefix of a longer identifier — keep scanning
				text = text[end:]
				continue
			}
		}
		return true
	}
}

// classifyCall returns a sinkMeta if the call shape matches a known
// dangerous sink. The boolean is false when the call is harmless.
func classifyCall(call *ast.Node, args []*ast.Node) (sinkMeta, bool) {
	name := callName(call)

	// 1. Bare-name function calls (function_call_expression).
	if call.Type() == "function_call_expression" {
		if processExecFuncs[name] {
			return processExecMeta(), true
		}
		if fileWriteFuncs[name] {
			return fileWriteMeta(), true
		}
		if fileReadFuncs[name] {
			// file_get_contents with an http(s):// URL is SSRF, not LFI.
			// Detect by inspecting the first arg's text.
			if name == "file_get_contents" && firstArgLooksLikeURL(args) {
				return httpClientMeta(), true
			}
			return fileReadMeta(), true
		}
		if name == "curl_setopt" {
			// curl_setopt($ch, CURLOPT_URL, $param) — second positional
			// constant is CURLOPT_URL.
			if len(args) >= 3 && strings.Contains(args[1].Text(), "CURLOPT_URL") {
				return httpClientMeta(), true
			}
		}
		if name == "curl_init" || name == "curl_exec" {
			return httpClientMeta(), true
		}
		// include/require are usually their own statement type but PHP
		// sometimes parses them as function_call_expression depending on
		// surrounding context.
		if name == "include" || name == "include_once" || name == "require" || name == "require_once" {
			return fileReadMeta(), true
		}
	}

	// 2. Method calls — HTTP-client-shaped invocations.
	if call.Type() == "member_call_expression" || call.Type() == "scoped_call_expression" {
		recvText := callReceiverText(call)
		argTexts := make([]string, 0, len(args))
		for _, a := range args {
			argTexts = append(argTexts, a.Text())
		}
		// Strongest signal: HTTP-method name on an HTTP-client receiver.
		if httpClientMethods[name] && receiverLooksHTTPClient(recvText) {
			return httpClientMeta(), true
		}
		// Weaker but very common: the call name itself signals an outbound
		// HTTP fetch. We deliberately use specific tokens rather than a
		// catch-all "request" substring — internal helper names like
		// `validateRequest` would otherwise be flagged as SSRF.
		lname := strings.ToLower(name)
		if strings.Contains(lname, "http") ||
			strings.Contains(lname, "fetchurl") ||
			strings.Contains(lname, "fetchremote") ||
			strings.Contains(lname, "geturl") ||
			strings.Contains(lname, "sendrequest") ||
			strings.Contains(lname, "makerequest") ||
			strings.Contains(lname, "httprequest") {
			return httpClientMeta(), true
		}
		// Pattern observed in ExternalSharesController::testRemote — a
		// helper call (`testRemoteUrl`) that takes an explicit HTTP client
		// as one of its arguments alongside the public param. The receiver
		// looks innocuous but the argument list reveals the network flow.
		if callArgsLookHTTPClient(argTexts) {
			return httpClientMeta(), true
		}
		// Catch-all: explicit method names from our HTTP map, even on an
		// unrecognised receiver (Symfony HttpClient, GuzzleHttp\Client,
		// etc.). Lower confidence — handled by the same meta.
		if httpClientMethods[name] && (strings.Contains(strings.ToLower(recvText), "send") || strings.Contains(strings.ToLower(recvText), "request")) {
			return httpClientMeta(), true
		}
	}
	return sinkMeta{}, false
}

func callName(call *ast.Node) string {
	// function_call_expression: function field
	if fn := call.ChildByFieldName("function"); fn != nil {
		if fn.Type() == "name" || fn.Type() == "variable_name" {
			return fn.Text()
		}
		if fn.Type() == "qualified_name" {
			// Last name component
			for i := fn.ChildCount() - 1; i >= 0; i-- {
				c := fn.Child(i)
				if c.Type() == "name" {
					return c.Text()
				}
			}
		}
	}
	// member_call_expression / scoped_call_expression: name field
	if n := call.ChildByFieldName("name"); n != nil {
		return n.Text()
	}
	return ""
}

func callReceiverText(call *ast.Node) string {
	if o := call.ChildByFieldName("object"); o != nil {
		return o.Text()
	}
	if s := call.ChildByFieldName("scope"); s != nil {
		return s.Text()
	}
	return ""
}

// firstArgLooksLikeURL returns true if the first argument's textual form
// contains "http://" or "https://" — strong signal that the file_get_contents
// call is actually a network fetch (SSRF), not a local-file read.
func firstArgLooksLikeURL(args []*ast.Node) bool {
	if len(args) == 0 {
		return false
	}
	t := args[0].Text()
	return strings.Contains(t, "http://") || strings.Contains(t, "https://") || strings.Contains(t, "ftp://")
}

func httpClientMeta() sinkMeta {
	return sinkMeta{
		category:    sinkHTTPClient,
		categoryStr: "http_client",
		cwe:         "CWE-918",
		owasp:       "A03:2021-Injection",
		titleNoun:   "HTTP client (SSRF)",
		fixHint:     "Validate the URL/host: parse with parse_url(), reject private/loopback IPs (CIDRs 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, ::1/128, fc00::/7), and apply a scheme allowlist (https only). Consider an explicit hostname allowlist for federated peers.",
	}
}

func fileReadMeta() sinkMeta {
	return sinkMeta{
		category:    sinkFileRead,
		categoryStr: "file_read",
		cwe:         "CWE-22",
		owasp:       "A01:2021-Broken Access Control",
		titleNoun:   "filesystem read (path traversal / LFI)",
		fixHint:     "Canonicalize the path with realpath() and verify it is contained within an expected base directory; basename() the param if only a filename is expected. Never pass an unvalidated user-controlled path to include / require.",
	}
}

func fileWriteMeta() sinkMeta {
	return sinkMeta{
		category:    sinkFileWrite,
		categoryStr: "file_write",
		cwe:         "CWE-22",
		owasp:       "A01:2021-Broken Access Control",
		titleNoun:   "filesystem write",
		fixHint:     "Confirm the target path is inside an allowed directory after realpath() canonicalization; reject absolute paths and \"..\" segments. Use basename() if only a filename is expected.",
	}
}

func processExecMeta() sinkMeta {
	return sinkMeta{
		category:    sinkProcessExec,
		categoryStr: "process_exec",
		cwe:         "CWE-78",
		owasp:       "A03:2021-Injection",
		titleNoun:   "process execution (RCE)",
		fixHint:     "Avoid shell pipelines with user input entirely; if you must, escape with escapeshellarg() for each individual argument and never use escapeshellcmd() on the whole command line. Prefer pcntl_exec() with an argv array.",
	}
}
