package goast

// Coverage-expansion AST detectors (BATOU-AST-012 .. BATOU-AST-018).
//
// Every detector here is a CONSTANT-MISCONFIGURATION resolved against the
// static type or import path of a real stdlib / well-known framework symbol.
// None match on a bare name: each is anchored on a package-qualified type
// (net/http.Cookie, crypto/rsa.GenerateKey, net/http/httputil.ReverseProxy,
// ...) so they cannot collide with same-named fields/methods on unrelated
// types. They block (high confidence) because there is no source/sink
// ambiguity — the insecure value is a literal in the program text.

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// --------------------------------------------------------------------
// BATOU-AST-012: Insecure cookie / session flags
//   CWE-1004 (HttpOnly omitted/false) · CWE-614 (Secure omitted/false)
//   CWE-1275 (SameSite=None without Secure)
// --------------------------------------------------------------------

// checkInsecureCookie flags a net/http.Cookie struct literal (or a
// gorilla/sessions.Options struct literal) that:
//   - omits or sets HttpOnly:false on an otherwise-populated session cookie,
//   - omits or sets Secure:false, or
//   - sets SameSite: http.SameSiteNoneMode without Secure:true.
//
// Anchored on the exact type net/http.Cookie / gorilla/sessions.Options, so
// it never matches a HttpOnly/Secure field on an unrelated config struct.
//
// FP guards (deliberately conservative — a HELD FP beats a noisy one):
//   - Only fires on a literal that already sets a value-bearing cookie
//     (Name + Value, or a sessions.Options that sets MaxAge/Path). A bare
//     placeholder literal is skipped.
//   - Cookie-deletion literals (MaxAge < 0) are skipped — clearing a cookie
//     does not need Secure/HttpOnly.
func (c *astChecker) checkInsecureCookie(lit *ast.CompositeLit) {
	isHTTPCookie := c.litTypeIs(lit, "net/http", "Cookie")
	isSessionOpts := c.litTypeIs(lit, "github.com/gorilla/sessions", "Options")
	if !isHTTPCookie && !isSessionOpts {
		return
	}

	var (
		hasName, hasValue          bool
		hasMaxAgeNeg               bool
		hasPathOrMaxAge            bool
		httpOnlyField, secureField ast.Expr
		sawHTTPOnly, sawSecure     bool
		sameSiteVal                ast.Expr
	)

	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Name":
			hasName = true
		case "Value":
			hasValue = true
		case "Path":
			hasPathOrMaxAge = true
		case "MaxAge":
			hasPathOrMaxAge = true
			if isNegativeIntLit(kv.Value) {
				hasMaxAgeNeg = true
			}
		case "HttpOnly", "HTTPOnly":
			sawHTTPOnly = true
			httpOnlyField = kv.Value
		case "Secure":
			sawSecure = true
			secureField = kv.Value
		case "SameSite":
			sameSiteVal = kv.Value
		}
	}

	// Cookie-deletion literal — clearing a cookie does not require flags.
	if hasMaxAgeNeg {
		return
	}

	// Only flag a literal that is actually establishing a cookie/session.
	// http.Cookie needs Name+Value; sessions.Options needs Path/MaxAge.
	populated := (isHTTPCookie && hasName && hasValue) || (isSessionOpts && hasPathOrMaxAge)
	if !populated {
		return
	}

	secureTrue := sawSecure && isTrueIdent(secureField)

	// CWE-1275: SameSite=None requires Secure. Highest-signal — report first.
	if c.isSameSiteNone(sameSiteVal) && !secureTrue {
		c.addCookieFinding(lit, "CWE-1275",
			"Cookie sets SameSite=None without Secure. Browsers reject SameSite=None cookies that are not Secure, and a None cookie sent over plaintext is exposed to network attackers and cross-site requests.",
			"Set Secure: true whenever SameSite is http.SameSiteNoneMode, or use http.SameSiteLaxMode / http.SameSiteStrictMode.")
		return
	}

	// CWE-614: Secure omitted or explicitly false.
	if !sawSecure || isFalseIdent(secureField) {
		c.addCookieFinding(lit, "CWE-614",
			"Cookie is missing the Secure flag, so it is transmitted over plaintext HTTP and can be intercepted by a network attacker.",
			"Set Secure: true so the cookie is only sent over HTTPS.")
		return
	}

	// CWE-1004: HttpOnly omitted or explicitly false (session-bearing cookie).
	if !sawHTTPOnly || isFalseIdent(httpOnlyField) {
		c.addCookieFinding(lit, "CWE-1004",
			"Cookie is missing the HttpOnly flag, so client-side JavaScript can read it. A session or auth cookie without HttpOnly is exposed to XSS-based theft.",
			"Set HttpOnly: true so the cookie is inaccessible to JavaScript.")
		return
	}
}

// isSameSiteNone reports whether expr is http.SameSiteNoneMode (the only
// SameSite mode that weakens cross-site protection).
func (c *astChecker) isSameSiteNone(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	httpName := c.localNameFor("net/http")
	return httpName != "" && ident.Name == httpName && sel.Sel.Name == "SameSiteNoneMode"
}

func (c *astChecker) addCookieFinding(node ast.Node, cwe, desc, suggestion string) {
	pos := c.fset.Position(node.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-012",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Insecure cookie configuration",
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(node),
		Suggestion:    suggestion,
		CWEID:         cwe,
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"http", "cookie", "session", "misconfig"},
	})
}

// --------------------------------------------------------------------
// BATOU-AST-013: net/http/pprof exposed on the default mux (CWE-489)
// BATOU-AST-014: net/http/cgi imported — httpoxy (CWE-665)
// --------------------------------------------------------------------

// checkDebugAndCGIImports flags two import-level misconfigurations:
//   - net/http/pprof (blank or named import): registers /debug/pprof/* on
//     http.DefaultServeMux at import time. If that mux is ever served, the
//     heap/goroutine/profile endpoints leak internals and enable DoS.
//   - net/http/cgi: vulnerable to httpoxy (CVE-2016-5386) — a request's
//     Proxy header maps to the HTTP_PROXY env var inside the CGI process.
func (c *astChecker) checkDebugAndCGIImports() {
	for _, imp := range c.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		pos := c.fset.Position(imp.Pos())
		switch path {
		case "net/http/pprof":
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-AST-013",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Debug pprof endpoints exposed",
				Description:   "Importing net/http/pprof registers /debug/pprof/* handlers on http.DefaultServeMux. If the default mux is served, anyone can pull heap/goroutine/CPU profiles (information disclosure) and trigger expensive profiling (DoS).",
				FilePath:      c.filePath,
				LineNumber:    pos.Line,
				Column:        pos.Column,
				MatchedText:   `import _ "net/http/pprof"`,
				Suggestion:    "Do not import net/http/pprof in production binaries. If you need profiling, register the pprof handlers on a separate, access-controlled mux bound to localhost.",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      rules.LangGo,
				Confidence:    "high",
				Tags:          []string{"http", "pprof", "debug", "info-disclosure"},
			})
		case "net/http/cgi":
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-AST-014",
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "net/http/cgi vulnerable to httpoxy",
				Description:   "net/http/cgi copies request headers into the CGI environment, so an attacker-supplied Proxy request header becomes the HTTP_PROXY environment variable inside the process (httpoxy, CVE-2016-5386). Outbound requests can then be redirected through an attacker-controlled proxy.",
				FilePath:      c.filePath,
				LineNumber:    pos.Line,
				Column:        pos.Column,
				MatchedText:   `import "net/http/cgi"`,
				Suggestion:    "Avoid net/http/cgi for new code. If it must be used, strip the Proxy header before invoking the CGI handler and pin HTTP_PROXY explicitly.",
				CWEID:         "CWE-665",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      rules.LangGo,
				Confidence:    "medium",
				Tags:          []string{"http", "cgi", "httpoxy"},
			})
		}
	}
}

// --------------------------------------------------------------------
// BATOU-AST-015: rsa.GenerateKey with bits < 2048 (CWE-326)
// BATOU-AST-016: http.FileServer(http.Dir(...)) directory listing (CWE-548)
// BATOU-AST-017: SHA-224 used as a digest (CWE-328)
// --------------------------------------------------------------------

// checkWeakCryptoAndFileServer dispatches the CallExpr-level coverage checks.
func (c *astChecker) checkWeakCryptoAndFileServer(call *ast.CallExpr) {
	c.checkWeakRSAKeySize(call)
	c.checkFileServerListing(call)
	c.checkSHA224Digest(call)
	c.checkListenAllInterfaces(call)
}

// --------------------------------------------------------------------
// BATOU-AST-019: net.Listen bound to 0.0.0.0 / all interfaces (CWE-200)
// --------------------------------------------------------------------

// checkListenAllInterfaces flags net.Listen("tcp", "0.0.0.0:...") where the
// address is an EXPLICIT 0.0.0.0 literal. Binding a listener to all interfaces
// can expose a service intended for localhost to the whole network.
//
// Deliberately narrow to avoid FPs: only the explicit "0.0.0.0:" literal is
// flagged. The idiomatic ":port" form (host omitted) is the common, often
// intentional default and is NOT flagged. A variable/config-supplied address
// is out of scope. Anchored on the net package alias.
func (c *astChecker) checkListenAllInterfaces(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Listen" {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	netName := c.localNameFor("net")
	if netName == "" || ident.Name != netName {
		return
	}
	// net.Listen(network, address) — address is arg 1.
	if len(call.Args) < 2 {
		return
	}
	addr := c.stringLitValue(call.Args[1])
	if !strings.HasPrefix(addr, "0.0.0.0:") {
		return
	}
	c.addAllInterfacesFinding(call, "net.Listen binds to 0.0.0.0 (all network interfaces), exposing the listener beyond localhost.")
}

// checkServerAddrAllInterfaces flags an http.Server struct literal whose Addr
// field is an explicit "0.0.0.0:..." literal. Same FP posture as the
// net.Listen check — only the literal 0.0.0.0 host is flagged.
func (c *astChecker) checkServerAddrAllInterfaces(lit *ast.CompositeLit) {
	if !c.litTypeIs(lit, "net/http", "Server") {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Addr" {
			continue
		}
		if strings.HasPrefix(c.stringLitValue(kv.Value), "0.0.0.0:") {
			c.addAllInterfacesFinding(kv, "http.Server.Addr binds to 0.0.0.0 (all network interfaces), exposing the server beyond localhost.")
		}
		return
	}
}

func (c *astChecker) addAllInterfacesFinding(node ast.Node, desc string) {
	pos := c.fset.Position(node.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-019",
		Severity:      rules.Low,
		SeverityLabel: rules.Low.String(),
		Title:         "Service bound to all network interfaces",
		Description:   desc + " If the service is meant for local or internal use only, it is reachable by any host that can route to the machine.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(node),
		Suggestion:    "Bind to a specific interface (e.g. 127.0.0.1:PORT for local-only) unless the service genuinely must be reachable from any interface.",
		CWEID:         "CWE-200",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangGo,
		Confidence:    "medium",
		Tags:          []string{"net", "bind", "all-interfaces", "exposure"},
	})
}

// checkWeakRSAKeySize flags crypto/rsa.GenerateKey(rand, bits) where bits is a
// constant < 2048. Anchored on the rsa package alias + method name, with the
// second argument resolved to an integer literal — a variable bit count is
// out of scope for a constant rule.
func (c *astChecker) checkWeakRSAKeySize(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "GenerateKey" {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	rsaName := c.localNameFor("crypto/rsa")
	if rsaName == "" || ident.Name != rsaName {
		return
	}
	if len(call.Args) < 2 {
		return
	}
	bits, ok := intLitValue(call.Args[1])
	if !ok || bits >= 2048 {
		return
	}
	pos := c.fset.Position(call.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-015",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Weak RSA key size",
		Description:   "rsa.GenerateKey is called with " + strconv.Itoa(bits) + " bits. RSA keys shorter than 2048 bits are factorable with modern resources and are rejected by current standards (NIST SP 800-57).",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(call),
		Suggestion:    "Generate at least 2048-bit RSA keys (rsa.GenerateKey(rand.Reader, 2048)); prefer 3072+ or switch to an EdDSA/ECDSA key.",
		CWEID:         "CWE-326",
		OWASPCategory: "A02:2021-Cryptographic Failures",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"crypto", "rsa", "weak-key"},
	})
}

// checkFileServerListing flags http.FileServer(http.Dir(...)). The default
// http.FileServer handler renders an autoindex (directory listing) for any
// directory lacking an index.html, disclosing the full file tree. Anchored on
// the net/http package alias for both FileServer and the inner Dir conversion.
func (c *astChecker) checkFileServerListing(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "FileServer" {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	httpName := c.localNameFor("net/http")
	if httpName == "" || ident.Name != httpName {
		return
	}
	if len(call.Args) != 1 {
		return
	}
	// Inner arg must be http.Dir(...) — http.FS(embed) and custom FileSystems
	// that disable listing are out of scope.
	inner, ok := call.Args[0].(*ast.CallExpr)
	if !ok {
		return
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || innerSel.Sel.Name != "Dir" {
		return
	}
	innerIdent, ok := innerSel.X.(*ast.Ident)
	if !ok || innerIdent.Name != httpName {
		return
	}
	pos := c.fset.Position(call.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-016",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Directory listing via http.FileServer",
		Description:   "http.FileServer(http.Dir(...)) serves a directory and renders an automatic directory listing for any path without an index.html, disclosing the entire file tree to clients.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(call),
		Suggestion:    "Wrap the FileSystem to suppress listings (return os.ErrNotExist for directories), serve a specific file with http.ServeFile, or embed assets with http.FS so no directory index is produced.",
		CWEID:         "CWE-548",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangGo,
		Confidence:    "medium",
		Tags:          []string{"http", "fileserver", "directory-listing", "info-disclosure"},
	})
}

// checkSHA224Digest flags crypto/sha256.Sum224 and crypto/sha256.New224.
// SHA-224 is a truncated SHA-256 with a 224-bit output; gosec (G407-class)
// and NIST guidance flag its use for new signatures/digests. Anchored on the
// sha256 package alias.
func (c *astChecker) checkSHA224Digest(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if sel.Sel.Name != "Sum224" && sel.Sel.Name != "New224" {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	sha256Name := c.localNameFor("crypto/sha256")
	if sha256Name == "" || ident.Name != sha256Name {
		return
	}
	pos := c.fset.Position(call.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-017",
		Severity:      rules.Low,
		SeverityLabel: rules.Low.String(),
		Title:         "Weak SHA-224 digest",
		Description:   "sha256." + sel.Sel.Name + " produces a 224-bit truncated SHA-256 digest. SHA-224 offers reduced collision resistance and is flagged for cryptographic digests/signatures.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(call),
		Suggestion:    "Use sha256.Sum256 / sha256.New (or SHA-384/512) for cryptographic digests.",
		CWEID:         "CWE-328",
		OWASPCategory: "A02:2021-Cryptographic Failures",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"crypto", "hash", "sha224", "weak-hash"},
	})
}

// --------------------------------------------------------------------
// BATOU-AST-018: ReverseProxy Director copies inbound host/URL (CWE-918)
// --------------------------------------------------------------------

// checkReverseProxyDirector flags a httputil.ReverseProxy struct literal whose
// Director function copies the inbound request's Host or URL.Host into the
// outbound target. A Director that does `req.URL.Host = req.Host` (or copies
// the client-supplied Host) lets a client steer the proxy to an arbitrary
// upstream — proxy SSRF / host smuggling.
//
// Anchored on net/http/httputil.ReverseProxy + the Director field; the body
// scan requires BOTH an assignment INTO req.URL.Host/req.URL.Scheme AND a
// read of the inbound req.Host on the RHS, so a normal fixed-upstream Director
// (`req.URL.Host = "backend:8080"`) does not match.
func (c *astChecker) checkReverseProxyDirector(lit *ast.CompositeLit) {
	if !c.litTypeIs(lit, "net/http/httputil", "ReverseProxy") {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Director" {
			continue
		}
		fn, ok := kv.Value.(*ast.FuncLit)
		if !ok || fn.Body == nil {
			continue
		}
		if reqParam := firstRequestParamName(fn); reqParam != "" {
			if directorCopiesInboundHost(fn.Body, reqParam) {
				pos := c.fset.Position(lit.Pos())
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "BATOU-AST-018",
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "Reverse proxy forwards client-controlled host",
					Description:   "The ReverseProxy Director copies the inbound request's Host into the outbound URL, so a client can set the upstream the proxy connects to (Host header / URL smuggling). This is server-side request forgery against internal services.",
					FilePath:      c.filePath,
					LineNumber:    pos.Line,
					Column:        pos.Column,
					MatchedText:   c.nodeSource(lit),
					Suggestion:    "Set req.URL.Host/Scheme to a fixed, validated upstream (or an allowlist lookup) inside the Director — never to the inbound req.Host.",
					CWEID:         "CWE-918",
					OWASPCategory: "A10:2021-Server-Side Request Forgery",
					Language:      rules.LangGo,
					Confidence:    "high",
					Tags:          []string{"http", "reverse-proxy", "ssrf", "host-smuggling"},
				})
			}
		}
		return
	}
}

// firstRequestParamName returns the name of the *http.Request parameter of a
// Director func literal (Director is func(*http.Request)), or "".
func firstRequestParamName(fn *ast.FuncLit) string {
	if fn.Type == nil || fn.Type.Params == nil {
		return ""
	}
	for _, field := range fn.Type.Params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Request" {
			continue
		}
		if len(field.Names) > 0 {
			return field.Names[0].Name
		}
	}
	return ""
}

// directorCopiesInboundHost reports whether the Director body BOTH assigns
// into req.URL.Host/Scheme AND reads the inbound req.Host on the RHS of an
// assignment to the URL. This two-sided requirement keeps fixed-upstream
// Directors clean.
func directorCopiesInboundHost(body *ast.BlockStmt, reqName string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// LHS must target req.URL.Host / req.URL.Scheme.
		lhsIsURLHost := false
		for _, lhs := range assign.Lhs {
			if isReqURLHostSelector(lhs, reqName) {
				lhsIsURLHost = true
			}
		}
		if !lhsIsURLHost {
			return true
		}
		// RHS must read the inbound req.Host (the client-controlled value).
		for _, rhs := range assign.Rhs {
			if exprReadsReqHost(rhs, reqName) {
				found = true
			}
		}
		return true
	})
	return found
}

// isReqURLHostSelector matches req.URL.Host or req.URL.Scheme (req == reqName).
func isReqURLHostSelector(expr ast.Expr, reqName string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name != "Host" && sel.Sel.Name != "Scheme" {
		return false
	}
	// sel.X must be req.URL
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok || inner.Sel.Name != "URL" {
		return false
	}
	base, ok := inner.X.(*ast.Ident)
	return ok && base.Name == reqName
}

// exprReadsReqHost reports whether expr reads req.Host (the inbound Host) for
// req == reqName, anywhere in the subtree. req.URL.Host (the assignment target)
// is excluded because its receiver is req.URL, not req.
func exprReadsReqHost(expr ast.Expr, reqName string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Host" {
			return true
		}
		if base, ok := sel.X.(*ast.Ident); ok && base.Name == reqName {
			found = true
		}
		return true
	})
	return found
}

// --------------------------------------------------------------------
// shared literal helpers
// --------------------------------------------------------------------

func isTrueIdent(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "true"
}

func isFalseIdent(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "false"
}

// intLitValue resolves an integer literal (incl. a leading unary minus) to its
// int value. Returns (0,false) for non-literal expressions.
func intLitValue(expr ast.Expr) (int, bool) {
	switch v := expr.(type) {
	case *ast.BasicLit:
		if v.Kind != token.INT {
			return 0, false
		}
		n, err := strconv.ParseInt(v.Value, 0, 64)
		if err != nil {
			return 0, false
		}
		return int(n), true
	case *ast.UnaryExpr:
		if v.Op == token.SUB {
			if n, ok := intLitValue(v.X); ok {
				return -n, true
			}
		}
	}
	return 0, false
}

func isNegativeIntLit(expr ast.Expr) bool {
	n, ok := intLitValue(expr)
	return ok && n < 0
}
