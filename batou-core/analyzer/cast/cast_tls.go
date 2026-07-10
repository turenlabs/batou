package cast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// OpenSSL always-accept verify-callback detection (CWE-295).
//
// Shape detected (BATOU-CAST-009):
//
//	int my_cb(int preverify_ok, X509_STORE_CTX *ctx) {
//	    return 1;          // unconditionally accept every certificate
//	}
//	...
//	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, my_cb);
//
// Wiring a verify callback that always returns 1 silently re-enables the
// "accept anything" behaviour that SSL_VERIFY_PEER was supposed to enforce —
// the cert chain result (preverify_ok) is discarded.
//
// Precision: the finding fires ONLY when BOTH conditions hold:
//  1. the callback identifier is the 3rd argument of an
//     SSL_CTX_set_verify / SSL_set_verify call, AND
//  2. that callback's definition has a single trivial `return 1;` body
//     (a `return <constant 1>`) and contains no conditional / loop / other
//     call that could inspect the certificate.
//
// A real callback that examines the chain (any `if`, loop, or function call in
// its body) is left untouched. Implemented independently from the CWE-295
// definition and the OpenSSL public API docs.
// ---------------------------------------------------------------------------

// checkTLSVerifyCallbacks runs the two-pass always-accept callback analysis and
// appends any findings. Called once per file from walk().
func (c *cChecker) checkTLSVerifyCallbacks() {
	root := c.tree.Root()
	if root == nil {
		return
	}

	// Pass 1: collect callback identifier names wired into SSL(_CTX)_set_verify
	// as the 3rd argument (index 2).
	registered := map[string]bool{}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() != "call_expression" {
			return true
		}
		name := cCallName(n)
		if name != "SSL_CTX_set_verify" && name != "SSL_set_verify" {
			return true
		}
		args := findChild(n, "argument_list")
		if args == nil {
			return true
		}
		named := args.NamedChildren()
		if len(named) < 3 {
			return true
		}
		// 3rd arg must be a bare identifier (the callback function name).
		if cb := identName(named[2]); cb != "" {
			registered[cb] = true
		}
		return true
	})
	if len(registered) == 0 {
		return
	}

	// Pass 2: find each registered callback's definition and check whether its
	// body is the trivial always-accept stub.
	root.Walk(func(n *ast.Node) bool {
		if n.Type() != "function_definition" {
			return true
		}
		fnName := functionDefName(n)
		if fnName == "" || !registered[fnName] {
			return true
		}
		body := n.ChildByFieldName("body")
		if body == nil {
			return true
		}
		if !bodyIsAlwaysAccept(body) {
			return true
		}
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-CAST-009",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "TLS verify callback always accepts (OpenSSL '" + fnName + "' returns 1 unconditionally)",
			Description: "The certificate-verification callback '" + fnName + "' is wired into SSL_CTX_set_verify/SSL_set_verify but its body unconditionally returns 1, accepting every certificate regardless of the chain-validation result (preverify_ok). This disables peer verification and allows man-in-the-middle attacks.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Return preverify_ok (or perform real checks and return 0 on failure). A verify callback must propagate the validation result, not hardcode acceptance.",
			CWEID:         "CWE-295",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      c.language,
			Confidence:    "high",
			Tags:          []string{"tls", "cert-validation", "openssl", "ast"},
		})
		return false
	})
}

// functionDefName extracts the function name from a function_definition node,
// unwrapping pointer declarators (e.g. `int *f(...)`).
func functionDefName(fnDef *ast.Node) string {
	decl := fnDef.ChildByFieldName("declarator")
	for decl != nil && decl.Type() == "pointer_declarator" {
		decl = decl.ChildByFieldName("declarator")
	}
	if decl == nil || decl.Type() != "function_declarator" {
		return ""
	}
	return declaratorIdentifier(decl.ChildByFieldName("declarator"))
}

// bodyIsAlwaysAccept reports whether a compound_statement body is the trivial
// always-accept stub: it contains at least one `return 1;` and NO control flow
// (if/for/while/switch), NO nested calls, and every return it does contain
// returns the literal 1. Any cert-inspecting logic (a conditional or a call)
// disqualifies it, so real callbacks never match.
func bodyIsAlwaysAccept(body *ast.Node) bool {
	sawReturn1 := false
	disqualified := false

	body.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "if_statement", "for_statement", "while_statement",
			"do_statement", "switch_statement", "conditional_expression",
			"call_expression":
			// Any branching or call could inspect the certificate — not a stub.
			disqualified = true
			return false
		case "return_statement":
			if returnsLiteralOne(n) {
				sawReturn1 = true
			} else {
				// `return preverify_ok;` or `return 0;` etc. — not always-accept.
				disqualified = true
			}
			return false
		}
		return true
	})

	return sawReturn1 && !disqualified
}

// returnsLiteralOne reports whether a return_statement returns the integer
// literal 1 (the OpenSSL "accept" value). Handles `return 1;` and `return (1);`.
func returnsLiteralOne(ret *ast.Node) bool {
	for _, ch := range ret.NamedChildren() {
		v := unwrapParens(ch)
		if v == nil {
			continue
		}
		if v.Type() == "number_literal" && v.Text() == "1" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// TLS certificate-verification DISABLED via explicit flag (CWE-295).
//
// Two independent, framework-anchored shapes are detected here, each keyed on a
// UNIQUE library symbol so there is no bare-name collision with application
// code:
//
//   BATOU-CAST-011  libcurl: curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0)
//                   or CURLOPT_SSL_VERIFYHOST with 0/false. Disabling either
//                   leaves the client open to a man-in-the-middle.
//
//   BATOU-CAST-012  GnuTLS: gnutls_certificate_set_verify_flags(creds,
//                   GNUTLS_VERIFY_DISABLE_*) — the DISABLE_CA_SIGN /
//                   DISABLE_TIME_CHECKS / DISABLE_CRL_CHECKS family TURNS OFF a
//                   validation step. (The GNUTLS_VERIFY_ALLOW_* legacy-cert
//                   compatibility members are NOT matched: real CA-bundle setup
//                   code such as curl's gtls.c uses ALLOW_X509_V1_CA_CRT
//                   deliberately, so matching ALLOW_* would false-positive on
//                   it. Only an explicit DISABLE of a check is unambiguous.)
//
// NOTE on the OpenSSL SSL_VERIFY_NONE shape: it was evaluated and deliberately
// NOT shipped here. TLS-stack wrappers legitimately set SSL_VERIFY_NONE and then
// verify the chain manually post-handshake (curl's openssl.c) or select the mode
// per a client-auth configuration option (redis's tls.c, where the adjacent case
// uses SSL_VERIFY_PEER). A single-file AST check cannot tell that compensated use
// apart from a blanket disable, so flagging it produces false positives on
// exactly the well-engineered code we scan. CAST-009 already covers the precise,
// FP-free sibling shape: a verify CALLBACK that unconditionally returns 1.
//
// Each rule below fires only on the literal "off"/DISABLE value, so a
// runtime-computed verify mode (CURLOPT_SSL_VERIFYPEER, want_verify) is left
// alone. Implemented independently from the libcurl / GnuTLS public API docs and
// the CWE-295 definition.
// ---------------------------------------------------------------------------

// checkTLSVerifyDisabled walks every call_expression once and dispatches to the
// two flag-based verify-disable shapes. Called once per file from walk().
func (c *cChecker) checkTLSVerifyDisabled(n *ast.Node) {
	switch cCallName(n) {
	case "curl_easy_setopt":
		c.checkCurlVerifyDisabled(n)
	case "gnutls_certificate_set_verify_flags":
		c.checkGnuTLSVerifyDisabled(n)
	}
}

// argText returns the trimmed source text of the i-th named argument of a
// call_expression, or "" if absent. Parentheses are unwrapped so `(0)` reads as
// `0`.
func callArgText(n *ast.Node, i int) string {
	args := findChild(n, "argument_list")
	if args == nil {
		return ""
	}
	named := args.NamedChildren()
	if i < 0 || i >= len(named) {
		return ""
	}
	return unwrapParens(named[i]).Text()
}

// checkCurlVerifyDisabled flags curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER,
// 0) and CURLOPT_SSL_VERIFYHOST set to 0/false (option in arg 1, value in arg 2).
func (c *cChecker) checkCurlVerifyDisabled(n *ast.Node) {
	opt := callArgText(n, 1)
	if opt != "CURLOPT_SSL_VERIFYPEER" && opt != "CURLOPT_SSL_VERIFYHOST" {
		return
	}
	val := callArgText(n, 2)
	// Only the literal "off" values disable verification. A variable
	// (CURLOPT_SSL_VERIFYPEER, want_verify) is left to runtime and not flagged.
	if val != "0" && val != "0L" && val != "false" && val != "FALSE" {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-011",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "libcurl TLS verification disabled (" + opt + " = " + val + ")",
		Description: "curl_easy_setopt sets " + opt + " to " + val + ", disabling " +
			"certificate-chain (CURLOPT_SSL_VERIFYPEER) or hostname (CURLOPT_SSL_VERIFYHOST) validation. " +
			"The client will then trust any certificate, allowing a man-in-the-middle to impersonate the " +
			"server (CWE-295).",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Leave CURLOPT_SSL_VERIFYPEER at 1 and CURLOPT_SSL_VERIFYHOST at 2 (the secure defaults). Pin or supply a CA bundle (CURLOPT_CAINFO/CURLOPT_CAPATH) instead of disabling verification.",
		CWEID:         "CWE-295",
		OWASPCategory: "A07:2021-Identification and Authentication Failures",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"tls", "cert-validation", "libcurl", "ast"},
	})
}

// checkGnuTLSVerifyDisabled flags gnutls_certificate_set_verify_flags whose flag
// argument (index 1) contains a GNUTLS_VERIFY_DISABLE_* / ALLOW_* token that
// relaxes chain validation.
func (c *cChecker) checkGnuTLSVerifyDisabled(n *ast.Node) {
	flags := callArgText(n, 1)
	if flags == "" {
		return
	}
	if !gnutlsFlagsDisableVerify(flags) {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-012",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "GnuTLS certificate verification weakened (gnutls_certificate_set_verify_flags)",
		Description: "gnutls_certificate_set_verify_flags is configured with a GNUTLS_VERIFY_DISABLE_* / " +
			"GNUTLS_VERIFY_ALLOW_* flag that relaxes X.509 chain validation (e.g. disabling CA-signature, " +
			"time, or any-X509-V1-CA checks). This weakens or removes certificate validation and exposes the " +
			"connection to man-in-the-middle attacks (CWE-295).",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Do not set GNUTLS_VERIFY_DISABLE_*/ALLOW_* flags in production. Keep the default strict verification and let gnutls_certificate_verify_peers* enforce the full chain.",
		CWEID:         "CWE-295",
		OWASPCategory: "A07:2021-Identification and Authentication Failures",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"tls", "cert-validation", "gnutls", "ast"},
	})
}

// gnutlsFlagsDisableVerify reports whether a GnuTLS verify-flags expression
// contains a token that explicitly DISABLES a validation step. Only the
// GNUTLS_VERIFY_DISABLE_* members are matched — each one turns a check off,
// which is unambiguous. The GNUTLS_VERIFY_ALLOW_* members (legacy-cert/
// broken-signature compatibility allowances) are intentionally NOT matched:
// real CA-trust setup code (e.g. curl's gtls.c uses ALLOW_X509_V1_CA_CRT)
// legitimately sets them, so matching ALLOW_* would false-positive on it.
// GNUTLS_VERIFY_DO_NOT_ALLOW_* members strengthen checks and are likewise
// excluded by requiring the "DISABLE_" infix.
func gnutlsFlagsDisableVerify(flags string) bool {
	disabling := []string{
		"GNUTLS_VERIFY_DISABLE_CA_SIGN",
		"GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS",
		"GNUTLS_VERIFY_DISABLE_TIME_CHECKS",
		"GNUTLS_VERIFY_DISABLE_CRL_CHECKS",
	}
	for _, w := range disabling {
		if strings.Contains(flags, w) {
			return true
		}
	}
	return false
}
