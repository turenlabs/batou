package java

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Coverage expansion: framework-anchored Java config / crypto / transport
// anti-patterns closing breadth gaps vs mainstream SAST rulesets. Every rule here is keyed on
// a concrete framework type / FQN-anchored API so it cannot collide with
// bare-name code. Each pairs a vulnerable pattern with the safe alternative in
// its Suggestion. Tightly gated to keep the false-positive rate flat.
// ---------------------------------------------------------------------------

// ===========================================================================
// JAVA-032: AccessController.doPrivileged wrapping a tainted-path/command op
// (privilege-escalation audit, CWE-250)
// ===========================================================================

var (
	reDoPrivileged = regexp.MustCompile(`AccessController\.doPrivileged\s*\(`)
	// Sensitive operations that, when wrapped in a privileged block, escalate
	// privilege if their argument is attacker-influenced.
	reDoPrivSensitive = regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(|new\s+ProcessBuilder\b|new\s+File(?:Reader|Writer|InputStream|OutputStream)?\s*\(|System\.load(?:Library)?\s*\(|System\.setProperty\s*\(|\.setAccessible\s*\(\s*true|System\.setSecurityManager\s*\(`)
	// A dynamic value (variable / concatenation) rather than a string literal
	// argument indicates the privileged op consumes non-constant data.
	reDoPrivDynamic = regexp.MustCompile(`\bexec\s*\(\s*[a-zA-Z_]\w*|\bcommand\s*\(\s*[a-zA-Z_]\w*|new\s+File[A-Za-z]*\s*\(\s*[a-zA-Z_]\w*|"\s*\+|\+\s*[a-zA-Z_]\w*\s*\)`)
)

type JavaDoPrivileged struct{}

func (r *JavaDoPrivileged) ID() string                      { return "BATOU-JAVA-032" }
func (r *JavaDoPrivileged) Name() string                    { return "JavaDoPrivileged" }
func (r *JavaDoPrivileged) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaDoPrivileged) Description() string {
	return "Detects AccessController.doPrivileged blocks that wrap a file/command/native-load operation on a dynamic argument (privilege-escalation surface)."
}
func (r *JavaDoPrivileged) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaDoPrivileged) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "doPrivileged") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reDoPrivileged, line, lowered[i]) {
			continue
		}
		// Examine the privileged block body (this line plus a small window).
		body := surroundingContext(lines, i, 8)
		if !reDoPrivSensitive.MatchString(body) {
			continue
		}
		if !reDoPrivDynamic.MatchString(body) {
			continue // wraps a constant op — not a privilege-escalation surface
		}
		findings = append(findings, rules.Finding{
			RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Privileged block wraps a dynamic file/command/native operation",
			Description:   "An AccessController.doPrivileged block executes a file, OS-command, or native-library operation on a non-constant argument. Code inside doPrivileged runs with the wrapping class's permissions regardless of the caller's, so any attacker-influenced path/command argument crosses a privilege boundary (CWE-250).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Keep the privileged block as small as possible and never let untrusted data choose the file path, command, or library inside it. Validate/canonicalize the argument BEFORE entering doPrivileged, or move the operation outside the privileged scope so it runs with the caller's reduced permissions.",
			CWEID:         "CWE-250",
			OWASPCategory: "A04:2021-Insecure Design",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"java", "privilege", "doprivileged", "access-controller"},
		})
	}
	return findings
}

// ===========================================================================
// JAVA-033: Custom XSSRequestWrapper regex-blocklist used as the ONLY XSS
// defense (insecure-sanitizer anti-pattern, CWE-79)
// ===========================================================================

var (
	// The class extends HttpServletRequestWrapper and strips "<script>"-style
	// patterns via regex replaceAll — a classic incomplete blocklist that
	// developers then trust as their sanitizer.
	reXSSWrapperClass   = regexp.MustCompile(`class\s+\w*XSS\w*RequestWrapper\b|extends\s+HttpServletRequestWrapper\b`)
	reXSSStripBlocklist = regexp.MustCompile(`\.replaceAll\s*\(\s*"[^"]*(?:<script|javascript:|onload|onerror|<img|<iframe|eval\(|src=|alert)[^"]*"`)
	reXSSStripPattern   = regexp.MustCompile(`Pattern\.compile\s*\(\s*"[^"]*(?:<script|javascript:|onload|onerror|<img|<iframe)[^"]*"`)
)

type JavaXSSStripBlocklist struct{}

func (r *JavaXSSStripBlocklist) ID() string                      { return "BATOU-JAVA-033" }
func (r *JavaXSSStripBlocklist) Name() string                    { return "JavaXSSStripBlocklist" }
func (r *JavaXSSStripBlocklist) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaXSSStripBlocklist) Description() string {
	return "Detects a custom XSSRequestWrapper that strips XSS via a regex blocklist (incomplete, easily bypassed sanitizer anti-pattern)."
}
func (r *JavaXSSStripBlocklist) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaXSSStripBlocklist) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Require the wrapper class context so this only fires on the
	// request-wrapper sanitizer anti-pattern, never on arbitrary replaceAll.
	if !rules.GMatchFile(reXSSWrapperClass, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reXSSStripBlocklist, line, lowered[i]) || rules.GMatchLower(reXSSStripPattern, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XSS defense relies on a regex blocklist in a custom request wrapper",
				Description:   "This HttpServletRequestWrapper attempts to neutralize XSS by stripping a fixed set of patterns (e.g. \"<script>\", \"javascript:\") with regex replaceAll. Blocklist filtering is trivially bypassed (case variation, encoding, broken-up tags, event handlers, SVG/data URIs) and gives a false sense of safety while the output is never context-encoded (CWE-79).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Do not rely on input blocklist stripping. Output-encode every value at the point of use with a context-aware encoder (OWASP Java Encoder: Encode.forHtml / forHtmlAttribute / forJavaScript), or sanitize rich HTML with an allowlist library (OWASP Java HTML Sanitizer). Treat this wrapper as defense-in-depth, not the primary control.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "xss", "blocklist", "request-wrapper", "insecure-sanitizer"},
			})
		}
	}
	return findings
}

// ===========================================================================
// JAVA-034: anonymous LDAP bind — Context.SECURITY_AUTHENTICATION = "none"
// (CWE-287)
// ===========================================================================

var (
	// Both the constant form and the literal string key, set to "none".
	reLdapAuthNone     = regexp.MustCompile(`(?:Context\.SECURITY_AUTHENTICATION|"java\.naming\.security\.authentication")\s*,\s*"none"`)
	reLdapAuthNoneProp = regexp.MustCompile(`\.put\s*\(\s*Context\.SECURITY_AUTHENTICATION\s*,\s*"none"|setProperty\s*\(\s*Context\.SECURITY_AUTHENTICATION\s*,\s*"none"`)
	reLdapContextHint  = regexp.MustCompile(`InitialDirContext|InitialLdapContext|LdapContext|DirContext|ldap://|ldaps://|com\.sun\.jndi\.ldap`)
)

type JavaLdapAnonymousBind struct{}

func (r *JavaLdapAnonymousBind) ID() string                      { return "BATOU-JAVA-034" }
func (r *JavaLdapAnonymousBind) Name() string                    { return "JavaLdapAnonymousBind" }
func (r *JavaLdapAnonymousBind) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaLdapAnonymousBind) Description() string {
	return "Detects a JNDI directory context configured with SECURITY_AUTHENTICATION set to \"none\" (anonymous LDAP bind)."
}
func (r *JavaLdapAnonymousBind) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaLdapAnonymousBind) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "SECURITY_AUTHENTICATION") {
		return nil
	}
	// Require an LDAP/JNDI directory-context context so the "none" value is
	// unambiguously an anonymous bind, not an unrelated auth flag.
	if !rules.GMatchFile(reLdapContextHint, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reLdapAuthNone, line, lowered[i]) || rules.GMatchLower(reLdapAuthNoneProp, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Anonymous LDAP bind (SECURITY_AUTHENTICATION = \"none\")",
				Description:   "The JNDI directory context sets java.naming.security.authentication to \"none\", performing an unauthenticated (anonymous) LDAP bind. Any access decision that trusts the bind result is bypassed, and queries run without credentials (CWE-287).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use \"simple\" (over LDAPS/StartTLS) or a SASL mechanism with a real service principal and credentials. Never treat an anonymous bind as authentication; require SECURITY_PRINCIPAL + SECURITY_CREDENTIALS and validate the bind succeeded with those credentials.",
				CWEID:         "CWE-287",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "ldap", "jndi", "anonymous-bind", "authentication"},
			})
		}
	}
	return findings
}

// ===========================================================================
// JAVA-035: Spring RestTemplate / WebClient request to a hardcoded http://
// (non-TLS) URL (insecure transport, CWE-319)
// ===========================================================================

var (
	// A REST client verb whose first argument is a string literal beginning
	// http:// (not https). The literal form keeps this precise — a variable URL
	// is handled by taint SSRF sinks, not this transport rule.
	reRestHttpClient = regexp.MustCompile(`(?:restTemplate|RestTemplate|webClient|WebClient|this\.restTemplate)\b`)
	reRestHttpVerb   = regexp.MustCompile(`\.(?:getForObject|getForEntity|postForObject|postForEntity|postForLocation|put|delete|exchange|patchForObject|uri)\s*\(\s*"http://`)
	reWebClientBase  = regexp.MustCompile(`\.baseUrl\s*\(\s*"http://`)
)

type JavaRestTemplateCleartext struct{}

func (r *JavaRestTemplateCleartext) ID() string                      { return "BATOU-JAVA-035" }
func (r *JavaRestTemplateCleartext) Name() string                    { return "JavaRestTemplateCleartext" }
func (r *JavaRestTemplateCleartext) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaRestTemplateCleartext) Description() string {
	return "Detects a Spring RestTemplate/WebClient call to a hardcoded http:// (cleartext) URL."
}
func (r *JavaRestTemplateCleartext) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaRestTemplateCleartext) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "http://") {
		return nil
	}
	if !rules.GMatchFile(reRestHttpClient, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// Skip localhost / 127.0.0.1 — local dev endpoints are not a transport risk.
		if strings.Contains(line, "http://localhost") || strings.Contains(line, "http://127.0.0.1") {
			continue
		}
		var m string
		if mm := rules.GFindLower(reRestHttpVerb, line, lowered[i]); mm != "" {
			m = mm
		} else if mm := rules.GFindLower(reWebClientBase, line, lowered[i]); mm != "" && reRestHttpClient.MatchString(surroundingContext(lines, i, 3)) {
			m = mm
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring REST client request over cleartext http://",
				Description:   "A Spring RestTemplate/WebClient call targets a hardcoded http:// URL. Request and response bodies (including credentials, tokens, and PII) travel unencrypted and are exposed to network eavesdropping and tampering (CWE-319).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use an https:// endpoint. If the remote only offers http, terminate TLS at a trusted proxy and connect to it over https; never send authenticated or sensitive requests in cleartext.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "spring", "resttemplate", "cleartext", "transport"},
			})
		}
	}
	return findings
}

// ===========================================================================
// JAVA-036: RESTEasy client built without hostname verification / cert
// validation disabled (insecure RESTEasy client config, CWE-295)
// ===========================================================================

var (
	reResteasyBuilder = regexp.MustCompile(`ResteasyClientBuilder(?:Impl)?\b|ResteasyClientBuilder\.newBuilder|ProxyFactory\.create`)
	reResteasyDisable = regexp.MustCompile(`\.disableTrustManager\s*\(|\.hostnameVerification\s*\(\s*(?:ResteasyClientBuilder\.HostnameVerificationPolicy\.)?ANY\b|\.hostnameVerifier\s*\(\s*\(?\s*\w*\s*,?\s*\w*\s*\)?\s*->\s*true`)
)

type JavaResteasyInsecureClient struct{}

func (r *JavaResteasyInsecureClient) ID() string                      { return "BATOU-JAVA-036" }
func (r *JavaResteasyInsecureClient) Name() string                    { return "JavaResteasyInsecureClient" }
func (r *JavaResteasyInsecureClient) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaResteasyInsecureClient) Description() string {
	return "Detects a RESTEasy client that disables the trust manager or hostname verification (TLS validation bypass)."
}
func (r *JavaResteasyInsecureClient) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaResteasyInsecureClient) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !rules.GMatchFile(reResteasyBuilder, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reResteasyDisable, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "RESTEasy client disables TLS certificate / hostname verification",
				Description:   "This RESTEasy client builder disables the trust manager or sets hostname verification to ANY / always-true. The client then accepts any TLS certificate for any host, defeating server authentication and exposing every request to man-in-the-middle attacks (CWE-295).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove disableTrustManager() and use the default hostname verification (HostnameVerificationPolicy.STRICT or WILDCARD with a proper trust store). For self-signed certs in non-prod, import the cert into a dedicated trust store instead of disabling validation.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "resteasy", "tls", "hostname-verification", "certificate"},
			})
		}
	}
	return findings
}

// ===========================================================================
// JAVA-037: Blowfish (or weak symmetric) key size < 128 bits (CWE-326)
// ===========================================================================

var (
	// KeyGenerator.getInstance("Blowfish") ... kg.init(N) where N < 128, OR a
	// SecretKeySpec for Blowfish built from a short key. We match the explicit
	// .init(<number>) form and check the literal.
	reBlowfishKeygen = regexp.MustCompile(`KeyGenerator\.getInstance\s*\(\s*"Blowfish"`)
	reKeygenInitNum  = regexp.MustCompile(`\.init\s*\(\s*(\d+)\b`)
)

type JavaWeakKeySize struct{}

func (r *JavaWeakKeySize) ID() string                      { return "BATOU-JAVA-037" }
func (r *JavaWeakKeySize) Name() string                    { return "JavaWeakKeySize" }
func (r *JavaWeakKeySize) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaWeakKeySize) Description() string {
	return "Detects a Blowfish KeyGenerator initialized with a key size below 128 bits (insufficient key size)."
}
func (r *JavaWeakKeySize) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaWeakKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "Blowfish") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// The init may be on a separate line from the getInstance — require the
		// Blowfish keygen to be present in a small preceding window.
		if !rules.GMatchLower(reKeygenInitNum, line, lowered[i]) {
			continue
		}
		win := surroundingContext(lines, i, 4)
		if !reBlowfishKeygen.MatchString(win) {
			continue
		}
		m := rules.GFindSubmatchLower(reKeygenInitNum, line, lowered[i])
		if len(m) < 2 {
			continue
		}
		bits := parseIntSafe(m[1])
		if bits == 0 || bits >= 128 {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Blowfish key size below 128 bits",
			Description:   "A Blowfish KeyGenerator is initialized with a key size under 128 bits. Short symmetric keys are brute-forceable; Blowfish itself is also a deprecated 64-bit-block cipher (Sweet32). This is an insufficient-key-size weakness (CWE-326).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use AES with a 128-bit or 256-bit key (KeyGenerator.getInstance(\"AES\"); kg.init(256)). Migrate off Blowfish for any new design.",
			CWEID:         "CWE-326",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"java", "crypto", "blowfish", "key-size"},
		})
	}
	return findings
}

func parseIntSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 1<<20 {
			return 0
		}
	}
	return n
}

// ===========================================================================
// JAVA-038: AES/GCM reusing a fixed GCMParameterSpec/IvParameterSpec nonce
// across encryptions (GCM nonce reuse — key recovery, CWE-323)
// ===========================================================================

var (
	reGCMCipher = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"AES/GCM`)
	// GCMParameterSpec(<tag>, <const>) where <const> is a string literal, a
	// .getBytes() of a literal, an inline byte-array literal, or an ALL-CAPS
	// constant identifier (1+ uppercase, e.g. IV / NONCE / GCM_IV).
	reGCMSpecConst = regexp.MustCompile(`new\s+GCMParameterSpec\s*\(\s*\d+\s*,\s*(?:"[^"]*"|"[^"]*"\.getBytes\s*\(|new\s+byte\s*\[\s*\]\s*\{|[A-Z][A-Z0-9_]*\s*[,)])`)
	// A GCM nonce / IV stored in a static / final field (a constant nonce reused
	// across every cipher.init in the class). Case-insensitive so ALL-CAPS
	// constant names (IV, NONCE) match.
	reGCMStaticSpec = regexp.MustCompile(`(?i)(?:static\s+final|private\s+final|final\s+static)\s+(?:gcmparameterspec|byte\s*\[\s*\])\s+\w*(?:iv|nonce|gcm|spec)\w*`)
)

type JavaGCMNonceReuse struct{}

func (r *JavaGCMNonceReuse) ID() string                      { return "BATOU-JAVA-038" }
func (r *JavaGCMNonceReuse) Name() string                    { return "JavaGCMNonceReuse" }
func (r *JavaGCMNonceReuse) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaGCMNonceReuse) Description() string {
	return "Detects AES/GCM encryption using a hardcoded or static-field GCMParameterSpec nonce (catastrophic nonce reuse)."
}
func (r *JavaGCMNonceReuse) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaGCMNonceReuse) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "GCM") {
		return nil
	}
	// Require AES/GCM cipher usage so we don't flag unrelated GCMParameterSpec
	// references (e.g. test vectors).
	if !rules.GMatchFile(reGCMCipher, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var detail string
		if rules.GMatchLower(reGCMSpecConst, line, lowered[i]) {
			detail = "GCMParameterSpec built from a constant / hardcoded nonce"
		} else if rules.GMatchLower(reGCMStaticSpec, line, lowered[i]) {
			detail = "GCM nonce held in a static/final field (reused across encryptions)"
		}
		if detail == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
			Title:         "AES-GCM nonce reuse: " + detail,
			Description:   "AES-GCM requires a unique nonce per encryption under a given key. Reusing a fixed/static nonce (this GCMParameterSpec is constant or class-level) lets an attacker recover the authentication subkey and forge ciphertexts, and leaks the XOR of plaintexts — a catastrophic failure (CWE-323).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Generate a fresh 12-byte random nonce for every encryption with SecureRandom, prepend it to the ciphertext, and never reuse a (key, nonce) pair. Build the GCMParameterSpec inside the encrypt method from that random nonce, not from a constant or shared field.",
			CWEID:         "CWE-323",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"java", "crypto", "aes-gcm", "nonce-reuse"},
		})
	}
	return findings
}

// ===========================================================================
// JAVA-039: org.apache.http.impl.client.DefaultHttpClient instantiation
// (deprecated; ships insecure SSL defaults, CWE-326)
// ===========================================================================

var reDefaultHttpClient = regexp.MustCompile(`new\s+DefaultHttpClient\s*\(`)

type JavaDefaultHttpClient struct{}

func (r *JavaDefaultHttpClient) ID() string                      { return "BATOU-JAVA-039" }
func (r *JavaDefaultHttpClient) Name() string                    { return "JavaDefaultHttpClient" }
func (r *JavaDefaultHttpClient) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaDefaultHttpClient) Description() string {
	return "Detects instantiation of the deprecated Apache DefaultHttpClient, which uses weak/insecure SSL defaults."
}
func (r *JavaDefaultHttpClient) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaDefaultHttpClient) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "DefaultHttpClient") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := rules.GFindLower(reDefaultHttpClient, line, lowered[i]); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Deprecated Apache DefaultHttpClient (insecure SSL defaults)",
				Description:   "org.apache.http.impl.client.DefaultHttpClient (HttpClient 4.x) is deprecated and negotiates obsolete SSL/TLS protocol versions and cipher suites by default, with no SNI and weak hostname handling. Connections it makes are exposed to downgrade and man-in-the-middle attacks (CWE-326).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use HttpClientBuilder.create().build() (or HttpClients.custom()) on a current HttpClient version, which defaults to modern TLS and strict hostname verification. Configure SSLConnectionSocketFactory with an explicit protocol/cipher allowlist if needed.",
				CWEID:         "CWE-326",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "httpclient", "ssl", "deprecated"},
			})
		}
	}
	return findings
}

// ===========================================================================
// JAVA-040: JavaMail Transport.connect to SMTP without STARTTLS/SSL (CWE-319)
// ===========================================================================

var (
	reMailTransportConnect = regexp.MustCompile(`Transport\.(?:connect|send)\s*\(|transport\.connect\s*\(`)
	reMailStartTLS         = regexp.MustCompile(`mail\.smtp\.starttls\.enable|mail\.smtp\.ssl\.enable|mail\.smtps\.|SMTPSSLTransport|"smtps"`)
	reMailSmtpHint         = regexp.MustCompile(`mail\.smtp\.host|"smtp"|javax\.mail|jakarta\.mail|Session\.getInstance|Session\.getDefaultInstance`)
)

type JavaMailNoTLS struct{}

func (r *JavaMailNoTLS) ID() string                      { return "BATOU-JAVA-040" }
func (r *JavaMailNoTLS) Name() string                    { return "JavaMailNoTLS" }
func (r *JavaMailNoTLS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaMailNoTLS) Description() string {
	return "Detects a JavaMail Transport.connect to SMTP without STARTTLS or SMTPS enabled (cleartext mail submission)."
}
func (r *JavaMailNoTLS) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaMailNoTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "Transport") {
		return nil
	}
	if !rules.GMatchFile(reMailSmtpHint, ctx) {
		return nil
	}
	// If STARTTLS / SSL / SMTPS is configured anywhere in the file, the
	// connection is encrypted — no finding.
	if rules.GMatchFile(reMailStartTLS, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if rules.GMatchLower(reMailTransportConnect, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SMTP mail submission without STARTTLS/SSL",
				Description:   "A JavaMail Transport connects/sends over SMTP with no mail.smtp.starttls.enable, mail.smtp.ssl.enable, or smtps transport configured. Message contents and SMTP-AUTH credentials are transmitted in cleartext and can be intercepted (CWE-319).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set props.put(\"mail.smtp.starttls.enable\", \"true\") (and starttls.required) for submission on port 587, or use the \"smtps\" transport / mail.smtp.ssl.enable on port 465. Verify the server certificate (mail.smtp.ssl.checkserveridentity=true).",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "javamail", "smtp", "starttls", "cleartext"},
			})
		}
	}
	return findings
}

// ===========================================================================
// JAVA-041: SearchControls.setReturningObjFlag(true) — LDAP entry poisoning /
// JNDI object reconstruction on returned LDAP entries (CWE-90)
// ===========================================================================

var (
	reSearchReturningObj = regexp.MustCompile(`\.setReturningObjFlag\s*\(\s*true\b|new\s+SearchControls\s*\([^)]*\btrue\b[^)]*\)`)
	reDirContextSearch   = regexp.MustCompile(`\.search\s*\(|SearchControls`)
)

type JavaLdapReturningObject struct{}

func (r *JavaLdapReturningObject) ID() string                      { return "BATOU-JAVA-041" }
func (r *JavaLdapReturningObject) Name() string                    { return "JavaLdapReturningObject" }
func (r *JavaLdapReturningObject) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaLdapReturningObject) Description() string {
	return "Detects SearchControls configured to return objects (setReturningObjFlag(true)) — LDAP entries can carry serialized/JNDI-reference objects that get reconstructed on the client."
}
func (r *JavaLdapReturningObject) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaLdapReturningObject) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "SearchControls") {
		return nil
	}
	if !rules.GMatchFile(reDirContextSearch, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// The setReturningObjFlag(true) form is precise. The bare
		// new SearchControls(... true ...) constructor's 2nd arg is also the
		// returning-object flag, but its first arg is the scope int — too
		// ambiguous to flag without the explicit setter, so only fire on the
		// named setter.
		if strings.Contains(line, "setReturningObjFlag") && rules.GMatchLower(reSearchReturningObj, line, lowered[i]) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LDAP search returns objects (setReturningObjFlag(true))",
				Description:   "SearchControls.setReturningObjFlag(true) makes DirContext.search reconstruct the JNDI objects stored in matched LDAP entries. A malicious or compromised directory can return a JNDI reference (or serialized object) that triggers remote class loading / deserialization on the client — LDAP entry poisoning (CWE-90, the same class as the Log4Shell JNDI gadget).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Leave returning-object disabled (the default) and read attributes instead of reconstructed objects. If object return is required, query only trusted directories over LDAPS and set com.sun.jndi.ldap.object.trustURLCodebase=false (do not load remote codebases).",
				CWEID:         "CWE-90",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "ldap", "jndi", "entry-poisoning", "deserialization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&JavaDoPrivileged{})
	rules.Register(&JavaXSSStripBlocklist{})
	rules.Register(&JavaLdapAnonymousBind{})
	rules.Register(&JavaRestTemplateCleartext{})
	rules.Register(&JavaResteasyInsecureClient{})
	rules.Register(&JavaWeakKeySize{})
	rules.Register(&JavaGCMNonceReuse{})
	rules.Register(&JavaDefaultHttpClient{})
	rules.Register(&JavaMailNoTLS{})
	rules.Register(&JavaLdapReturningObject{})
}
