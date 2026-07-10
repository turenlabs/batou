package python

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// ECL campaign — Python rule-breadth (BATOU-PY-031, 033, 035, 037, 040, 041)
//
// Every rule in this file is FRAMEWORK / LIBRARY-anchored: the regex matches a
// distinctive vendor API (paramiko AutoAddPolicy, ssl.wrap_socket, hashids
// seeded with a secret, a render() context built from globals()/locals(),
// float() applied to request data), never a bare builtin name that would
// collide with unrelated code. Each rule carries a same-line safe-usage escape
// so the documented secure pattern stays clean.
//
// Detections that already exist elsewhere in the catalog are deliberately NOT
// re-implemented here — adding a second rule on the same (line, CWE) would
// either dedup away (dead code) or double-fire (FP inflation):
//   - jinja2.Environment autoescape  → BATOU-PY-003 (python.go)
//   - MongoDB $where server-side JS  → BATOU-NOSQL-001 (nosql.go)
//   - world-writable 0o777/0o666     → BATOU-MISC-010 (misconfig_ext.go)
//   - hardcoded default-arg secret   → BATOU-SEC-001 (secrets.go, default-arg form)
//   - requests/httpx verify=False    → BATOU-PY-023 + python.go requestsVerifyFalse
// ---------------------------------------------------------------------------

// PY-031: paramiko host-key policy that auto-accepts unknown server keys (MITM)
var (
	// set_missing_host_key_policy(AutoAddPolicy()) / WarningPolicy() — both
	// silently trust an unknown host key. RejectPolicy() is the secure choice
	// and is explicitly NOT matched.
	rePyParamikoAutoAdd = regexp.MustCompile(`set_missing_host_key_policy\s*\(\s*(?:paramiko\.)?(?:client\.)?(?:AutoAddPolicy|WarningPolicy)\s*\(`)
)

// PY-033: ssl.wrap_socket() with a downgraded/insecure protocol version
var (
	rePySSLWrapSocket = regexp.MustCompile(`ssl\.wrap_socket\s*\(`)
	// Explicit insecure protocol selection — PROTOCOL_SSLv2/SSLv3/SSLv23/TLSv1/
	// TLSv1_1. PROTOCOL_TLS / PROTOCOL_TLS_CLIENT (the modern auto-negotiating
	// constants) are NOT matched.
	rePySSLInsecureProto = regexp.MustCompile(`ssl\.PROTOCOL_(?:SSLv2|SSLv3|SSLv23|TLSv1(?:_1)?)\b`)
)

// PY-035: hashids / obfuscation library seeded with the application SECRET_KEY
var (
	// Hashids(salt=SECRET_KEY) / Hashids(SECRET_KEY) / Hashids(app.secret_key).
	// Reusing the crypto secret as a hashids salt both leaks rotation surface
	// and treats a reversible, non-crypto obfuscator as if it were a MAC.
	rePyHashidsSecret = regexp.MustCompile(`Hashids\s*\([^)]*(?:SECRET_KEY|secret_key|SECRET|\.secret_key)`)
)

// PY-037: template render() context built from globals()/locals()
var (
	// render(request, 'tpl.html', globals()) or Context(locals()) — leaks the
	// whole namespace (secrets, settings, internal objects) into the template.
	rePyRenderGlobals = regexp.MustCompile(`(?:render|render_to_response|render_to_string|get_template\s*\([^)]*\)\s*\.render|Context)\s*\([^)]*\b(?:globals|locals)\s*\(\s*\)`)
)

// PY-040: float(user_input) NaN/Infinity injection (CWE-1289)
var (
	// float(request.args['x']) / float(request.form.get(...)) etc. — the
	// builtin float() accepts the literal strings 'nan', 'inf', '-inf', which
	// poison subsequent numeric comparisons (NaN != NaN, every `<`/`>` is
	// False), bypassing range/auth checks. Anchored to a request-derived
	// argument so it never fires on float() of a constant.
	rePyFloatRequest = regexp.MustCompile(`\bfloat\s*\(\s*(?:request\.(?:args|form|values|GET|POST|data|json|cookies|headers|query_params|params)\b|self\.request\.|flask\.request\.)`)
)

// PY-041: os file-creation / mkdir API called with a world-writable mode literal
var (
	// os.open / os.mkdir / os.makedirs / os.mkfifo / os.mknod with an explicit
	// 0o777 / 0o666 / 0777 / 0666 mode literal anywhere in the arg list. The
	// distinctive `os.<api>(` prefix anchors this to the os module (never a bare
	// open()/mkdir on some unrelated object), and the explicit world-writable
	// octal literal is the unambiguous vulnerable signal — restrictive modes
	// (0o600/0o644/0o700/0o755) are NOT matched. Complements BATOU-PY-022, which
	// only covered os.chmod.
	rePyOsWorldWritable = regexp.MustCompile(`\bos\.(?:open|mkdir|makedirs|mkfifo|mknod)\s*\([^)]*,\s*0o?(?:777|666)\b`)
	// os.umask(0) / os.umask(0o000) disables the process umask entirely, so every
	// subsequent file is created world-writable regardless of the requested mode.
	rePyOsUmaskZero = regexp.MustCompile(`\bos\.umask\s*\(\s*0o?0*\s*\)`)
)

func init() {
	rules.Register(&ParamikoAutoAddHostKey{})
	rules.Register(&SSLWrapSocketInsecure{})
	rules.Register(&HashidsSecretKeySalt{})
	rules.Register(&RenderNamespaceContext{})
	rules.Register(&FloatNaNInjection{})
	rules.Register(&OsWorldWritableCreate{})
}

// ---------------------------------------------------------------------------
// PY-031: paramiko AutoAddPolicy / WarningPolicy (CWE-295)
// ---------------------------------------------------------------------------

type ParamikoAutoAddHostKey struct{}

func (r *ParamikoAutoAddHostKey) ID() string                      { return "BATOU-PY-031" }
func (r *ParamikoAutoAddHostKey) Name() string                    { return "ParamikoAutoAddHostKey" }
func (r *ParamikoAutoAddHostKey) DefaultSeverity() rules.Severity { return rules.High }
func (r *ParamikoAutoAddHostKey) Description() string {
	return "Detects paramiko SSHClient.set_missing_host_key_policy(AutoAddPolicy()/WarningPolicy()), which trusts unknown SSH host keys and enables man-in-the-middle attacks."
}
func (r *ParamikoAutoAddHostKey) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *ParamikoAutoAddHostKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "set_missing_host_key_policy") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if m := rules.GFindLower(rePyParamikoAutoAdd, line, lowered[i]); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "paramiko trusts unknown SSH host keys (MITM)",
				Description:   "set_missing_host_key_policy(AutoAddPolicy()) (or WarningPolicy()) tells paramiko to silently accept any server host key it has not seen before. An attacker who can intercept the connection can present their own key and the client will trust it, enabling a man-in-the-middle attack on the SSH session.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use RejectPolicy() and pre-populate known host keys with client.load_system_host_keys() / load_host_keys(), or pin the expected server key. Only AutoAddPolicy in throwaway test code.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "paramiko", "ssh", "tls", "mitm"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-033: ssl.wrap_socket() with insecure protocol (CWE-326 / CWE-327)
// ---------------------------------------------------------------------------

type SSLWrapSocketInsecure struct{}

func (r *SSLWrapSocketInsecure) ID() string                      { return "BATOU-PY-033" }
func (r *SSLWrapSocketInsecure) Name() string                    { return "SSLWrapSocketInsecure" }
func (r *SSLWrapSocketInsecure) DefaultSeverity() rules.Severity { return rules.High }
func (r *SSLWrapSocketInsecure) Description() string {
	return "Detects the deprecated ssl.wrap_socket() API and explicit selection of an obsolete TLS/SSL protocol version (SSLv2/SSLv3/SSLv23/TLSv1/TLSv1.1)."
}
func (r *SSLWrapSocketInsecure) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *SSLWrapSocketInsecure) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasWrap := strings.Contains(ctx.Content, "ssl.wrap_socket")
	hasProto := strings.Contains(ctx.Content, "ssl.PROTOCOL_")
	if !hasWrap && !hasProto {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var title, desc, matched string
		if m := rules.GFindLower(rePySSLInsecureProto, line, lowered[i]); m != "" {
			matched = m
			title = "Insecure SSL/TLS protocol version selected"
			desc = "Explicitly selecting an obsolete protocol (SSLv2, SSLv3, SSLv23, TLSv1, or TLSv1.1) forces the connection onto a version with known cryptographic weaknesses (POODLE, BEAST, etc.). These protocols must not be negotiated."
		} else if m := rules.GFindLower(rePySSLWrapSocket, line, lowered[i]); m != "" {
			matched = m
			title = "Deprecated ssl.wrap_socket() in use"
			desc = "ssl.wrap_socket() is deprecated and does not perform hostname verification by default. It is removed in modern Python; using it leaves the connection open to man-in-the-middle attacks."
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use ssl.create_default_context() (which selects a safe protocol and verifies the certificate + hostname) and call context.wrap_socket(sock, server_hostname=host). Never pin to SSLv*/TLSv1*.",
				CWEID:         "CWE-326",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "ssl", "tls", "crypto"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-035: hashids seeded with SECRET_KEY (CWE-326)
// ---------------------------------------------------------------------------

type HashidsSecretKeySalt struct{}

func (r *HashidsSecretKeySalt) ID() string                      { return "BATOU-PY-035" }
func (r *HashidsSecretKeySalt) Name() string                    { return "HashidsSecretKeySalt" }
func (r *HashidsSecretKeySalt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *HashidsSecretKeySalt) Description() string {
	return "Detects a hashids obfuscator seeded with the application SECRET_KEY/secret_key. Hashids is reversible and non-cryptographic; reusing the crypto secret as its salt treats a predictable ID as if it were a secret."
}
func (r *HashidsSecretKeySalt) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *HashidsSecretKeySalt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "Hashids") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if m := rules.GFindLower(rePyHashidsSecret, line, lowered[i]); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hashids seeded with the application SECRET_KEY",
				Description:   "Hashids is a reversible, non-cryptographic obfuscation library — it provides no integrity or confidentiality. Seeding it with SECRET_KEY both ties IDs to the crypto secret (so a leaked ID scheme narrows the secret's rotation) and gives a false impression that the resulting IDs are unguessable. Treat hashids output as public.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use a dedicated random salt for Hashids (not SECRET_KEY) and never rely on hashids for authorization. For unguessable tokens use secrets.token_urlsafe().",
				CWEID:         "CWE-326",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "hashids", "crypto", "secret"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-037: render() context built from globals()/locals() (CWE-200)
// ---------------------------------------------------------------------------

type RenderNamespaceContext struct{}

func (r *RenderNamespaceContext) ID() string                      { return "BATOU-PY-037" }
func (r *RenderNamespaceContext) Name() string                    { return "RenderNamespaceContext" }
func (r *RenderNamespaceContext) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RenderNamespaceContext) Description() string {
	return "Detects a template render context built from globals()/locals(), which exposes the entire namespace — including secrets, settings, and internal objects — to the template."
}
func (r *RenderNamespaceContext) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *RenderNamespaceContext) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "globals()") && !strings.Contains(ctx.Content, "locals()") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if m := rules.GFindLower(rePyRenderGlobals, line, lowered[i]); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Template context built from globals()/locals()",
				Description:   "Passing globals() or locals() as the template context hands the template the entire namespace: SECRET_KEY, database credentials, internal helper objects, and anything else in scope. A template-injection or even a benign authoring mistake can then leak those values into the rendered page.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Build the context explicitly with only the variables the template needs: render(request, 'tpl.html', {'user': user, 'items': items}).",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "django", "template", "info-exposure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-040: float(user_input) NaN/Infinity injection (CWE-1289)
// ---------------------------------------------------------------------------

type FloatNaNInjection struct{}

func (r *FloatNaNInjection) ID() string                      { return "BATOU-PY-040" }
func (r *FloatNaNInjection) Name() string                    { return "FloatNaNInjection" }
func (r *FloatNaNInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FloatNaNInjection) Description() string {
	return "Detects float() called directly on request data. Python's float() parses 'nan'/'inf'/'-inf', and NaN breaks every numeric comparison (NaN != NaN), allowing range/quota/auth checks to be bypassed."
}
func (r *FloatNaNInjection) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FloatNaNInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "float(") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if m := rules.GFindLower(rePyFloatRequest, line, lowered[i]); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "float() of request data — NaN/Infinity injection",
				Description:   "float() converts the strings 'nan', 'inf', and '-inf' into special IEEE-754 values. NaN compares False against everything (including itself), so a request value of 'nan' silently defeats range checks (`if x < limit`), quotas, and price/amount validation; 'inf' overflows accumulators. The value reaches a comparison without ever being rejected.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "After conversion, reject non-finite input: v = float(raw); if not math.isfinite(v): abort(400). Or validate with a schema (pydantic, marshmallow) that disallows nan/inf.",
				CWEID:         "CWE-1289",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "validation", "nan", "type-confusion"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-041: os.open/mkdir/makedirs/mkfifo with world-writable mode, or
//         os.umask(0) (CWE-732 — insecure file permissions)
// ---------------------------------------------------------------------------

type OsWorldWritableCreate struct{}

func (r *OsWorldWritableCreate) ID() string                      { return "BATOU-PY-041" }
func (r *OsWorldWritableCreate) Name() string                    { return "OsWorldWritableCreate" }
func (r *OsWorldWritableCreate) DefaultSeverity() rules.Severity { return rules.High }
func (r *OsWorldWritableCreate) Description() string {
	return "Detects os.open/os.mkdir/os.makedirs/os.mkfifo/os.mknod called with a world-writable mode literal (0o777/0o666), or os.umask(0) which makes every subsequently created file world-writable."
}
func (r *OsWorldWritableCreate) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *OsWorldWritableCreate) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.Contains(ctx.Content, "os.") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var title, desc, matched string
		if m := rules.GFindLower(rePyOsWorldWritable, line, lowered[i]); m != "" {
			matched = m
			title = "os file/directory created with world-writable permissions"
			desc = "Creating a file or directory with mode 0o777 or 0o666 grants every local user read and write access. An attacker on the same host can read sensitive data written to the file, or overwrite it to inject content/code that the owning process later trusts."
		} else if m := rules.GFindLower(rePyOsUmaskZero, line, lowered[i]); m != "" {
			matched = m
			title = "os.umask(0) disables default permission masking"
			desc = "os.umask(0) clears the process umask, so files and directories created afterwards keep their full requested mode — typically world-writable (0o666/0o777). Every file the process creates from this point is exposed to all local users."
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use restrictive modes: 0o600 (private files), 0o644 (public read-only), 0o700/0o750 (directories). Set a sane umask (os.umask(0o077)) instead of clearing it, and never pass 0o777/0o666 to os.open/os.mkdir/os.makedirs.",
				CWEID:         "CWE-732",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "os", "file-permissions", "world-writable"},
			})
		}
	}
	return findings
}
