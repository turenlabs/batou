package python

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Extension patterns for PY-019 through PY-030
// ---------------------------------------------------------------------------

// PY-019: Django raw SQL query with format/f-string
var (
	reDjangoRawFStr    = regexp.MustCompile(`\.raw\s*\(\s*f["']`)
	reDjangoRawFormat  = regexp.MustCompile(`\.raw\s*\(\s*["'][^"']*["']\s*\.format\s*\(`)
	reDjangoCursorFStr = regexp.MustCompile(`cursor\.execute\s*\(\s*f["']`)
)

// PY-020: Flask debug mode enabled in production
var (
	reFlaskDebugTrue     = regexp.MustCompile(`app\.debug\s*=\s*True`)
	reFlaskRunDebug      = regexp.MustCompile(`\.run\s*\([^)]*debug\s*=\s*True`)
	reFlaskEnvDebug      = regexp.MustCompile(`FLASK_DEBUG\s*=\s*["']?1["']?`)
	reFlaskConfigDebug   = regexp.MustCompile(`config\s*\[\s*["']DEBUG["']\s*\]\s*=\s*True`)
)

// PY-021: Insecure use of xml.etree without defusedxml
var (
	reXMLParse       = regexp.MustCompile(`(?:xml\.etree\.ElementTree|ET)\.(?:parse|fromstring|iterparse|XMLParser)\s*\(`)
	reXMLSaxParse    = regexp.MustCompile(`xml\.sax\.(?:parse|parseString|make_parser)\s*\(`)
	reXMLDomParse    = regexp.MustCompile(`xml\.dom\.(?:minidom|pulldom)\.(?:parse|parseString)\s*\(`)
	reDefusedXML     = regexp.MustCompile(`defusedxml`)
)

// PY-022: os.chmod with overly permissive mode
var (
	reOsChmod777  = regexp.MustCompile(`os\.chmod\s*\([^,]+,\s*0o?777\s*\)`)
	reOsChmod666  = regexp.MustCompile(`os\.chmod\s*\([^,]+,\s*0o?666\s*\)`)
	reOsChmodStat = regexp.MustCompile(`os\.chmod\s*\([^,]+,\s*(?:stat\.S_IRWXU\s*\|\s*stat\.S_IRWXG\s*\|\s*stat\.S_IRWXO)\s*\)`)
)

// PY-023: Requests library SSL verification disabled
var (
	reRequestsSessionVerify = regexp.MustCompile(`\.verify\s*=\s*False`)
	reSessionGetNoVerify    = regexp.MustCompile(`session\.(?:get|post|put|delete|patch|head|options)\s*\([^)]*verify\s*=\s*False`)
)

// PY-024: Tarfile extractall without path validation
var (
	reTarOpen        = regexp.MustCompile(`tarfile\.open\s*\(`)
	reTarExtract     = regexp.MustCompile(`\.extract(?:all)?\s*\(`)
	reTarFilterSafe  = regexp.MustCompile(`filter\s*=\s*['"](?:data|tar|fully_trusted)['"]`)
)

// PY-025: Django SECRET_KEY hardcoded
var (
	reDjangoSecretKey      = regexp.MustCompile(`SECRET_KEY\s*=\s*["'][^"']{8,}["']`)
	reDjangoSecretKeyEnv   = regexp.MustCompile(`SECRET_KEY\s*=\s*(?:os\.(?:environ|getenv)|config\s*\(|env\s*\()`)
)

// PY-026: Insecure deserialization via jsonpickle/dill
var (
	reJsonpickleLoad = regexp.MustCompile(`jsonpickle\.(?:decode|loads?)\s*\(`)
	reDillLoad       = regexp.MustCompile(`dill\.(?:load|loads)\s*\(`)
	reJoblib         = regexp.MustCompile(`joblib\.load\s*\(`)
)

// PY-027: SQL Alchemy text() with f-string/format
var (
	reSATextFStr    = regexp.MustCompile(`text\s*\(\s*f["']`)
	reSATextFormat  = regexp.MustCompile(`text\s*\(\s*["'][^"']*["']\s*\.format\s*\(`)
	reSATextPercent = regexp.MustCompile(`text\s*\(\s*["'][^"']*["']\s*%\s*[(\w]`)
	reSAExecuteFStr = regexp.MustCompile(`(?:session|engine|connection|conn)\s*\.execute\s*\(\s*f["']`)
)

// PY-028: Django ALLOWED_HOSTS wildcard
var (
	reDjangoAllowedHostsStar = regexp.MustCompile(`ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]`)
	reDjangoAllowedEmpty     = regexp.MustCompile(`ALLOWED_HOSTS\s*=\s*\[\s*\]`)
)

// PY-029: Zipfile extract without checking filename
var (
	reZipfileExtract    = regexp.MustCompile(`(?:ZipFile|zipfile\.ZipFile)\s*\([^)]*\)`)
	reZipExtractMethod  = regexp.MustCompile(`\.extract\s*\(`)
	reZipExtractAll     = regexp.MustCompile(`\.extractall\s*\(`)
	reZipNameCheck      = regexp.MustCompile(`(?:\.filename|\.name|os\.path\.basename|startswith|realpath)`)
)

// PY-030: Unsafe regex with user input
var (
	reReCompileVar   = regexp.MustCompile(`re\.compile\s*\(\s*(?:request\.|user_input|param|query|pattern|search|data|payload|args\[)`)
	reReSearchVar    = regexp.MustCompile(`re\.(?:search|match|findall|sub|split)\s*\(\s*(?:request\.|user_input|param|query|pattern|search|data|payload|args\[)`)
	reReEscapeUsed   = regexp.MustCompile(`re\.escape\s*\(`)
)

func init() {
	rules.Register(&DjangoRawSQLFStr{})
	rules.Register(&FlaskDebugEnabled{})
	rules.Register(&InsecureXMLParsing{})
	rules.Register(&OsChmodPermissive{})
	rules.Register(&RequestsNoSSL{})
	rules.Register(&TarfilePathTraversal{})
	rules.Register(&DjangoHardcodedSecret{})
	rules.Register(&InsecureDeserJsonpickle{})
	rules.Register(&SQLAlchemyTextInjection{})
	rules.Register(&DjangoAllowedHostsWild{})
	rules.Register(&ZipfileZipSlip{})
	rules.Register(&UnsafeRegexUserInput{})
}

// ---------------------------------------------------------------------------
// PY-019: Django raw SQL query with format/f-string
// ---------------------------------------------------------------------------

type DjangoRawSQLFStr struct{}

func (r *DjangoRawSQLFStr) ID() string                      { return "GTSS-PY-019" }
func (r *DjangoRawSQLFStr) Name() string                    { return "DjangoRawSQLFStr" }
func (r *DjangoRawSQLFStr) DefaultSeverity() rules.Severity { return rules.High }
func (r *DjangoRawSQLFStr) Description() string {
	return "Detects Django .raw() and cursor.execute() with f-strings or .format(), enabling SQL injection."
}
func (r *DjangoRawSQLFStr) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *DjangoRawSQLFStr) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reDjangoRawFStr.FindString(line); m != "" {
			matched = m
		} else if m := reDjangoRawFormat.FindString(line); m != "" {
			matched = m
		} else if m := reDjangoCursorFStr.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django SQL injection via f-string/format in raw query",
				Description:   "Using f-strings or .format() in Django .raw() or cursor.execute() bypasses Django's parameterized query protection, enabling SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries: Model.objects.raw('SELECT * FROM t WHERE id = %s', [user_id]) or cursor.execute('SELECT * FROM t WHERE id = %s', [user_id]).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "django", "sql-injection", "f-string"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-020: Flask debug mode enabled in production
// ---------------------------------------------------------------------------

type FlaskDebugEnabled struct{}

func (r *FlaskDebugEnabled) ID() string                      { return "GTSS-PY-020" }
func (r *FlaskDebugEnabled) Name() string                    { return "FlaskDebugEnabled" }
func (r *FlaskDebugEnabled) DefaultSeverity() rules.Severity { return rules.High }
func (r *FlaskDebugEnabled) Description() string {
	return "Detects Flask debug mode enabled via app.debug, app.run(debug=True), or config, exposing Werkzeug debugger."
}
func (r *FlaskDebugEnabled) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FlaskDebugEnabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "flask") && !strings.Contains(ctx.Content, "Flask") && !strings.Contains(ctx.Content, "debug") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reFlaskDebugTrue.FindString(line); m != "" {
			matched = m
		} else if m := reFlaskConfigDebug.FindString(line); m != "" {
			matched = m
		} else if m := reFlaskEnvDebug.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Flask debug mode enabled in application code",
				Description:   "Flask debug mode enables the Werkzeug interactive debugger, which provides a Python shell in the browser. If deployed to production, anyone can execute arbitrary code on the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use environment variables: app.debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'. Never hardcode debug=True. Use gunicorn or waitress for production.",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "flask", "debug", "werkzeug"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-021: Insecure use of xml.etree without defusedxml
// ---------------------------------------------------------------------------

type InsecureXMLParsing struct{}

func (r *InsecureXMLParsing) ID() string                      { return "GTSS-PY-021" }
func (r *InsecureXMLParsing) Name() string                    { return "InsecureXMLParsing" }
func (r *InsecureXMLParsing) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureXMLParsing) Description() string {
	return "Detects use of Python's built-in xml.etree/xml.sax/xml.dom parsers without defusedxml, vulnerable to XXE."
}
func (r *InsecureXMLParsing) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *InsecureXMLParsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if reDefusedXML.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reXMLParse.FindString(line); m != "" {
			matched = m
		} else if m := reXMLSaxParse.FindString(line); m != "" {
			matched = m
		} else if m := reXMLDomParse.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure XML parsing without defusedxml (XXE vulnerability)",
				Description:   "Python's built-in XML parsers (xml.etree, xml.sax, xml.dom) are vulnerable to XML External Entity (XXE) attacks by default. An attacker can read local files, perform SSRF, or cause denial of service via entity expansion.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use defusedxml instead: from defusedxml.ElementTree import parse, fromstring. It blocks XXE, entity expansion, and DTD processing by default.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "xml", "xxe", "defusedxml"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-022: os.chmod with overly permissive mode
// ---------------------------------------------------------------------------

type OsChmodPermissive struct{}

func (r *OsChmodPermissive) ID() string                      { return "GTSS-PY-022" }
func (r *OsChmodPermissive) Name() string                    { return "OsChmodPermissive" }
func (r *OsChmodPermissive) DefaultSeverity() rules.Severity { return rules.High }
func (r *OsChmodPermissive) Description() string {
	return "Detects os.chmod() with overly permissive file modes (0o777, 0o666) that expose files."
}
func (r *OsChmodPermissive) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *OsChmodPermissive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reOsChmod777.FindString(line); m != "" {
			matched = m
		} else if m := reOsChmod666.FindString(line); m != "" {
			matched = m
		} else if m := reOsChmodStat.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "os.chmod with world-writable/world-readable permissions",
				Description:   "Setting file permissions to 0o777 or 0o666 allows any user on the system to read and write the file. This can expose sensitive data or allow code injection via file modification.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use restrictive permissions: os.chmod(path, 0o600) for sensitive files, 0o644 for public read-only files.",
				CWEID:         "CWE-732",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "chmod", "file-permissions"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-023: Requests library SSL verification disabled
// ---------------------------------------------------------------------------

type RequestsNoSSL struct{}

func (r *RequestsNoSSL) ID() string                      { return "GTSS-PY-023" }
func (r *RequestsNoSSL) Name() string                    { return "RequestsNoSSL" }
func (r *RequestsNoSSL) DefaultSeverity() rules.Severity { return rules.High }
func (r *RequestsNoSSL) Description() string {
	return "Detects requests.Session with verify=False or session-level SSL verification disabled."
}
func (r *RequestsNoSSL) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *RequestsNoSSL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "session") && !strings.Contains(ctx.Content, "Session") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reRequestsSessionVerify.FindString(line); m != "" {
			matched = m
		} else if m := reSessionGetNoVerify.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Requests session with SSL verification disabled",
				Description:   "Setting verify=False on a requests Session disables TLS certificate verification for all subsequent requests. This makes the connection vulnerable to man-in-the-middle attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove verify=False. For self-signed certificates, set verify='/path/to/ca-bundle.crt'. For development, use mkcert for locally-trusted certs.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "requests", "ssl", "certificate"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-024: Tarfile extractall without path validation
// ---------------------------------------------------------------------------

type TarfilePathTraversal struct{}

func (r *TarfilePathTraversal) ID() string                      { return "GTSS-PY-024" }
func (r *TarfilePathTraversal) Name() string                    { return "TarfilePathTraversal" }
func (r *TarfilePathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *TarfilePathTraversal) Description() string {
	return "Detects tarfile.extractall() without filter parameter (CVE-2007-4559 path traversal)."
}
func (r *TarfilePathTraversal) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *TarfilePathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "tarfile") {
		return nil
	}
	if reTarFilterSafe.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if reTarExtract.MatchString(line) && !reTarFilterSafe.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Tarfile extraction without path validation (CVE-2007-4559)",
				Description:   "tarfile.extractall() without the filter parameter extracts entries with arbitrary paths including ../../ traversal sequences. A malicious tar archive can write files anywhere on the filesystem.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use extractall(filter='data') on Python 3.12+. On older versions, iterate members and validate each path: if os.path.isabs(member.name) or '..' in member.name: skip.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "tarfile", "path-traversal", "zip-slip"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-025: Django SECRET_KEY hardcoded
// ---------------------------------------------------------------------------

type DjangoHardcodedSecret struct{}

func (r *DjangoHardcodedSecret) ID() string                      { return "GTSS-PY-025" }
func (r *DjangoHardcodedSecret) Name() string                    { return "DjangoHardcodedSecret" }
func (r *DjangoHardcodedSecret) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DjangoHardcodedSecret) Description() string {
	return "Detects Django SECRET_KEY hardcoded as a string literal instead of loaded from environment."
}
func (r *DjangoHardcodedSecret) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *DjangoHardcodedSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "SECRET_KEY") {
		return nil
	}
	if reDjangoSecretKeyEnv.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if m := reDjangoSecretKey.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django SECRET_KEY hardcoded in source code",
				Description:   "The Django SECRET_KEY is hardcoded as a string literal. This key signs session cookies, CSRF tokens, password reset tokens, and other security-critical data. Anyone with source code access can forge these values.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Load SECRET_KEY from environment: SECRET_KEY = os.environ['SECRET_KEY']. Use django-environ or python-decouple for configuration management.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "django", "secret-key", "hardcoded"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-026: Insecure deserialization via jsonpickle/dill
// ---------------------------------------------------------------------------

type InsecureDeserJsonpickle struct{}

func (r *InsecureDeserJsonpickle) ID() string                      { return "GTSS-PY-026" }
func (r *InsecureDeserJsonpickle) Name() string                    { return "InsecureDeserJsonpickle" }
func (r *InsecureDeserJsonpickle) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureDeserJsonpickle) Description() string {
	return "Detects insecure deserialization via jsonpickle, dill, or joblib which allow arbitrary code execution."
}
func (r *InsecureDeserJsonpickle) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *InsecureDeserJsonpickle) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		var lib string
		if m := reJsonpickleLoad.FindString(line); m != "" {
			matched = m
			lib = "jsonpickle"
		} else if m := reDillLoad.FindString(line); m != "" {
			matched = m
			lib = "dill"
		} else if m := reJoblib.FindString(line); m != "" {
			matched = m
			lib = "joblib"
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure deserialization via " + lib,
				Description:   lib + " deserializes arbitrary Python objects, allowing remote code execution if the serialized data is attacker-controlled. Unlike pickle, " + lib + "'s JSON format may give a false sense of security.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use standard json.loads() for data exchange. If object serialization is needed, use pydantic or dataclasses with explicit schema validation.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", lib, "deserialization", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-027: SQL Alchemy text() with f-string/format
// ---------------------------------------------------------------------------

type SQLAlchemyTextInjection struct{}

func (r *SQLAlchemyTextInjection) ID() string                      { return "GTSS-PY-027" }
func (r *SQLAlchemyTextInjection) Name() string                    { return "SQLAlchemyTextInjection" }
func (r *SQLAlchemyTextInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *SQLAlchemyTextInjection) Description() string {
	return "Detects SQLAlchemy text() or execute() with f-strings or .format(), bypassing parameterized queries."
}
func (r *SQLAlchemyTextInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *SQLAlchemyTextInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reSATextFStr.FindString(line); m != "" {
			matched = m
		} else if m := reSATextFormat.FindString(line); m != "" {
			matched = m
		} else if m := reSATextPercent.FindString(line); m != "" {
			matched = m
		} else if m := reSAExecuteFStr.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQLAlchemy SQL injection via f-string/format in text()",
				Description:   "Using f-strings or .format() inside SQLAlchemy text() or execute() bypasses parameterized query protection. User input interpolated into the SQL string enables SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use SQLAlchemy's bind parameters: text('SELECT * FROM t WHERE id = :id').bindparams(id=user_id) or session.execute(text('...'), {'id': user_id}).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "sqlalchemy", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-028: Django ALLOWED_HOSTS wildcard
// ---------------------------------------------------------------------------

type DjangoAllowedHostsWild struct{}

func (r *DjangoAllowedHostsWild) ID() string                      { return "GTSS-PY-028" }
func (r *DjangoAllowedHostsWild) Name() string                    { return "DjangoAllowedHostsWild" }
func (r *DjangoAllowedHostsWild) DefaultSeverity() rules.Severity { return rules.High }
func (r *DjangoAllowedHostsWild) Description() string {
	return "Detects Django ALLOWED_HOSTS set to ['*'] which disables host header validation."
}
func (r *DjangoAllowedHostsWild) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoAllowedHostsWild) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "ALLOWED_HOSTS") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if m := reDjangoAllowedHostsStar.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django ALLOWED_HOSTS set to wildcard ['*']",
				Description:   "Setting ALLOWED_HOSTS = ['*'] disables Django's Host header validation. This enables HTTP Host header injection attacks including cache poisoning, password reset poisoning, and SSRF via the Host header.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Set ALLOWED_HOSTS to your actual domain names: ALLOWED_HOSTS = ['example.com', 'www.example.com']. Use environment variables for different environments.",
				CWEID:         "CWE-16",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "django", "allowed-hosts", "host-header"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-029: Zipfile extract without checking filename
// ---------------------------------------------------------------------------

type ZipfileZipSlip struct{}

func (r *ZipfileZipSlip) ID() string                      { return "GTSS-PY-029" }
func (r *ZipfileZipSlip) Name() string                    { return "ZipfileZipSlip" }
func (r *ZipfileZipSlip) DefaultSeverity() rules.Severity { return rules.High }
func (r *ZipfileZipSlip) Description() string {
	return "Detects Python zipfile extract/extractall without checking filenames for path traversal (zip slip)."
}
func (r *ZipfileZipSlip) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *ZipfileZipSlip) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "zipfile") && !strings.Contains(ctx.Content, "ZipFile") {
		return nil
	}
	if reZipNameCheck.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		if reZipExtractAll.MatchString(line) || reZipExtractMethod.MatchString(line) {
			if strings.Contains(line, "zipfile") || strings.Contains(line, "ZipFile") || strings.Contains(ctx.Content, "ZipFile") {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Zipfile extraction without filename validation (zip slip)",
					Description:   "zipfile.extract() or extractall() without validating member filenames allows path traversal. A malicious zip archive can contain entries like ../../etc/cron.d/backdoor to write files outside the target directory.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Validate each entry's filename before extraction: for info in zf.infolist(): target = os.path.join(dest, info.filename); if not os.path.realpath(target).startswith(os.path.realpath(dest)): raise ValueError('Zip slip')",
					CWEID:         "CWE-22",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"python", "zipfile", "zip-slip", "path-traversal"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PY-030: Unsafe regex with user input
// ---------------------------------------------------------------------------

type UnsafeRegexUserInput struct{}

func (r *UnsafeRegexUserInput) ID() string                      { return "GTSS-PY-030" }
func (r *UnsafeRegexUserInput) Name() string                    { return "UnsafeRegexUserInput" }
func (r *UnsafeRegexUserInput) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UnsafeRegexUserInput) Description() string {
	return "Detects re.compile/search/match with user-controlled input as the pattern, enabling ReDoS."
}
func (r *UnsafeRegexUserInput) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *UnsafeRegexUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if reReEscapeUsed.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isPyComment(t) {
			continue
		}
		var matched string
		if m := reReCompileVar.FindString(line); m != "" {
			matched = m
		} else if m := reReSearchVar.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "User-controlled input used as regex pattern (ReDoS risk)",
				Description:   "User input is passed directly as a regex pattern to re.compile/search/match. A malicious pattern with nested quantifiers (e.g., (a+)+) causes catastrophic backtracking, freezing the process.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Escape user input with re.escape() before using it in regex: re.compile(re.escape(user_input)). Or use string methods (str.find, str.replace) for simple matching.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "regex", "redos", "user-input"},
			})
		}
	}
	return findings
}
