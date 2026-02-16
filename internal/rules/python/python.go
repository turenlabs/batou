package python

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled patterns ---

// PY-001: subprocess shell injection (more specific than generic INJ-002)
var (
	subprocessShellTrue = regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*shell\s*=\s*True`)
	subprocessFString   = regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output|check_call)\s*\(\s*f["']`)
	subprocessFormat    = regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*\.format\s*\(`)
	subprocessPercent   = regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*%\s*[(\w]`)
	subprocessConcat    = regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output|check_call)\s*\(\s*(?:[a-zA-Z_]\w*\s*\+|"[^"]*"\s*\+)`)
)

// PY-002: os.path.join traversal with user input
var (
	osPathJoinInput = regexp.MustCompile(`os\.path\.join\s*\(`)
)

// PY-003: Jinja2 Environment autoescape disabled
var (
	jinja2EnvAutoescapeFalse = regexp.MustCompile(`Environment\s*\([^)]*autoescape\s*=\s*(?:False|0)`)
	jinja2EnvNoAutoescape    = regexp.MustCompile(`Environment\s*\(`)
	jinja2AutoescapeTrue     = regexp.MustCompile(`autoescape\s*=\s*(?:True|select_autoescape|1)`)
)

// PY-004: yaml.load without SafeLoader
var (
	yamlUnsafeLoad = regexp.MustCompile(`yaml\.(?:load|unsafe_load)\s*\(`)
	yamlSafeLoader = regexp.MustCompile(`Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|CSafeLoader|FullLoader|CFullLoader)`)
	yamlSafeLoad   = regexp.MustCompile(`yaml\.safe_load\s*\(`)
)

// PY-005: tempfile.mktemp (race condition)
var (
	tempfileMktemp = regexp.MustCompile(`tempfile\.mktemp\s*\(`)
)

// PY-006: assert for security checks
var (
	assertSecurity = regexp.MustCompile(`\bassert\b\s+(?:[a-zA-Z_]\w*\.)*(?:is_authenticated|is_admin|is_superuser|is_staff|has_permission|has_role|check_permission|is_authorized|is_valid|is_verified|check_auth|verify_token|validate_token|check_access)`)
	assertCompare  = regexp.MustCompile(`\bassert\b\s+(?:password|token|secret|api_key|session|role|permission|credential)\b`)
)

// PY-007: pickle/dill/cloudpickle/shelve deserialization (more specific patterns)
var (
	pickleLoadUserInput = regexp.MustCompile(`(?:pickle|cPickle|dill|cloudpickle|shelve|marshal)\.(?:load|loads)\s*\(`)
	pickleFromRequest   = regexp.MustCompile(`(?:request\.|flask\.|bottle\.)`)
)

// PY-008: hmac.compare_digest missing (timing attack)
var (
	directTokenCompare = regexp.MustCompile(`(?:token|secret|api_key|password_hash|signature|hmac|digest|hash_value)\s*(?:==|!=)\s*(?:[a-zA-Z_]\w*|["'])`)
	hmacCompareDigest  = regexp.MustCompile(`hmac\.compare_digest`)
	secretsCompare     = regexp.MustCompile(`secrets\.compare_digest`)
)

// PY-009: Django raw SQL / extra / RawSQL
var (
	djangoRawSQL      = regexp.MustCompile(`\.raw\s*\(\s*(?:f["']|["'][^"']*["']\s*%\s*[(\w]|["'][^"']*["']\s*\.format\s*\()`)
	djangoExtra       = regexp.MustCompile(`\.extra\s*\(\s*(?:where|select|tables)\s*=`)
	djangoRawSQLExpr  = regexp.MustCompile(`RawSQL\s*\(\s*(?:f["']|["'][^"']*["']\s*%\s*[(\w]|["'][^"']*["']\s*\.format\s*\()`)
	djangoConnection  = regexp.MustCompile(`connection\.cursor\s*\(\s*\)`)
	djangoCursorExec  = regexp.MustCompile(`cursor\.execute\s*\(\s*(?:f["']|["'][^"']*["']\s*%\s*[(\w]|["'][^"']*["']\s*\.format\s*\(|[a-zA-Z_]\w*\s*(?:\+|%))`)
)

// PY-010: Flask secret_key hardcoded (more specific patterns)
var (
	flaskSecretHardcoded = regexp.MustCompile(`(?:(?:SECRET_KEY|secret_key)\s*=\s*["'][^"']+["']|config\s*\[\s*["']SECRET_KEY["']\s*\]\s*=\s*["'][^"']+["'])`)
	flaskSecretEnv       = regexp.MustCompile(`(?:SECRET_KEY|secret_key)\s*=\s*os\.(?:environ|getenv)`)
)

// PY-011: requests/urllib3 TLS verification disabled
var (
	requestsVerifyFalse   = regexp.MustCompile(`requests\.(?:get|post|put|delete|patch|head|options|request)\s*\([^)]*verify\s*=\s*False`)
	urllib3DisableWarnings = regexp.MustCompile(`urllib3\.disable_warnings\s*\(`)
	urllib3NoVerify        = regexp.MustCompile(`HTTPSConnectionPool\s*\([^)]*cert_reqs\s*=\s*["']CERT_NONE["']`)
	sslNoVerify           = regexp.MustCompile(`ssl\._create_unverified_context`)
	httpxVerifyFalse      = regexp.MustCompile(`httpx\.(?:Client|AsyncClient)\s*\([^)]*verify\s*=\s*False`)
	aiohttpNoVerify       = regexp.MustCompile(`(?:ssl\s*=\s*False|connector\s*=\s*aiohttp\.TCPConnector\s*\([^)]*ssl\s*=\s*False)`)
)

// PY-012: ReDoS via re.compile with user input
var (
	reCompileUserInput = regexp.MustCompile(`re\.(?:compile|match|search|findall|sub|split)\s*\(`)
)

// PY-013: tarfile/zipfile extraction without filter
var (
	tarExtractAll     = regexp.MustCompile(`\.extractall\s*\(`)
	tarExtractFilter  = regexp.MustCompile(`filter\s*=`)
	tarExtractMembers = regexp.MustCompile(`members\s*=`)
	zipExtractAll     = regexp.MustCompile(`ZipFile\s*\([^)]*\)\s*\.extractall`)
)

// PY-014: f-string in logging (injection + performance)
var (
	loggingFString = regexp.MustCompile(`(?:logging\.(?:debug|info|warning|error|critical|exception)|logger\.(?:debug|info|warning|error|critical|exception)|log\.(?:debug|info|warning|error|critical|exception))\s*\(\s*f["']`)
	loggingFormat  = regexp.MustCompile(`(?:logging\.(?:debug|info|warning|error|critical|exception)|logger\.(?:debug|info|warning|error|critical|exception)|log\.(?:debug|info|warning|error|critical|exception))\s*\(\s*["'][^"']*["']\s*\.format\s*\(`)
	loggingPercent = regexp.MustCompile(`(?:logging\.(?:debug|info|warning|error|critical|exception)|logger\.(?:debug|info|warning|error|critical|exception)|log\.(?:debug|info|warning|error|critical|exception))\s*\(\s*["'][^"']*["']\s*%\s*[(\w]`)
)

// PY-015: jwt.decode without verification
var (
	jwtDecodeNoVerify  = regexp.MustCompile(`jwt\.decode\s*\([^)]*(?:verify\s*=\s*False|options\s*=\s*\{[^}]*"verify_signature"\s*:\s*False)`)
	jwtDecodeAlgNone   = regexp.MustCompile(`jwt\.decode\s*\([^)]*algorithms\s*=\s*\[?\s*["']none["']`)
)

// PY-016: Werkzeug/Flask debugger in production
var (
	werkzeugDebugger   = regexp.MustCompile(`(?:run_simple|serve)\s*\([^)]*use_debugger\s*=\s*True`)
	werkzeugDebuggerPW = regexp.MustCompile(`debugger_pin\s*=`)
	flaskDebugRun      = regexp.MustCompile(`app\.run\s*\([^)]*debug\s*=\s*True`)
	debugToolbar       = regexp.MustCompile(`DebugToolbarExtension\s*\(`)
)

// PY-017: FastAPI missing input validation
var (
	fastapiQueryParam = regexp.MustCompile(`(?:Query|Header|Cookie|Path)\s*\(\s*\)`)
	fastapiRawBody    = regexp.MustCompile(`(?:Body\s*\(\s*\.\.\.\s*\)|await\s+request\.(?:json|body)\s*\(\s*\))`)
)

// PY-018: asyncio subprocess with shell=True
var (
	asyncioShellTrue = regexp.MustCompile(`(?:asyncio\.create_subprocess_shell|await\s+asyncio\.create_subprocess_shell)\s*\(`)
	asyncioShellConcat = regexp.MustCompile(`create_subprocess_shell\s*\(\s*(?:f["']|["'][^"']*"\s*\+|[a-zA-Z_]\w*\s*\+)`)
)

func init() {
	rules.Register(&SubprocessShellInjection{})
	rules.Register(&PathTraversal{})
	rules.Register(&Jinja2AutoescapeDisabled{})
	rules.Register(&UnsafeYAMLLoad{})
	rules.Register(&TempfileMktemp{})
	rules.Register(&AssertSecurity{})
	rules.Register(&UnsafeDeserialization{})
	rules.Register(&TimingAttack{})
	rules.Register(&DjangoRawSQL{})
	rules.Register(&FlaskHardcodedSecret{})
	rules.Register(&TLSVerificationDisabled{})
	rules.Register(&ReDoS{})
	rules.Register(&UnsafeArchiveExtraction{})
	rules.Register(&LoggingInjection{})
	rules.Register(&JWTNoVerification{})
	rules.Register(&DebuggerInProduction{})
	rules.Register(&FastAPIMissingValidation{})
	rules.Register(&AsyncioShellInjection{})
}

// --- PY-001: Subprocess Shell Injection ---

type SubprocessShellInjection struct{}

func (r *SubprocessShellInjection) ID() string                      { return "BATOU-PY-001" }
func (r *SubprocessShellInjection) Name() string                    { return "SubprocessShellInjection" }
func (r *SubprocessShellInjection) Description() string             { return "Detects subprocess calls with shell=True and user-controlled input, or string formatting in shell commands." }
func (r *SubprocessShellInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SubprocessShellInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *SubprocessShellInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := subprocessShellTrue.FindString(line); loc != "" {
			matched = loc
			desc = "subprocess with shell=True"
		} else if loc := subprocessFString.FindString(line); loc != "" {
			matched = loc
			desc = "subprocess with f-string command"
		} else if loc := subprocessFormat.FindString(line); loc != "" {
			matched = loc
			desc = "subprocess with .format() command"
		} else if loc := subprocessPercent.FindString(line); loc != "" {
			matched = loc
			desc = "subprocess with %-formatted command"
		} else if loc := subprocessConcat.FindString(line); loc != "" {
			matched = loc
			desc = "subprocess with concatenated command"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Shell injection via " + desc,
				Description:   "Using " + desc + " allows arbitrary command execution. An attacker who controls any part of the command string can inject shell metacharacters to execute additional commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use subprocess with shell=False (the default) and pass arguments as a list: subprocess.run(['cmd', arg1, arg2]). For complex commands, use shlex.split() on trusted command templates only.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "subprocess", "shell-injection", "command-injection"},
			})
		}
	}

	return findings
}

// --- PY-002: Path Traversal via os.path.join ---

type PathTraversal struct{}

func (r *PathTraversal) ID() string                      { return "BATOU-PY-002" }
func (r *PathTraversal) Name() string                    { return "PathTraversal" }
func (r *PathTraversal) Description() string             { return "Detects os.path.join with user-controlled input that may allow directory traversal." }
func (r *PathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *PathTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag when user input sources are present in the file
	hasUserInput := containsUserInputSource(ctx.Content)
	if !hasUserInput {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if osPathJoinInput.MatchString(line) {
			// Check if line references user-controlled variables
			context := surroundingContext(lines, i, 3)
			if containsUserVariable(context) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Path traversal via os.path.join with user input",
					Description:   "os.path.join() does not prevent directory traversal. If the second argument starts with '/', it discards the first argument entirely. An attacker can supply '../' sequences or absolute paths to access arbitrary files.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Validate the joined path with os.path.realpath() and verify it starts with the intended base directory: resolved = os.path.realpath(os.path.join(base, user_input)); assert resolved.startswith(os.path.realpath(base)).",
					CWEID:         "CWE-22",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"python", "path-traversal", "os.path.join"},
				})
			}
		}
	}

	return findings
}

// --- PY-003: Jinja2 Autoescape Disabled ---

type Jinja2AutoescapeDisabled struct{}

func (r *Jinja2AutoescapeDisabled) ID() string                      { return "BATOU-PY-003" }
func (r *Jinja2AutoescapeDisabled) Name() string                    { return "Jinja2AutoescapeDisabled" }
func (r *Jinja2AutoescapeDisabled) Description() string             { return "Detects Jinja2 Environment created with autoescape disabled, enabling XSS." }
func (r *Jinja2AutoescapeDisabled) DefaultSeverity() rules.Severity { return rules.High }
func (r *Jinja2AutoescapeDisabled) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *Jinja2AutoescapeDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		// Explicit autoescape=False
		if loc := jinja2EnvAutoescapeFalse.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Jinja2 Environment with autoescape explicitly disabled",
				Description:   "The Jinja2 Environment is created with autoescape=False. All template variables will be rendered without HTML escaping, making the application vulnerable to cross-site scripting (XSS) if any user input is rendered in templates.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Set autoescape=True or use select_autoescape(): Environment(autoescape=select_autoescape(['html', 'xml'])).",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "jinja2", "xss", "autoescape"},
			})
			continue
		}

		// Environment without autoescape (default is False in Jinja2)
		if jinja2EnvNoAutoescape.MatchString(line) && strings.Contains(line, "jinja2") {
			context := surroundingContext(lines, i, 2)
			if !jinja2AutoescapeTrue.MatchString(context) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Medium,
					SeverityLabel: rules.Medium.String(),
					Title:         "Jinja2 Environment without explicit autoescape (defaults to False)",
					Description:   "The Jinja2 Environment is created without setting autoescape. Jinja2 defaults to autoescape=False, which means template variables are not HTML-escaped. This is a common source of XSS vulnerabilities.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Explicitly set autoescape=True or use select_autoescape(): Environment(autoescape=select_autoescape()).",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"python", "jinja2", "xss", "autoescape"},
				})
			}
		}
	}

	return findings
}

// --- PY-004: Unsafe YAML Load ---

type UnsafeYAMLLoad struct{}

func (r *UnsafeYAMLLoad) ID() string                      { return "BATOU-PY-004" }
func (r *UnsafeYAMLLoad) Name() string                    { return "UnsafeYAMLLoad" }
func (r *UnsafeYAMLLoad) Description() string             { return "Detects yaml.load() without SafeLoader, enabling arbitrary code execution." }
func (r *UnsafeYAMLLoad) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UnsafeYAMLLoad) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *UnsafeYAMLLoad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if loc := yamlUnsafeLoad.FindString(line); loc != "" {
			// Check if SafeLoader is specified on this line or the next
			context := surroundingContext(lines, i, 1)
			if yamlSafeLoader.MatchString(context) {
				continue
			}

			severity := r.DefaultSeverity()
			title := "yaml.load() without SafeLoader allows arbitrary code execution"
			if strings.Contains(loc, "unsafe_load") {
				title = "yaml.unsafe_load() explicitly enables arbitrary code execution"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				SeverityLabel: severity.String(),
				Title:         title,
				Description:   "yaml.load() without Loader=SafeLoader uses the default FullLoader (or the old Loader in older PyYAML), which can execute arbitrary Python objects via YAML tags like !!python/object/apply:os.system. This is a well-known remote code execution vector.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use yaml.safe_load() or pass Loader=yaml.SafeLoader: yaml.load(data, Loader=yaml.SafeLoader).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "yaml", "deserialization", "rce"},
			})
		}
	}

	return findings
}

// --- PY-005: tempfile.mktemp Race Condition ---

type TempfileMktemp struct{}

func (r *TempfileMktemp) ID() string                      { return "BATOU-PY-005" }
func (r *TempfileMktemp) Name() string                    { return "TempfileMktemp" }
func (r *TempfileMktemp) Description() string             { return "Detects use of deprecated tempfile.mktemp() which has a TOCTOU race condition." }
func (r *TempfileMktemp) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TempfileMktemp) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *TempfileMktemp) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if loc := tempfileMktemp.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "tempfile.mktemp() has a TOCTOU race condition",
				Description:   "tempfile.mktemp() is deprecated because it has a time-of-check to time-of-use (TOCTOU) race condition. Between the time the filename is generated and the file is created, an attacker could create a symlink at that path, leading to file overwrite or information disclosure.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use tempfile.mkstemp() for files or tempfile.mkdtemp() for directories, which atomically create the file/directory. Better yet, use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() context managers.",
				CWEID:         "CWE-377",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "tempfile", "race-condition", "toctou"},
			})
		}
	}

	return findings
}

// --- PY-006: Assert for Security Checks ---

type AssertSecurity struct{}

func (r *AssertSecurity) ID() string                      { return "BATOU-PY-006" }
func (r *AssertSecurity) Name() string                    { return "AssertSecurity" }
func (r *AssertSecurity) Description() string             { return "Detects use of Python assert statements for security checks, which are removed with -O flag." }
func (r *AssertSecurity) DefaultSeverity() rules.Severity { return rules.High }
func (r *AssertSecurity) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *AssertSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		if loc := assertSecurity.FindString(line); loc != "" {
			matched = loc
		} else if loc := assertCompare.FindString(line); loc != "" {
			matched = loc
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Security check uses assert statement (removed with python -O)",
				Description:   "Assert statements are removed when Python runs with the -O (optimize) flag. Using assert for authentication, authorization, or input validation means these checks silently disappear in optimized mode, bypassing all security controls.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Replace assert with an explicit if check and raise an appropriate exception: if not user.is_authenticated: raise PermissionError('Authentication required').",
				CWEID:         "CWE-617",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "assert", "security-check", "authorization"},
			})
		}
	}

	return findings
}

// --- PY-007: Unsafe Deserialization ---

type UnsafeDeserialization struct{}

func (r *UnsafeDeserialization) ID() string                      { return "BATOU-PY-007" }
func (r *UnsafeDeserialization) Name() string                    { return "UnsafeDeserialization" }
func (r *UnsafeDeserialization) Description() string             { return "Detects pickle/dill/cloudpickle/shelve/marshal deserialization with user-controlled data." }
func (r *UnsafeDeserialization) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UnsafeDeserialization) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *UnsafeDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag when there's evidence of user/network input
	hasNetworkInput := containsUserInputSource(ctx.Content) ||
		strings.Contains(ctx.Content, "socket") ||
		strings.Contains(ctx.Content, "recv(") ||
		strings.Contains(ctx.Content, "urlopen") ||
		strings.Contains(ctx.Content, "redis") ||
		strings.Contains(ctx.Content, "celery") ||
		strings.Contains(ctx.Content, "kombu")

	if !hasNetworkInput {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if loc := pickleLoadUserInput.FindString(line); loc != "" {
			lib := "pickle"
			if strings.Contains(loc, "dill") {
				lib = "dill"
			} else if strings.Contains(loc, "cloudpickle") {
				lib = "cloudpickle"
			} else if strings.Contains(loc, "shelve") {
				lib = "shelve"
			} else if strings.Contains(loc, "marshal") {
				lib = "marshal"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe " + lib + " deserialization with network/user input",
				Description:   lib + " deserialization of untrusted data allows arbitrary code execution. An attacker can craft a " + lib + " payload that executes arbitrary Python code, including system commands, on deserialization.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Never deserialize untrusted data with " + lib + ". Use JSON, MessagePack, or Protocol Buffers for data exchange. If " + lib + " is required, implement HMAC signing to verify data integrity before deserializing.",
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

// --- PY-008: Timing Attack on Secret Comparison ---

type TimingAttack struct{}

func (r *TimingAttack) ID() string                      { return "BATOU-PY-008" }
func (r *TimingAttack) Name() string                    { return "TimingAttack" }
func (r *TimingAttack) Description() string             { return "Detects direct comparison of secrets/tokens instead of constant-time comparison." }
func (r *TimingAttack) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TimingAttack) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *TimingAttack) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// If file already uses hmac.compare_digest, skip (developer is aware)
	if hmacCompareDigest.MatchString(ctx.Content) || secretsCompare.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if loc := directTokenCompare.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Secret comparison vulnerable to timing attack",
				Description:   "Direct string comparison (== or !=) of secrets, tokens, or hashes is vulnerable to timing attacks. The comparison short-circuits on the first different byte, leaking information about how many bytes match.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use hmac.compare_digest(a, b) or secrets.compare_digest(a, b) for constant-time comparison of secrets.",
				CWEID:         "CWE-208",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "timing-attack", "secret-comparison"},
			})
		}
	}

	return findings
}

// --- PY-009: Django Raw SQL Injection ---

type DjangoRawSQL struct{}

func (r *DjangoRawSQL) ID() string                      { return "BATOU-PY-009" }
func (r *DjangoRawSQL) Name() string                    { return "DjangoRawSQL" }
func (r *DjangoRawSQL) Description() string             { return "Detects Django .raw(), .extra(), RawSQL() with string interpolation enabling SQL injection." }
func (r *DjangoRawSQL) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DjangoRawSQL) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *DjangoRawSQL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := djangoRawSQL.FindString(line); loc != "" {
			matched = loc
			desc = "Django .raw() with string interpolation"
		} else if loc := djangoExtra.FindString(line); loc != "" {
			matched = loc
			desc = "Django .extra() (deprecated and unsafe)"
		} else if loc := djangoRawSQLExpr.FindString(line); loc != "" {
			matched = loc
			desc = "Django RawSQL() expression with string interpolation"
		} else if djangoCursorExec.MatchString(line) && djangoConnection.MatchString(ctx.Content) {
			matched = djangoCursorExec.FindString(line)
			desc = "Django cursor.execute() with string interpolation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQL injection via " + desc,
				Description:   desc + " allows SQL injection when user input is interpolated into the query string. Attackers can modify query logic, extract sensitive data, or execute administrative operations.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries: Model.objects.raw('SELECT * FROM t WHERE id = %s', [user_id]) or the Django ORM: Model.objects.filter(id=user_id). Avoid .extra() entirely (deprecated in Django 4.0).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "django", "sql-injection", "raw-sql"},
			})
		}
	}

	return findings
}

// --- PY-010: Flask Hardcoded Secret Key ---

type FlaskHardcodedSecret struct{}

func (r *FlaskHardcodedSecret) ID() string                      { return "BATOU-PY-010" }
func (r *FlaskHardcodedSecret) Name() string                    { return "FlaskHardcodedSecret" }
func (r *FlaskHardcodedSecret) Description() string             { return "Detects Flask/Django SECRET_KEY hardcoded as a string literal instead of loaded from environment." }
func (r *FlaskHardcodedSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *FlaskHardcodedSecret) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *FlaskHardcodedSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if loc := flaskSecretHardcoded.FindString(line); loc != "" {
			// Skip if it's clearly an env-based approach
			if flaskSecretEnv.MatchString(line) {
				continue
			}
			// Skip example/placeholder values
			if strings.Contains(line, "change-me") || strings.Contains(line, "CHANGE_ME") ||
				strings.Contains(line, "your-secret") || strings.Contains(line, "TODO") {
				// Still flag, but lower confidence
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SECRET_KEY hardcoded as string literal",
				Description:   "The SECRET_KEY is hardcoded in the source code. This key is used for signing session cookies, CSRF tokens, and other security-sensitive operations. Anyone with access to the source code can forge sessions and bypass CSRF protection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Load SECRET_KEY from environment: SECRET_KEY = os.environ['SECRET_KEY'] or use python-decouple/django-environ. Generate with: python -c 'import secrets; print(secrets.token_hex(32))'.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "flask", "django", "secret-key", "hardcoded"},
			})
		}
	}

	return findings
}

// --- PY-011: TLS Verification Disabled ---

type TLSVerificationDisabled struct{}

func (r *TLSVerificationDisabled) ID() string                      { return "BATOU-PY-011" }
func (r *TLSVerificationDisabled) Name() string                    { return "TLSVerificationDisabled" }
func (r *TLSVerificationDisabled) Description() string             { return "Detects disabled TLS certificate verification in requests, httpx, aiohttp, and urllib3." }
func (r *TLSVerificationDisabled) DefaultSeverity() rules.Severity { return rules.High }
func (r *TLSVerificationDisabled) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *TLSVerificationDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := requestsVerifyFalse.FindString(line); loc != "" {
			matched = loc
			desc = "requests library with verify=False"
		} else if loc := urllib3DisableWarnings.FindString(line); loc != "" {
			matched = loc
			desc = "urllib3 InsecureRequestWarning suppressed"
		} else if loc := urllib3NoVerify.FindString(line); loc != "" {
			matched = loc
			desc = "urllib3 with CERT_NONE"
		} else if loc := sslNoVerify.FindString(line); loc != "" {
			matched = loc
			desc = "ssl._create_unverified_context()"
		} else if loc := httpxVerifyFalse.FindString(line); loc != "" {
			matched = loc
			desc = "httpx client with verify=False"
		} else if loc := aiohttpNoVerify.FindString(line); loc != "" {
			matched = loc
			desc = "aiohttp with SSL verification disabled"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "TLS certificate verification disabled: " + desc,
				Description:   "Disabling TLS certificate verification (" + desc + ") makes the connection vulnerable to man-in-the-middle attacks. An attacker on the network can intercept, read, and modify all HTTPS traffic.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove verify=False and fix the underlying certificate issue. For self-signed certs, pass the CA bundle: verify='/path/to/ca-bundle.crt'. For development, use mkcert to create locally-trusted certificates.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "tls", "ssl", "certificate-verification"},
			})
		}
	}

	return findings
}

// --- PY-012: ReDoS via User-Controlled Regex ---

type ReDoS struct{}

func (r *ReDoS) ID() string                      { return "BATOU-PY-012" }
func (r *ReDoS) Name() string                    { return "ReDoS" }
func (r *ReDoS) Description() string             { return "Detects re.compile/match/search with user-controlled patterns enabling Regular Expression Denial of Service." }
func (r *ReDoS) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReDoS) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *ReDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag when user input sources are present
	if !containsUserInputSource(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if reCompileUserInput.MatchString(line) {
			// Check if user-controlled variable is passed as the pattern
			context := surroundingContext(lines, i, 3)
			if containsUserVariable(context) && !strings.Contains(context, "re.escape") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "User-controlled regex pattern enables ReDoS",
					Description:   "A user-controlled string is used as a regex pattern. Malicious patterns with nested quantifiers (e.g., (a+)+) cause catastrophic backtracking, consuming CPU for minutes or hours on crafted input strings. This is a Regular Expression Denial of Service (ReDoS) vulnerability.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Sanitize user input with re.escape() before using it in regex patterns: re.compile(re.escape(user_input)). Alternatively, use a timeout with the regex module (pip install regex) or validate the pattern complexity before compilation.",
					CWEID:         "CWE-1333",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"python", "regex", "redos", "denial-of-service"},
				})
			}
		}
	}

	return findings
}

// --- PY-013: Unsafe Archive Extraction ---

type UnsafeArchiveExtraction struct{}

func (r *UnsafeArchiveExtraction) ID() string                      { return "BATOU-PY-013" }
func (r *UnsafeArchiveExtraction) Name() string                    { return "UnsafeArchiveExtraction" }
func (r *UnsafeArchiveExtraction) Description() string             { return "Detects tarfile/zipfile extractall() without path validation (CVE-2007-4559)." }
func (r *UnsafeArchiveExtraction) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeArchiveExtraction) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *UnsafeArchiveExtraction) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		if tarExtractAll.MatchString(line) {
			context := surroundingContext(lines, i, 3)
			// Skip if filter= or members= is used (Python 3.12+ or manual filtering)
			if tarExtractFilter.MatchString(context) || tarExtractMembers.MatchString(context) {
				continue
			}

			desc := "tarfile.extractall()"
			if strings.Contains(line, "ZipFile") || strings.Contains(ctx.Content, "zipfile") {
				desc = "zipfile.extractall()"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe " + desc + " without path validation (CVE-2007-4559)",
				Description:   desc + " extracts all members without validating their paths. A malicious archive can contain entries with absolute paths or '../' sequences that write files outside the target directory (zip slip / tar slip).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "For tarfile (Python 3.12+): use extractall(filter='data'). For older Python: validate each member's path before extraction. For zipfile: check that resolved paths stay within the target directory.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "tarfile", "zipfile", "zip-slip", "path-traversal"},
			})
		}
	}

	return findings
}

// --- PY-014: Logging with String Formatting ---

type LoggingInjection struct{}

func (r *LoggingInjection) ID() string                      { return "BATOU-PY-014" }
func (r *LoggingInjection) Name() string                    { return "LoggingInjection" }
func (r *LoggingInjection) Description() string             { return "Detects f-string/.format()/% formatting in logging calls instead of lazy % formatting." }
func (r *LoggingInjection) DefaultSeverity() rules.Severity { return rules.Low }
func (r *LoggingInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *LoggingInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := loggingFString.FindString(line); loc != "" {
			matched = loc
			desc = "f-string in logging call"
		} else if loc := loggingFormat.FindString(line); loc != "" {
			matched = loc
			desc = ".format() in logging call"
		} else if loc := loggingPercent.FindString(line); loc != "" {
			matched = loc
			desc = "%-formatting in logging call"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Logging uses eager string formatting (" + desc + ")",
				Description:   "Using f-strings, .format(), or % formatting in logging calls eagerly evaluates the string even when the log level is disabled. This wastes CPU and, more critically, if the format string includes user input, it may enable log injection or log forging attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use lazy %-formatting built into the logging module: logger.info('User %s logged in', username) instead of logger.info(f'User {username} logged in'). This defers string formatting until the message is actually emitted.",
				CWEID:         "CWE-117",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "logging", "log-injection", "performance"},
			})
		}
	}

	return findings
}

// --- PY-015: JWT Decode Without Verification ---

type JWTNoVerification struct{}

func (r *JWTNoVerification) ID() string                      { return "BATOU-PY-015" }
func (r *JWTNoVerification) Name() string                    { return "JWTNoVerification" }
func (r *JWTNoVerification) Description() string             { return "Detects PyJWT jwt.decode() with signature verification disabled or algorithm=none." }
func (r *JWTNoVerification) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JWTNoVerification) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *JWTNoVerification) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := jwtDecodeNoVerify.FindString(line); loc != "" {
			matched = loc
			desc = "jwt.decode() with signature verification disabled"
		} else if loc := jwtDecodeAlgNone.FindString(line); loc != "" {
			matched = loc
			desc = "jwt.decode() with algorithm='none' (no signature)"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JWT token accepted without signature verification",
				Description:   desc + " allows an attacker to forge arbitrary JWT tokens. Without verification, any claims (user ID, roles, permissions) in the token can be fabricated, leading to complete authentication bypass.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256']). Never use algorithms=['none'] or disable verification in production. Explicitly specify allowed algorithms to prevent algorithm confusion attacks.",
				CWEID:         "CWE-347",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "jwt", "authentication", "signature-bypass"},
			})
		}
	}

	return findings
}

// --- PY-016: Debugger in Production ---

type DebuggerInProduction struct{}

func (r *DebuggerInProduction) ID() string                      { return "BATOU-PY-016" }
func (r *DebuggerInProduction) Name() string                    { return "DebuggerInProduction" }
func (r *DebuggerInProduction) Description() string             { return "Detects Werkzeug debugger, Flask debug mode, and debug toolbar enabled in application code." }
func (r *DebuggerInProduction) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DebuggerInProduction) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *DebuggerInProduction) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string
		severity := r.DefaultSeverity()

		if loc := werkzeugDebugger.FindString(line); loc != "" {
			matched = loc
			desc = "Werkzeug debugger enabled (use_debugger=True)"
			severity = rules.Critical
		} else if loc := flaskDebugRun.FindString(line); loc != "" {
			matched = loc
			desc = "Flask app.run(debug=True)"
			severity = rules.High
		} else if loc := debugToolbar.FindString(line); loc != "" {
			matched = loc
			desc = "Flask-DebugToolbar enabled"
			severity = rules.Medium
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				SeverityLabel: severity.String(),
				Title:         desc + " may expose interactive debugger in production",
				Description:   "The Werkzeug debugger provides an interactive Python console in the browser that allows executing arbitrary code on the server. If exposed in production, anyone can run system commands, read files, and take full control of the server. Even with a PIN, this is critical.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never enable the debugger in production. Use environment variables to control debug mode: app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'). Use a WSGI server like gunicorn for production.",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "flask", "werkzeug", "debugger", "rce"},
			})
		}
	}

	return findings
}

// --- PY-017: FastAPI Missing Input Validation ---

type FastAPIMissingValidation struct{}

func (r *FastAPIMissingValidation) ID() string                      { return "BATOU-PY-017" }
func (r *FastAPIMissingValidation) Name() string                    { return "FastAPIMissingValidation" }
func (r *FastAPIMissingValidation) Description() string             { return "Detects FastAPI endpoints accepting raw user input without Pydantic validation or Query/Path constraints." }
func (r *FastAPIMissingValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPIMissingValidation) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *FastAPIMissingValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan FastAPI files
	if !strings.Contains(ctx.Content, "fastapi") && !strings.Contains(ctx.Content, "FastAPI") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := fastapiQueryParam.FindString(line); loc != "" {
			matched = loc
			desc = "FastAPI Query/Header/Cookie/Path parameter without validation constraints"
		} else if loc := fastapiRawBody.FindString(line); loc != "" {
			matched = loc
			desc = "FastAPI endpoint reads raw request body without Pydantic model validation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         desc,
				Description:   "FastAPI supports rich input validation via Pydantic models and parameter constraints (min_length, max_length, regex, ge, le). Accepting unconstrained input bypasses this validation, potentially allowing injection attacks or unexpected data processing.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Add validation constraints: Query(min_length=1, max_length=100, regex='^[a-zA-Z0-9]+$'). For request bodies, use Pydantic models with field validators instead of reading raw JSON.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "fastapi", "input-validation", "pydantic"},
			})
		}
	}

	return findings
}

// --- PY-018: Asyncio Subprocess Shell Injection ---

type AsyncioShellInjection struct{}

func (r *AsyncioShellInjection) ID() string                      { return "BATOU-PY-018" }
func (r *AsyncioShellInjection) Name() string                    { return "AsyncioShellInjection" }
func (r *AsyncioShellInjection) Description() string             { return "Detects asyncio.create_subprocess_shell with potentially user-controlled commands." }
func (r *AsyncioShellInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *AsyncioShellInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *AsyncioShellInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPyComment(trimmed) {
			continue
		}

		var matched string
		var desc string
		confidence := "medium"

		if loc := asyncioShellConcat.FindString(line); loc != "" {
			matched = loc
			desc = "asyncio.create_subprocess_shell with dynamic command"
			confidence = "high"
		} else if loc := asyncioShellTrue.FindString(line); loc != "" {
			matched = loc
			desc = "asyncio.create_subprocess_shell always invokes the shell"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Shell injection via " + desc,
				Description:   "asyncio.create_subprocess_shell() always invokes the system shell to parse the command string. If any part of the command includes user input, an attacker can inject shell metacharacters to execute arbitrary commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use asyncio.create_subprocess_exec() instead, which takes arguments as a list without shell interpretation: await asyncio.create_subprocess_exec('cmd', arg1, arg2).",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"python", "asyncio", "shell-injection", "command-injection"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func isPyComment(line string) bool {
	return strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "\"\"\"") ||
		strings.HasPrefix(line, "'''")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func surroundingContext(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func containsUserInputSource(content string) bool {
	return strings.Contains(content, "request.") ||
		strings.Contains(content, "flask.request") ||
		strings.Contains(content, "request.GET") ||
		strings.Contains(content, "request.POST") ||
		strings.Contains(content, "request.args") ||
		strings.Contains(content, "request.form") ||
		strings.Contains(content, "request.json") ||
		strings.Contains(content, "request.data") ||
		strings.Contains(content, "request.files") ||
		strings.Contains(content, "request.query_params") ||
		strings.Contains(content, "sys.argv") ||
		strings.Contains(content, "input(") ||
		strings.Contains(content, "raw_input(") ||
		strings.Contains(content, "getattr(request") ||
		strings.Contains(content, "request.headers") ||
		strings.Contains(content, "request.cookies") ||
		strings.Contains(content, "call.receive") ||
		strings.Contains(content, "Query(") ||
		strings.Contains(content, "Path(") ||
		strings.Contains(content, "Header(") ||
		strings.Contains(content, "Body(")
}

func containsUserVariable(context string) bool {
	return strings.Contains(context, "request") ||
		strings.Contains(context, "user_input") ||
		strings.Contains(context, "user_data") ||
		strings.Contains(context, "filename") ||
		strings.Contains(context, "file_name") ||
		strings.Contains(context, "file_path") ||
		strings.Contains(context, "path") ||
		strings.Contains(context, "query") ||
		strings.Contains(context, "param") ||
		strings.Contains(context, "args") ||
		strings.Contains(context, "input") ||
		strings.Contains(context, "payload") ||
		strings.Contains(context, "pattern") ||
		strings.Contains(context, "search") ||
		strings.Contains(context, "kwargs")
}
