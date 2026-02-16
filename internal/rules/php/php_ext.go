package php

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Extension patterns for PHP-013 through PHP-024
// ---------------------------------------------------------------------------

// PHP-013: Type juggling in authentication (== vs ===)
var (
	reAuthLooseCompare = regexp.MustCompile(`if\s*\(\s*\$\w+\s*==\s*\$(?:password|token|hash|secret|stored|expected|correct|valid|db)`)
	reAuthLooseRev     = regexp.MustCompile(`if\s*\(\s*\$(?:password|token|hash|secret|stored|expected|correct|valid|db)\w*\s*==\s*\$`)
	rePasswordVerify   = regexp.MustCompile(`password_verify\s*\(`)
	reHashEquals       = regexp.MustCompile(`hash_equals\s*\(`)
)

// PHP-014: extract() with user input
var (
	reExtractGet     = regexp.MustCompile(`\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)`)
	reExtractVar     = regexp.MustCompile(`\bextract\s*\(\s*\$(?:data|input|params|request|body|payload|args|fields)`)
	reExtractExtrSkip = regexp.MustCompile(`\bextract\s*\([^,]+,\s*EXTR_(?:SKIP|PREFIX_ALL|IF_EXISTS)`)
)

// PHP-015: preg_replace with /e modifier
var (
	rePregReplaceE  = regexp.MustCompile(`\bpreg_replace\s*\(\s*["']/[^/]*/[^"']*e[^"']*["']`)
	rePregReplaceEVar = regexp.MustCompile(`\bpreg_replace\s*\(\s*\$[^,]*,\s*\$`)
)

// PHP-016: register_globals enabled
var (
	reRegisterGlobals   = regexp.MustCompile(`(?i)register_globals\s*=\s*(?:on|1|true)`)
	reIniSetRegGlobals  = regexp.MustCompile(`\bini_set\s*\(\s*["']register_globals["']\s*,\s*(?:1|'1'|"1"|true|'on'|"on")`)
)

// PHP-017: file_put_contents with user path
var (
	reFilePutUser     = regexp.MustCompile(`\bfile_put_contents\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|path|file|name|filename|dest|target|dir|output)`)
	reFilePutConcat   = regexp.MustCompile(`\bfile_put_contents\s*\(\s*["'][^"']*["']\s*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|path|file|name|filename)`)
	reFilePutBasename = regexp.MustCompile(`basename\s*\(`)
)

// PHP-018: include/require with user input (extended LFI/RFI)
var (
	reIncludeVarExt   = regexp.MustCompile(`\b(?:include|include_once|require|require_once)\s*\(?\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[`)
	reIncludeConcat2  = regexp.MustCompile(`\b(?:include|include_once|require|require_once)\s*\(?\s*(?:\$\w+\s*\.\s*\$_(?:GET|POST|REQUEST))`)
)

// PHP-019: assert() with user input
var (
	reAssertUser     = regexp.MustCompile(`\bassert\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input|param|data|cmd|code|expr)`)
	reAssertConcat   = regexp.MustCompile(`\bassert\s*\(\s*["'][^"']*["']\s*\.\s*\$`)
)

// PHP-020: create_function with user input
var (
	reCreateFuncUser  = regexp.MustCompile(`\bcreate_function\s*\(\s*["'][^"']*["']\s*,\s*\$`)
	reCreateFuncConcat = regexp.MustCompile(`\bcreate_function\s*\(\s*["'][^"']*["']\s*,\s*["'][^"']*["']\s*\.\s*\$`)
)

// PHP-021: mail() header injection (extended)
var (
	reMailAdditionalHeaders = regexp.MustCompile(`\bmail\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|headers|from|subject|to)`)
	reMailFifthParam        = regexp.MustCompile(`\bmail\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)`)
)

// PHP-022: session.use_strict_mode disabled
var (
	reSessionStrictMode    = regexp.MustCompile(`(?i)session\.use_strict_mode\s*=\s*(?:0|off|false)`)
	reIniSetStrictMode     = regexp.MustCompile(`\bini_set\s*\(\s*["']session\.use_strict_mode["']\s*,\s*(?:0|'0'|"0"|false|'false'|"false")`)
)

// PHP-023: display_errors On in production (extended)
var (
	reDisplayErrorsOn    = regexp.MustCompile(`(?i)\bdisplay_errors\b.*\b(?:On|1|true)\b`)
	reErrorReporting     = regexp.MustCompile(`\berror_reporting\s*\(\s*E_ALL\s*\)`)
	reDisplayStartupErr  = regexp.MustCompile(`(?i)display_startup_errors\s*=\s*(?:1|on|true)`)
)

// PHP-024: mysqli_real_escape_string misuse
var (
	reMysqliEscape     = regexp.MustCompile(`\bmysqli?_real_escape_string\s*\(`)
	reMysqliEscapeLike = regexp.MustCompile(`LIKE\s*['"]%`)
	reMysqliSetCharset = regexp.MustCompile(`\bmysqli?_set_charset\s*\(|SET\s+NAMES\b`)
	reMysqliPrepare    = regexp.MustCompile(`\b(?:prepare|mysqli_prepare)\s*\(`)
)

func init() {
	rules.Register(&PHPAuthTypeJuggling{})
	rules.Register(&PHPExtractUser{})
	rules.Register(&PHPPregReplaceE{})
	rules.Register(&PHPRegisterGlobals{})
	rules.Register(&PHPFilePutUser{})
	rules.Register(&PHPIncludeExtLFI{})
	rules.Register(&PHPAssertUser{})
	rules.Register(&PHPCreateFunction{})
	rules.Register(&PHPMailHeaderExt{})
	rules.Register(&PHPSessionStrictMode{})
	rules.Register(&PHPDisplayErrorsExt{})
	rules.Register(&PHPMysqliEscapeMisuse{})
}

// ---------------------------------------------------------------------------
// PHP-013: PHP type juggling in authentication
// ---------------------------------------------------------------------------

type PHPAuthTypeJuggling struct{}

func (r *PHPAuthTypeJuggling) ID() string                      { return "BATOU-PHP-013" }
func (r *PHPAuthTypeJuggling) Name() string                    { return "PHPAuthTypeJuggling" }
func (r *PHPAuthTypeJuggling) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPAuthTypeJuggling) Description() string {
	return "Detects loose comparison (==) in authentication contexts where type juggling can bypass password/token checks."
}
func (r *PHPAuthTypeJuggling) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPAuthTypeJuggling) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if rePasswordVerify.MatchString(ctx.Content) || reHashEquals.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reAuthLooseCompare.FindString(line); m != "" {
			matched = m
		} else if m := reAuthLooseRev.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP type juggling in authentication comparison (== instead of ===)",
				Description:   "Using == to compare passwords, tokens, or hashes is vulnerable to PHP type juggling. Strings like '0e123' and '0e456' compare as equal (both cast to float 0). An attacker can craft hashes that bypass authentication.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use hash_equals() for comparing hashes, password_verify() for passwords, or strict comparison (===) for tokens. Never use == for security comparisons.",
				CWEID:         "CWE-843",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "type-juggling", "authentication", "bypass"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-014: extract() with user input
// ---------------------------------------------------------------------------

type PHPExtractUser struct{}

func (r *PHPExtractUser) ID() string                      { return "BATOU-PHP-014" }
func (r *PHPExtractUser) Name() string                    { return "PHPExtractUser" }
func (r *PHPExtractUser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPExtractUser) Description() string {
	return "Detects extract() called with user-controlled superglobals, enabling variable overwrite attacks."
}
func (r *PHPExtractUser) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPExtractUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "extract") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reExtractExtrSkip.MatchString(line) {
			continue
		}
		var matched string
		if m := reExtractGet.FindString(line); m != "" {
			matched = m
		} else if m := reExtractVar.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "extract() with user-controlled input (variable overwrite)",
				Description:   "extract() imports array keys as variables. When called with $_GET/$_POST/$_REQUEST, an attacker can overwrite ANY variable in scope including $isAdmin, $isAuthenticated, database credentials, or file paths.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never use extract() with user input. Access values directly: $name = $_POST['name']. If extract is needed, use EXTR_SKIP flag and an allowlist: extract($data, EXTR_SKIP).",
				CWEID:         "CWE-621",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "extract", "variable-overwrite"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-015: preg_replace with /e modifier
// ---------------------------------------------------------------------------

type PHPPregReplaceE struct{}

func (r *PHPPregReplaceE) ID() string                      { return "BATOU-PHP-015" }
func (r *PHPPregReplaceE) Name() string                    { return "PHPPregReplaceE" }
func (r *PHPPregReplaceE) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPPregReplaceE) Description() string {
	return "Detects preg_replace() with the /e modifier which evaluates the replacement string as PHP code."
}
func (r *PHPPregReplaceE) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPPregReplaceE) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "preg_replace") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := rePregReplaceE.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "preg_replace with /e modifier (code execution)",
				Description:   "The /e modifier in preg_replace() evaluates the replacement string as PHP code using eval(). If the matched content is user-controlled, this enables arbitrary PHP code execution. Deprecated since PHP 5.5, removed in PHP 7.0.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use preg_replace_callback() instead: preg_replace_callback('/pattern/', function($matches) { return strtoupper($matches[1]); }, $input);",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "preg-replace", "eval", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-016: register_globals enabled
// ---------------------------------------------------------------------------

type PHPRegisterGlobals struct{}

func (r *PHPRegisterGlobals) ID() string                      { return "BATOU-PHP-016" }
func (r *PHPRegisterGlobals) Name() string                    { return "PHPRegisterGlobals" }
func (r *PHPRegisterGlobals) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPRegisterGlobals) Description() string {
	return "Detects register_globals enabled in configuration, which imports request variables into the global scope."
}
func (r *PHPRegisterGlobals) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPRegisterGlobals) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reRegisterGlobals.FindString(line); m != "" {
			matched = m
		} else if m := reIniSetRegGlobals.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "register_globals enabled (auto-import request variables)",
				Description:   "register_globals imports all GET/POST/COOKIE variables into the global scope, allowing attackers to overwrite any uninitialized variable. This enables authentication bypass, file inclusion, and other attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Disable register_globals (removed in PHP 5.4). Access variables explicitly via $_GET, $_POST, $_COOKIE. Initialize all variables before use.",
				CWEID:         "CWE-621",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "register-globals", "variable-overwrite"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-017: file_put_contents with user path
// ---------------------------------------------------------------------------

type PHPFilePutUser struct{}

func (r *PHPFilePutUser) ID() string                      { return "BATOU-PHP-017" }
func (r *PHPFilePutUser) Name() string                    { return "PHPFilePutUser" }
func (r *PHPFilePutUser) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPFilePutUser) Description() string {
	return "Detects file_put_contents() with user-controlled file path enabling arbitrary file write and path traversal."
}
func (r *PHPFilePutUser) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPFilePutUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "file_put_contents") {
		return nil
	}
	if reFilePutBasename.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reFilePutUser.FindString(line); m != "" {
			matched = m
		} else if m := reFilePutConcat.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "file_put_contents with user-controlled path (arbitrary file write)",
				Description:   "file_put_contents() with user-controlled path allows writing arbitrary files via path traversal (../../). An attacker can overwrite configuration files, upload web shells, or modify .htaccess for code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use basename() to strip directory components: file_put_contents($dir . '/' . basename($filename), $data). Validate the resolved path starts within the intended directory using realpath().",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "file-write", "path-traversal"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-018: include/require with user input (extended LFI/RFI)
// ---------------------------------------------------------------------------

type PHPIncludeExtLFI struct{}

func (r *PHPIncludeExtLFI) ID() string                      { return "BATOU-PHP-018" }
func (r *PHPIncludeExtLFI) Name() string                    { return "PHPIncludeExtLFI" }
func (r *PHPIncludeExtLFI) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPIncludeExtLFI) Description() string {
	return "Detects include/require with direct superglobal array access or concatenated user input (LFI/RFI)."
}
func (r *PHPIncludeExtLFI) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPIncludeExtLFI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reIncludeVarExt.FindString(line); m != "" {
			matched = m
		} else if m := reIncludeConcat2.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP include/require with superglobal input (LFI/RFI)",
				Description:   "include/require with $_GET/$_POST array access enables Local File Inclusion (reading /etc/passwd, session files, logs) and Remote File Inclusion (executing remote PHP code) if allow_url_include is enabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a whitelist: $allowed = ['home', 'about', 'contact']; if (in_array($page, $allowed)) include($page . '.php'). Disable allow_url_include. Use open_basedir restriction.",
				CWEID:         "CWE-98",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "lfi", "rfi", "include"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-019: assert() with user input
// ---------------------------------------------------------------------------

type PHPAssertUser struct{}

func (r *PHPAssertUser) ID() string                      { return "BATOU-PHP-019" }
func (r *PHPAssertUser) Name() string                    { return "PHPAssertUser" }
func (r *PHPAssertUser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPAssertUser) Description() string {
	return "Detects assert() with user-controlled input, which evaluates the argument as PHP code (before PHP 8.0)."
}
func (r *PHPAssertUser) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPAssertUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "assert") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reAssertUser.FindString(line); m != "" {
			matched = m
		} else if m := reAssertConcat.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "assert() with user input (code execution)",
				Description:   "PHP assert() with string argument evaluates it as PHP code (before PHP 8.0). Passing user-controlled input to assert() enables arbitrary code execution: assert('system(\"id\")') runs the system command.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to assert(). Use proper validation functions instead. In PHP 7.2+, set zend.assertions=-1 in production to disable assertions entirely.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "assert", "eval", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-020: create_function with user input
// ---------------------------------------------------------------------------

type PHPCreateFunction struct{}

func (r *PHPCreateFunction) ID() string                      { return "BATOU-PHP-020" }
func (r *PHPCreateFunction) Name() string                    { return "PHPCreateFunction" }
func (r *PHPCreateFunction) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPCreateFunction) Description() string {
	return "Detects create_function() with user-controlled body, which internally uses eval() for code execution."
}
func (r *PHPCreateFunction) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPCreateFunction) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "create_function") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reCreateFuncUser.FindString(line); m != "" {
			matched = m
		} else if m := reCreateFuncConcat.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "create_function() with user-controlled body (eval injection)",
				Description:   "create_function() uses eval() internally to create anonymous functions. User-controlled input in the function body enables arbitrary PHP code execution. Deprecated in PHP 7.2, removed in PHP 8.0.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Replace create_function() with closures (anonymous functions): $func = function($args) use ($captured) { ... }; Closures are safer and faster.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "create-function", "eval", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-021: mail() header injection (extended)
// ---------------------------------------------------------------------------

type PHPMailHeaderExt struct{}

func (r *PHPMailHeaderExt) ID() string                      { return "BATOU-PHP-021" }
func (r *PHPMailHeaderExt) Name() string                    { return "PHPMailHeaderExt" }
func (r *PHPMailHeaderExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPMailHeaderExt) Description() string {
	return "Detects mail() with user-controlled additional_headers or additional_parameters enabling header/sendmail injection."
}
func (r *PHPMailHeaderExt) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPMailHeaderExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "mail") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var detail string
		if m := reMailFifthParam.FindString(line); m != "" {
			matched = m
			detail = "mail() 5th parameter with user input (sendmail argument injection)"
		} else if m := reMailAdditionalHeaders.FindString(line); m != "" {
			matched = m
			detail = "mail() additional headers with user-controlled value"
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP mail() injection: " + detail,
				Description:   "User input in mail() headers allows injecting arbitrary SMTP headers via CRLF sequences. The 5th parameter passes arguments directly to sendmail, enabling -X (log to file) and -O (queue directory) injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use PHPMailer or SwiftMailer/Symfony Mailer. Strip \\r and \\n from all user input in headers. Never pass user input as the 5th argument to mail().",
				CWEID:         "CWE-93",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "mail", "header-injection", "sendmail"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-022: session.use_strict_mode disabled
// ---------------------------------------------------------------------------

type PHPSessionStrictMode struct{}

func (r *PHPSessionStrictMode) ID() string                      { return "BATOU-PHP-022" }
func (r *PHPSessionStrictMode) Name() string                    { return "PHPSessionStrictMode" }
func (r *PHPSessionStrictMode) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PHPSessionStrictMode) Description() string {
	return "Detects session.use_strict_mode disabled, allowing session fixation attacks with arbitrary session IDs."
}
func (r *PHPSessionStrictMode) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPSessionStrictMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reSessionStrictMode.FindString(line); m != "" {
			matched = m
		} else if m := reIniSetStrictMode.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "session.use_strict_mode disabled (session fixation risk)",
				Description:   "With use_strict_mode disabled, PHP accepts any session ID provided by the client, even ones that were never issued by the server. This enables session fixation attacks where an attacker pre-sets a victim's session ID.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Enable strict mode: ini_set('session.use_strict_mode', 1) or session.use_strict_mode = 1 in php.ini. Call session_regenerate_id(true) after successful authentication.",
				CWEID:         "CWE-384",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "session", "fixation", "strict-mode"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-023: display_errors On in production (extended)
// ---------------------------------------------------------------------------

type PHPDisplayErrorsExt struct{}

func (r *PHPDisplayErrorsExt) ID() string                      { return "BATOU-PHP-023" }
func (r *PHPDisplayErrorsExt) Name() string                    { return "PHPDisplayErrorsExt" }
func (r *PHPDisplayErrorsExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PHPDisplayErrorsExt) Description() string {
	return "Detects display_startup_errors enabled or error_reporting(E_ALL) without display_errors=Off, exposing stack traces."
}
func (r *PHPDisplayErrorsExt) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPDisplayErrorsExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var title string
		if m := reDisplayStartupErr.FindString(line); m != "" {
			matched = m
			title = "display_startup_errors enabled (information disclosure)"
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Enabling display_startup_errors shows PHP startup errors including extension loading failures, path information, and configuration details. Combined with error_reporting(E_ALL), this exposes sensitive internals.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Set display_startup_errors = Off and display_errors = Off in production. Use error_log = /var/log/php_errors.log to log errors server-side.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "display-errors", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PHP-024: mysqli_real_escape_string misuse (charset bypass)
// ---------------------------------------------------------------------------

type PHPMysqliEscapeMisuse struct{}

func (r *PHPMysqliEscapeMisuse) ID() string                      { return "BATOU-PHP-024" }
func (r *PHPMysqliEscapeMisuse) Name() string                    { return "PHPMysqliEscapeMisuse" }
func (r *PHPMysqliEscapeMisuse) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PHPMysqliEscapeMisuse) Description() string {
	return "Detects mysqli_real_escape_string usage without charset set, vulnerable to multibyte charset bypass (GBK/Shift-JIS)."
}
func (r *PHPMysqliEscapeMisuse) Languages() []rules.Language { return []rules.Language{rules.LangPHP} }

func (r *PHPMysqliEscapeMisuse) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reMysqliEscape.MatchString(ctx.Content) {
		return nil
	}
	if reMysqliPrepare.MatchString(ctx.Content) {
		return nil
	}
	hasCharset := reMysqliSetCharset.MatchString(ctx.Content)
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reMysqliEscape.MatchString(line) {
			confidence := "medium"
			desc := "mysqli_real_escape_string used instead of prepared statements"
			if !hasCharset {
				confidence = "high"
				desc = "mysqli_real_escape_string without explicit charset (multibyte bypass risk)"
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "mysqli_real_escape_string misuse: " + desc,
				Description:   "mysqli_real_escape_string without an explicit charset set via mysqli_set_charset() is vulnerable to multibyte charset bypass attacks (GBK, Shift-JIS). Even with charset set, it is less safe than prepared statements.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use prepared statements instead: $stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?'); $stmt->bind_param('i', $id). If escaping is unavoidable, call mysqli_set_charset('utf8mb4') first.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"php", "mysqli", "escape", "charset"},
			})
		}
	}
	return findings
}
