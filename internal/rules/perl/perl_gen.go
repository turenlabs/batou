package perl

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns (generated rules PL-019 through PL-028)
// ---------------------------------------------------------------------------

// PL-019: Two-argument open shell injection
var (
	reGenTwoArgOpen     = regexp.MustCompile(`open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*\$`)
	reGenTwoArgOpenMode = regexp.MustCompile(`open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*["'][<>]+["']`)
)

// PL-020: Storable::thaw on network data
var (
	reGenThaw       = regexp.MustCompile(`(?:Storable::)?thaw\s*\(`)
	reGenNetContext = regexp.MustCompile(`(?i)(?:socket|recv|receive|network|remote|accept|connect|IO::Socket|Net::)`)
)

// PL-021: CGI response splitting
var (
	reGenPrintCRLF = regexp.MustCompile(`print\s+["'].*\\r\\n.*\$[a-zA-Z_]`)
	reGenHeaderVar = regexp.MustCompile(`(?i)(?:print\s+.*(?:Location|Set-Cookie|Content-Type)\s*:\s*.*\$|header\s*\(.*\$)`)
)

// PL-022: DBI do() with interpolation
var (
	reGenDbiDoInterp  = regexp.MustCompile(`\$\w+->do\s*\(\s*"[^"]*\$[a-zA-Z_{][^"]*"`)
	reGenDbiDoConcat  = regexp.MustCompile(`\$\w+->do\s*\(\s*["'][^"']*["']\s*\.`)
)

// PL-023: require with variable
var reGenRequireVar = regexp.MustCompile(`\brequire\s+\$[a-zA-Z_]`)

// PL-024: Regex with user input ReDoS
var (
	reGenRegexUserVar  = regexp.MustCompile(`=~\s*(?:m\s*)?/[^/]*\$[a-zA-Z_]`)
	reGenQrUserVar     = regexp.MustCompile(`qr/[^/]*\$[a-zA-Z_]`)
)

// PL-025: Weak hash for passwords
var (
	reGenWeakDigest  = regexp.MustCompile(`(?:Digest::MD5|Digest::SHA1|Digest::SHA\b)`)
	reGenPasswdCtx   = regexp.MustCompile(`(?i)(?:password|passwd|pwd|credential)`)
)

// PL-026: MIME::Lite header injection
var (
	reGenMimeLite    = regexp.MustCompile(`MIME::Lite->new\s*\(`)
	reGenMimeHeader  = regexp.MustCompile(`(?:To|From|Subject|Cc|Bcc)\s*=>\s*\$`)
)

// PL-027: CGI::Cookie parse DoS
var reGenCGICookieParse = regexp.MustCompile(`CGI::Cookie->parse\s*\(`)

// PL-028: Taint mode disabled
var (
	reGenPerlShebang    = regexp.MustCompile(`^#!\s*/usr/bin/(?:env\s+)?perl`)
	reGenTaintFlag      = regexp.MustCompile(`-.*T`)
)

// ---------------------------------------------------------------------------
// PL-019: Two-Argument Open Shell Injection
// ---------------------------------------------------------------------------

type TwoArgOpen struct{}

func (r *TwoArgOpen) ID() string                      { return "BATOU-PL-019" }
func (r *TwoArgOpen) Name() string                    { return "PerlTwoArgOpen" }
func (r *TwoArgOpen) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *TwoArgOpen) Description() string {
	return "Detects Perl two-argument open() with a variable, which allows shell injection via pipe characters and special file modes."
}
func (r *TwoArgOpen) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *TwoArgOpen) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		if reGenTwoArgOpen.MatchString(line) && !reGenTwoArgOpenMode.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Two-argument open() with variable input",
				Description:   "Two-argument open(FH, $var) interprets the filename as a mode+path, allowing pipe injection (|cmd) and other shell attacks when $var is user-controlled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use three-argument open: open(my $fh, '<', $filename). This separates the mode from the path, preventing injection.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "open", "shell-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-020: Storable::thaw on Network Data
// ---------------------------------------------------------------------------

type StorableThawNetwork struct{}

func (r *StorableThawNetwork) ID() string                      { return "BATOU-PL-020" }
func (r *StorableThawNetwork) Name() string                    { return "PerlStorableThawNetwork" }
func (r *StorableThawNetwork) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *StorableThawNetwork) Description() string {
	return "Detects Storable::thaw() in code with network/socket context, enabling deserialization of arbitrary Perl objects from untrusted network data."
}
func (r *StorableThawNetwork) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *StorableThawNetwork) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenNetContext.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		if reGenThaw.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Storable::thaw on network data",
				Description:   "Storable::thaw deserializes arbitrary Perl data structures. When applied to data received from network sources, attackers can craft payloads that execute code during deserialization.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use JSON or CBOR for network serialization instead of Storable. If Storable is required, validate and authenticate the data source before deserialization.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "deserialization", "storable"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-021: CGI Response Splitting
// ---------------------------------------------------------------------------

type CGIResponseSplitting struct{}

func (r *CGIResponseSplitting) ID() string                      { return "BATOU-PL-021" }
func (r *CGIResponseSplitting) Name() string                    { return "PerlCGIResponseSplitting" }
func (r *CGIResponseSplitting) DefaultSeverity() rules.Severity { return rules.High }
func (r *CGIResponseSplitting) Description() string {
	return "Detects HTTP response splitting via CRLF injection in Perl CGI print statements with interpolated variables in header output."
}
func (r *CGIResponseSplitting) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *CGIResponseSplitting) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		var matched string
		if loc := reGenPrintCRLF.FindString(line); loc != "" {
			matched = loc
		} else if loc := reGenHeaderVar.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CGI response splitting via CRLF injection",
				Description:   "User-controlled variables in HTTP header output can inject CRLF sequences, allowing attackers to split responses, inject headers, or perform XSS.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Strip or reject CR/LF characters from user input before including in headers. Use CGI.pm header methods or a framework that handles header encoding safely.",
				CWEID:         "CWE-113",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "cgi", "response-splitting"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-022: DBI do() with Interpolation
// ---------------------------------------------------------------------------

type DBIDoInterpolation struct{}

func (r *DBIDoInterpolation) ID() string                      { return "BATOU-PL-022" }
func (r *DBIDoInterpolation) Name() string                    { return "PerlDBIDoInterpolation" }
func (r *DBIDoInterpolation) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DBIDoInterpolation) Description() string {
	return "Detects DBI do() calls with string interpolation or concatenation, enabling SQL injection."
}
func (r *DBIDoInterpolation) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *DBIDoInterpolation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		var matched string
		if loc := reGenDbiDoInterp.FindString(line); loc != "" {
			matched = loc
		} else if loc := reGenDbiDoConcat.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "DBI do() with variable interpolation",
				Description:   "The $dbh->do() call includes interpolated variables or string concatenation in the SQL query, enabling SQL injection attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use placeholders: $dbh->do(\"DELETE FROM users WHERE id = ?\", undef, $id). Never interpolate variables into SQL strings.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "sql-injection", "dbi"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-023: require with Variable
// ---------------------------------------------------------------------------

type RequireVariable struct{}

func (r *RequireVariable) ID() string                      { return "BATOU-PL-023" }
func (r *RequireVariable) Name() string                    { return "PerlRequireVariable" }
func (r *RequireVariable) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RequireVariable) Description() string {
	return "Detects require with a variable argument, which loads and executes arbitrary Perl modules at runtime, enabling code injection."
}
func (r *RequireVariable) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *RequireVariable) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		if reGenRequireVar.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "require with variable argument",
				Description:   "Using require with a variable loads and executes an arbitrary Perl module at runtime. If the variable is user-controlled, an attacker can load malicious code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use a whitelist of allowed modules: my %allowed = (Foo => 1, Bar => 1); require $mod if $allowed{$mod}. Never allow user input to directly control require.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "code-injection", "require"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-024: Regex with User Input ReDoS
// ---------------------------------------------------------------------------

type RegexUserInputReDoS struct{}

func (r *RegexUserInputReDoS) ID() string                      { return "BATOU-PL-024" }
func (r *RegexUserInputReDoS) Name() string                    { return "PerlRegexUserInputReDoS" }
func (r *RegexUserInputReDoS) DefaultSeverity() rules.Severity { return rules.High }
func (r *RegexUserInputReDoS) Description() string {
	return "Detects regex patterns containing interpolated user variables, which can cause ReDoS (Regular Expression Denial of Service) via crafted patterns."
}
func (r *RegexUserInputReDoS) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *RegexUserInputReDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		var matched string
		if loc := reGenRegexUserVar.FindString(line); loc != "" {
			matched = loc
		} else if loc := reGenQrUserVar.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regex with user-controlled variable",
				Description:   "User-controlled variables interpolated into regex patterns can cause ReDoS via catastrophic backtracking, or enable regex injection to alter match behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use quotemeta() or \\Q...\\E to escape user input: =~ /\\Q$user_input\\E/. If regex features are needed, validate the pattern or use a timeout.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "regex", "redos"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-025: Weak Hash for Passwords
// ---------------------------------------------------------------------------

type WeakHashPasswords struct{}

func (r *WeakHashPasswords) ID() string                      { return "BATOU-PL-025" }
func (r *WeakHashPasswords) Name() string                    { return "PerlWeakHashPasswords" }
func (r *WeakHashPasswords) DefaultSeverity() rules.Severity { return rules.High }
func (r *WeakHashPasswords) Description() string {
	return "Detects use of Digest::MD5 or Digest::SHA1 in code that handles passwords. These fast hashes are unsuitable for password storage."
}
func (r *WeakHashPasswords) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *WeakHashPasswords) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenPasswdCtx.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		if reGenWeakDigest.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Weak hash function in password context",
				Description:   "Digest::MD5 and Digest::SHA1 are fast cryptographic hashes unsuitable for password storage. They are vulnerable to brute-force, rainbow table, and length extension attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use Crypt::Argon2, Crypt::Bcrypt, or Authen::Passphrase for password hashing. These provide salting and configurable work factors.",
				CWEID:         "CWE-328",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "crypto", "password-hashing"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-026: MIME::Lite Header Injection
// ---------------------------------------------------------------------------

type MIMELiteHeaderInjection struct{}

func (r *MIMELiteHeaderInjection) ID() string                      { return "BATOU-PL-026" }
func (r *MIMELiteHeaderInjection) Name() string                    { return "PerlMIMELiteHeaderInjection" }
func (r *MIMELiteHeaderInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *MIMELiteHeaderInjection) Description() string {
	return "Detects MIME::Lite email creation with user-controlled variables in header fields, enabling email header injection."
}
func (r *MIMELiteHeaderInjection) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *MIMELiteHeaderInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		if reGenMimeLite.MatchString(line) || reGenMimeHeader.MatchString(line) {
			// Check surrounding context for variable headers
			ctx_text := surroundingContext(lines, i, 5)
			if reGenMimeHeader.MatchString(ctx_text) && reGenMimeLite.MatchString(ctx_text) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "MIME::Lite with user input in headers",
					Description:   "MIME::Lite email headers (To, From, Subject, Cc, Bcc) with user-controlled variables enable email header injection. Attackers can inject additional recipients or headers via CRLF sequences.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Validate and sanitize email addresses before use. Strip CR/LF characters from all header values. Use Email::Stuffer or Email::MIME with proper encoding.",
					CWEID:         "CWE-93",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"perl", "email", "header-injection"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-027: CGI::Cookie Parse DoS
// ---------------------------------------------------------------------------

type CGICookieParseDoS struct{}

func (r *CGICookieParseDoS) ID() string                      { return "BATOU-PL-027" }
func (r *CGICookieParseDoS) Name() string                    { return "PerlCGICookieParseDoS" }
func (r *CGICookieParseDoS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CGICookieParseDoS) Description() string {
	return "Detects CGI::Cookie->parse() which can be exploited with crafted cookie strings to cause excessive memory consumption or CPU usage."
}
func (r *CGICookieParseDoS) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *CGICookieParseDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}
		if reGenCGICookieParse.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CGI::Cookie->parse with untrusted input",
				Description:   "CGI::Cookie->parse() can consume excessive memory or CPU when processing crafted cookie strings with many delimiters or nested values.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Limit the size of cookie input before parsing. Consider using a more robust cookie parser like Cookie::Baker, or validate the Cookie header length.",
				CWEID:         "CWE-400",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"perl", "cgi", "dos"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// PL-028: Taint Mode Disabled
// ---------------------------------------------------------------------------

type TaintModeDisabled struct{}

func (r *TaintModeDisabled) ID() string                      { return "BATOU-PL-028" }
func (r *TaintModeDisabled) Name() string                    { return "PerlTaintModeDisabled" }
func (r *TaintModeDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TaintModeDisabled) Description() string {
	return "Detects Perl scripts with a shebang line that does not include the -T (taint mode) flag, which helps prevent use of untrusted data in dangerous operations."
}
func (r *TaintModeDisabled) Languages() []rules.Language { return []rules.Language{rules.LangPerl} }

func (r *TaintModeDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) && i > 0 {
			continue
		}
		if reGenPerlShebang.MatchString(line) && !reGenTaintFlag.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl script without taint mode (-T)",
				Description:   "The Perl shebang line does not include -T (taint mode). Taint mode marks all external input as tainted and prevents its use in system calls, file operations, and eval without explicit untainting.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Add -T to the shebang line: #!/usr/bin/perl -T. This enables taint checking which helps prevent injection attacks by tracking untrusted data.",
				CWEID:         "CWE-20",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"perl", "taint-mode", "input-validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&TwoArgOpen{})
	rules.Register(&StorableThawNetwork{})
	rules.Register(&CGIResponseSplitting{})
	rules.Register(&DBIDoInterpolation{})
	rules.Register(&RequireVariable{})
	rules.Register(&RegexUserInputReDoS{})
	rules.Register(&WeakHashPasswords{})
	rules.Register(&MIMELiteHeaderInjection{})
	rules.Register(&CGICookieParseDoS{})
	rules.Register(&TaintModeDisabled{})
}
