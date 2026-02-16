package perl

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Perl extension rules (BATOU-PL-011 .. BATOU-PL-018)
// ---------------------------------------------------------------------------

// PL-011: Two-argument open (command injection)
var (
	reTwoArgOpen      = regexp.MustCompile(`\bopen\s*\(\s*\$?\w+\s*,\s*\$`)
	reTwoArgOpenPipe  = regexp.MustCompile(`\bopen\s*\(\s*\$?\w+\s*,\s*["'][|>]`)
	reTwoArgOpenVar   = regexp.MustCompile(`\bopen\s*\(\s*\w+\s*,\s*"[^"]*\$[a-zA-Z_{]`)
)

// PL-012: Backtick/qx with variable interpolation
var (
	reBacktickVar     = regexp.MustCompile("`[^`]*\\$[a-zA-Z_{]")
	reQxVar           = regexp.MustCompile(`\bqx\s*[({/|][^)}\\/|]*\$[a-zA-Z_{]`)
	reQxBracket       = regexp.MustCompile(`\bqx\s*\[[^\]]*\$[a-zA-Z_{]`)
)

// PL-013: DBI query without placeholders
var (
	reDBIDoConcat      = regexp.MustCompile(`\$\w+->do\s*\(\s*"[^"]*\$[a-zA-Z_{]`)
	reDBIPrepareConcat = regexp.MustCompile(`\$\w+->prepare\s*\(\s*"[^"]*\$[a-zA-Z_{]`)
	reDBISelectConcat  = regexp.MustCompile(`\$\w+->selectrow_(?:array|hashref|arrayref)\s*\(\s*"[^"]*\$[a-zA-Z_{]`)
	reDBIQuote         = regexp.MustCompile(`->quote\s*\(`)
)

// PL-014: Taint mode not enabled for CGI
var (
	reCGIUse         = regexp.MustCompile(`\buse\s+CGI\b`)
	reTaintMode      = regexp.MustCompile(`^#!.*-T\b|^#!.*\s-\w*T`)
	rePerlTaintCheck = regexp.MustCompile(`\${.*\btainted\b}|Scalar::Util.*tainted`)
)

// PL-015: eval with user input
var (
	reEvalVar         = regexp.MustCompile(`\beval\s*\(\s*\$`)
	reEvalInterp      = regexp.MustCompile(`\beval\s*\(\s*"[^"]*\$[a-zA-Z_{]`)
	reEvalCGI         = regexp.MustCompile(`\beval\s*\(\s*\$(?:cgi|query|param|input|data|body)`)
	reStringEval      = regexp.MustCompile(`\beval\s+"[^"]*\$`)
)

// PL-016: Regex with user input
var (
	reRegexUserInput  = regexp.MustCompile(`=~\s*(?:m|s)?\s*/[^/]*\$[a-zA-Z_{]`)
	reRegexQR         = regexp.MustCompile(`\bqr\s*/[^/]*\$[a-zA-Z_{]`)
)

// PL-017: Insecure temporary file
var (
	reTmpnam       = regexp.MustCompile(`\btmpnam\s*\(`)
	reTempfile     = regexp.MustCompile(`\btempnam\s*\(`)
	rePredictTmp   = regexp.MustCompile(`(?:"/tmp/|'/tmp/)[^"']*\$`)
	reMktemp       = regexp.MustCompile(`\bmktemp\s*\(`)
	reFileTempSafe = regexp.MustCompile(`File::Temp|tempfile\s*\(|tmpfile\s*\(`)
)

// PL-018: Symlink attack via predictable filename
var (
	reSymlinkCreate   = regexp.MustCompile(`\bsymlink\s*\(`)
	rePredictFilename = regexp.MustCompile(`open\s*\(\s*\$?\w+\s*,\s*["']>\s*/tmp/[a-zA-Z_]`)
	reTmpConcat       = regexp.MustCompile(`"/tmp/"\s*\.\s*\$|'/tmp/'\s*\.\s*\$`)
)

func init() {
	rules.Register(&PerlTwoArgOpen{})
	rules.Register(&PerlBacktickVar{})
	rules.Register(&PerlDBINoPlaceholder{})
	rules.Register(&PerlTaintMode{})
	rules.Register(&PerlEvalUser{})
	rules.Register(&PerlRegexUser{})
	rules.Register(&PerlInsecureTmp{})
	rules.Register(&PerlSymlinkAttack{})
}

// ---------------------------------------------------------------------------
// BATOU-PL-011: Perl two-argument open (command injection)
// ---------------------------------------------------------------------------

type PerlTwoArgOpen struct{}

func (r *PerlTwoArgOpen) ID() string                      { return "BATOU-PL-011" }
func (r *PerlTwoArgOpen) Name() string                    { return "PerlTwoArgOpen" }
func (r *PerlTwoArgOpen) Description() string             { return "Detects Perl two-argument open() which interprets special characters (|, >, <) in the filename, enabling command injection." }
func (r *PerlTwoArgOpen) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PerlTwoArgOpen) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlTwoArgOpen) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reTwoArgOpenPipe.FindString(line); m != "" {
			matched = m
			desc = "Two-argument open() with explicit pipe or redirection character. This directly executes a shell command or opens a file in an unsafe mode."
		} else if m := reTwoArgOpenVar.FindString(line); m != "" {
			matched = m
			desc = "Two-argument open() with variable interpolation in the filename. If the variable starts with | it executes a command, with > it truncates the file."
		} else if m := reTwoArgOpen.FindString(line); m != "" {
			matched = m
			desc = "Two-argument open() with a variable as the second argument. Perl interprets special characters in the filename: leading | executes as a command, > opens for writing."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl two-argument open (command injection)",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use three-argument open: open(my $fh, '<', $filename). The three-argument form does not interpret special characters in the filename. Always use lexical filehandles (my $fh).",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "open", "command-injection", "two-arg"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-012: Perl backtick/qx with variable interpolation
// ---------------------------------------------------------------------------

type PerlBacktickVar struct{}

func (r *PerlBacktickVar) ID() string                      { return "BATOU-PL-012" }
func (r *PerlBacktickVar) Name() string                    { return "PerlBacktickVar" }
func (r *PerlBacktickVar) Description() string             { return "Detects Perl backtick or qx// with variable interpolation, enabling command injection." }
func (r *PerlBacktickVar) DefaultSeverity() rules.Severity { return rules.High }
func (r *PerlBacktickVar) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlBacktickVar) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reBacktickVar.FindString(line); m != "" {
			matched = m
			desc = "Backtick operator with variable interpolation. Shell metacharacters in the variable enable arbitrary command injection."
		} else if m := reQxVar.FindString(line); m != "" {
			matched = m
			desc = "qx// with variable interpolation. The variable is interpolated into a shell command, enabling command injection."
		} else if m := reQxBracket.FindString(line); m != "" {
			matched = m
			desc = "qx[] with variable interpolation. The variable is interpolated into a shell command."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl backtick/qx with variable interpolation",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use IPC::Run, IPC::Open3, or system() with a list form to avoid shell interpretation: system('cmd', $arg1, $arg2). Use quotemeta() or Perl's \\Q\\E to escape shell metacharacters if backticks are unavoidable.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "backtick", "qx", "command-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-013: Perl DBI query without placeholders
// ---------------------------------------------------------------------------

type PerlDBINoPlaceholder struct{}

func (r *PerlDBINoPlaceholder) ID() string                      { return "BATOU-PL-013" }
func (r *PerlDBINoPlaceholder) Name() string                    { return "PerlDBINoPlaceholder" }
func (r *PerlDBINoPlaceholder) Description() string             { return "Detects Perl DBI queries with variable interpolation instead of placeholders, enabling SQL injection." }
func (r *PerlDBINoPlaceholder) DefaultSeverity() rules.Severity { return rules.High }
func (r *PerlDBINoPlaceholder) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlDBINoPlaceholder) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		// Skip if the line uses quote()
		if reDBIQuote.MatchString(line) {
			continue
		}

		var matched string
		var desc string

		if m := reDBIDoConcat.FindString(line); m != "" {
			matched = m
			desc = "DBI->do() with variable interpolation. User input embedded in the SQL string enables SQL injection."
		} else if m := reDBIPrepareConcat.FindString(line); m != "" {
			matched = m
			desc = "DBI->prepare() with variable interpolation. The SQL is pre-interpolated before prepare(), bypassing parameterization."
		} else if m := reDBISelectConcat.FindString(line); m != "" {
			matched = m
			desc = "DBI->selectrow with variable interpolation. User input is embedded directly in the SQL query."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl DBI query without placeholders (SQL injection)",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use DBI placeholders: $sth = $dbh->prepare(\"SELECT * FROM users WHERE id = ?\"); $sth->execute($user_id). Or use $dbh->quote() if placeholders are not possible.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "dbi", "sql-injection", "placeholders"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-014: Perl taint mode not enabled for CGI
// ---------------------------------------------------------------------------

type PerlTaintMode struct{}

func (r *PerlTaintMode) ID() string                      { return "BATOU-PL-014" }
func (r *PerlTaintMode) Name() string                    { return "PerlTaintMode" }
func (r *PerlTaintMode) Description() string             { return "Detects Perl CGI scripts without taint mode (-T), which leaves user input validation unchecked." }
func (r *PerlTaintMode) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PerlTaintMode) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlTaintMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check files that use CGI
	if !reCGIUse.MatchString(ctx.Content) {
		return nil
	}

	// Check if taint mode is enabled
	if reTaintMode.MatchString(ctx.Content) || rePerlTaintCheck.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if reCGIUse.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl CGI without taint mode (-T)",
				Description:   "This CGI script uses the CGI module but does not enable taint mode (-T flag). Taint mode marks all external input as tainted and prevents its use in sensitive operations (system, open, eval, SQL) until explicitly sanitized via regex.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add -T to the shebang line: #!/usr/bin/perl -T. Then untaint user input with a regex: ($clean) = ($input =~ /^([a-zA-Z0-9]+)$/). Taint mode catches many injection vulnerabilities at runtime.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "cgi", "taint-mode", "input-validation"},
			})
			break // Only report once
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-015: Perl eval with user input
// ---------------------------------------------------------------------------

type PerlEvalUser struct{}

func (r *PerlEvalUser) ID() string                      { return "BATOU-PL-015" }
func (r *PerlEvalUser) Name() string                    { return "PerlEvalUser" }
func (r *PerlEvalUser) Description() string             { return "Detects Perl string eval with variable interpolation or user input, enabling arbitrary code execution." }
func (r *PerlEvalUser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PerlEvalUser) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlEvalUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string

		if m := reEvalCGI.FindString(line); m != "" {
			matched = m
		} else if m := reEvalInterp.FindString(line); m != "" {
			matched = m
		} else if m := reEvalVar.FindString(line); m != "" {
			matched = m
		} else if m := reStringEval.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl eval with user input (code injection)",
				Description:   "Perl string eval() compiles and executes arbitrary Perl code from a string. If the string contains user-controlled data, an attacker can inject arbitrary Perl code including system(), unlink(), or any other dangerous operation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid string eval with user input. Use eval { block } form for exception handling instead. For dynamic dispatch, use a hash of code references: my %dispatch = (action1 => \\&sub1); $dispatch{$action}->();",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "eval", "code-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-016: Perl regex with user input (injection)
// ---------------------------------------------------------------------------

type PerlRegexUser struct{}

func (r *PerlRegexUser) ID() string                      { return "BATOU-PL-016" }
func (r *PerlRegexUser) Name() string                    { return "PerlRegexUser" }
func (r *PerlRegexUser) Description() string             { return "Detects Perl regex with user-controlled variable interpolation, enabling ReDoS or regex injection." }
func (r *PerlRegexUser) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PerlRegexUser) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlRegexUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string

		if m := reRegexUserInput.FindString(line); m != "" {
			matched = m
		} else if m := reRegexQR.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl regex with user input (ReDoS/injection risk)",
				Description:   "A Perl regex pattern includes variable interpolation. An attacker can craft a malicious pattern with catastrophic backtracking (ReDoS) to cause denial of service, or inject regex metacharacters to bypass validation or execute code via (?{...}) if enabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use quotemeta() or \\Q\\E to escape user input in regex: $str =~ /\\Q$user_input\\E/. This treats the variable as a literal string. For complex patterns, validate the input format before embedding.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "regex", "redos", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-017: Perl insecure temporary file
// ---------------------------------------------------------------------------

type PerlInsecureTmp struct{}

func (r *PerlInsecureTmp) ID() string                      { return "BATOU-PL-017" }
func (r *PerlInsecureTmp) Name() string                    { return "PerlInsecureTmp" }
func (r *PerlInsecureTmp) Description() string             { return "Detects Perl insecure temporary file creation via tmpnam(), mktemp(), or predictable /tmp filenames." }
func (r *PerlInsecureTmp) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PerlInsecureTmp) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlInsecureTmp) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if using File::Temp (secure alternative)
	if reFileTempSafe.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reTmpnam.FindString(line); m != "" {
			matched = m
			desc = "tmpnam() generates a predictable temporary filename. An attacker can create a symlink at the predicted path before the file is created, leading to symlink attacks (writing to arbitrary files)."
		} else if m := reMktemp.FindString(line); m != "" {
			matched = m
			desc = "mktemp() creates a predictable temporary filename without atomically opening it. A TOCTOU race condition allows symlink attacks between name generation and file creation."
		} else if m := rePredictTmp.FindString(line); m != "" {
			matched = m
			desc = "A file is opened in /tmp with a path that includes variable interpolation but may be predictable. Predictable temp filenames enable symlink attacks."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl insecure temporary file creation",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use File::Temp which creates temporary files securely: use File::Temp qw(tempfile); my ($fh, $filename) = tempfile(UNLINK => 1). File::Temp uses unpredictable names and atomic file creation.",
				CWEID:         "CWE-377",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "tmpfile", "race-condition", "symlink"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PL-018: Perl symlink attack via predictable filename
// ---------------------------------------------------------------------------

type PerlSymlinkAttack struct{}

func (r *PerlSymlinkAttack) ID() string                      { return "BATOU-PL-018" }
func (r *PerlSymlinkAttack) Name() string                    { return "PerlSymlinkAttack" }
func (r *PerlSymlinkAttack) Description() string             { return "Detects Perl file operations writing to predictable /tmp paths, enabling symlink race condition attacks." }
func (r *PerlSymlinkAttack) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PerlSymlinkAttack) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PerlSymlinkAttack) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := rePredictFilename.FindString(line); m != "" {
			matched = m
			desc = "A file is opened for writing (>) in /tmp with a predictable filename. An attacker can pre-create a symlink at this path to redirect writes to arbitrary files (e.g., /etc/crontab, ~/.ssh/authorized_keys)."
		} else if m := reTmpConcat.FindString(line); m != "" {
			matched = m
			desc = "A /tmp path is built via string concatenation with a variable. If the resulting path is predictable, an attacker can exploit a TOCTOU race to create a symlink and redirect file operations."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl symlink attack via predictable /tmp filename",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use File::Temp for secure temporary files: use File::Temp qw(tempfile); my ($fh, $name) = tempfile(DIR => '/tmp', UNLINK => 1). Check with -l (lstat) that the path is not a symlink before opening, or use O_NOFOLLOW.",
				CWEID:         "CWE-59",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "symlink", "race-condition", "tmp"},
			})
		}
	}
	return findings
}
