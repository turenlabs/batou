package perl

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// PL-001: Command Injection
var (
	// system("cmd $var") - single string argument with interpolation
	systemSingleInterp = regexp.MustCompile(`\bsystem\s*\(\s*"[^"]*\$[a-zA-Z_{]`)
	// system($var) - variable as command
	systemConcatVar    = regexp.MustCompile(`\bsystem\s*\(\s*\$`)
	// exec("cmd $var") or exec($var)
	execWithVar        = regexp.MustCompile(`\bexec\s*\(\s*"[^"]*\$[a-zA-Z_{]`)
	execConcatVar      = regexp.MustCompile(`\bexec\s*\(\s*\$`)
	// `cmd $var`
	backtickWithVar    = regexp.MustCompile("`[^`]*\\$[a-zA-Z_{]")
	// qx(cmd $var)
	qxWithVar          = regexp.MustCompile(`qx\s*[\({/][^)\}/]*\$[a-zA-Z_{]`)
	// open(FH, "|cmd $var") or open($fh, "|$var")
	openPipeWithVar    = regexp.MustCompile(`open\s*\([^)]*["']\|[^"']*\$[a-zA-Z_{]`)
)

// PL-002: SQL Injection
var (
	// $dbh->do("....$var...") - interpolation inside the SQL string
	dbiDoInterp       = regexp.MustCompile(`\$dbh->do\s*\(\s*"[^"]*\$[a-zA-Z_{][^"]*"`)
	// $dbh->do("..." . $var) - concatenation
	dbiDoConcatDot    = regexp.MustCompile(`\$dbh->do\s*\(\s*["'][^"']*["']\s*\.`)
	// $dbh->prepare("...$var...") - interpolation inside prepare string
	dbiPrepInterp     = regexp.MustCompile(`\$dbh->prepare\s*\(\s*"[^"]*\$[a-zA-Z_{][^"]*"`)
	// $dbh->prepare("..." . $var) - concatenation
	dbiPrepConcat     = regexp.MustCompile(`\$dbh->prepare\s*\(\s*["'][^"']*["']\s*\.`)
	// $dbh->selectrow_*("...$var...") - interpolation
	dbiSelectInterp   = regexp.MustCompile(`\$dbh->select(?:row|all)_\w+\s*\(\s*"[^"]*\$[a-zA-Z_{][^"]*"`)
	// $dbh->selectrow_*("..." . $var) - concatenation
	dbiSelectConcat   = regexp.MustCompile(`\$dbh->select(?:row|all)_\w+\s*\(\s*["'][^"']*["']\s*\.`)
)

// PL-003: Code Injection
var (
	evalStringVar    = regexp.MustCompile(`\beval\s*\(\s*\$`)
	evalStringQuoted = regexp.MustCompile(`\beval\s*\(\s*["'].*\$`)
	evalDollar       = regexp.MustCompile(`\beval\s+\$`)
	evalQuoteInterp  = regexp.MustCompile(`\beval\s+"[^"]*\$`)
)

// PL-004: Path Traversal
var (
	// Two-arg open: open(FH, $var) or open(my $fh, $var) - allows pipe injection
	twoArgOpen      = regexp.MustCompile(`open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*\$`)
	// Three-arg open with user var: open(FH, '<', $var)
	openWithUserVar = regexp.MustCompile(`open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*["'][<>]*["']\s*,\s*\$`)
	// Three-arg open with path concat: open(FH, '<', "/path/" . $var)
	openConcatPath  = regexp.MustCompile(`open\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*["'][<>]*["']\s*,\s*["'][^"']*["']\s*\.\s*\$`)
)

// PL-005: Regex DoS
var (
	regexWithVar    = regexp.MustCompile(`=~\s*(?:m\s*)?/[^/]*\$[a-zA-Z_]`)
	regexWithInterp = regexp.MustCompile(`=~\s*(?:m\s*)?/[^/]*\$\{`)
	qrWithVar       = regexp.MustCompile(`qr/[^/]*\$[a-zA-Z_]`)
)

// PL-006: CGI XSS
var (
	printParamDirect = regexp.MustCompile(`print\s+.*\$cgi->param\s*\(`)
	printQParam      = regexp.MustCompile(`print\s+.*\$q->param\s*\(`)
	printParamVar    = regexp.MustCompile(`print\s+.*param\s*\(`)
	printUserVar     = regexp.MustCompile(`print\s+["'].*\$(?:input|user_input|name|data|query|value|content|body|text|message|comment)\b`)
	headerWithParam  = regexp.MustCompile(`\$cgi->header.*\$|\$q->header.*\$`)
)

// PL-007: Insecure File Operations
var (
	twoArgOpenBare  = regexp.MustCompile(`open\s*\(\s*(?:my\s+)?\w+\s*,\s*\$`)
	chmod0777       = regexp.MustCompile(`chmod\s*\(\s*0?777\b`)
	chmodWorldWrite = regexp.MustCompile(`chmod\s*\(\s*0?666\b`)
	mkdirWorldWrite = regexp.MustCompile(`mkdir\s*\(\s*\$?\w+\s*,\s*0?777\b`)
)

// PL-008: Deserialization
var (
	storableThaw     = regexp.MustCompile(`(?:Storable::)?thaw\s*\(\s*\$`)
	storableRetrieve = regexp.MustCompile(`(?:Storable::)?retrieve\s*\(\s*\$`)
	yamlLoadVar      = regexp.MustCompile(`YAML(?:::Syck)?::Load\s*\(\s*\$`)
	yamlLoadFile     = regexp.MustCompile(`YAML(?:::Syck)?::LoadFile\s*\(\s*\$`)
)

// PL-009: LDAP Injection
var (
	ldapSearchInterp = regexp.MustCompile(`\$ldap->search\s*\([^)]*filter\s*=>\s*["'].*\$`)
	ldapSearchConcat = regexp.MustCompile(`\$ldap->search\s*\([^)]*filter\s*=>\s*["'][^"']*["']\s*\.`)
	ldapFilterVar    = regexp.MustCompile(`filter\s*=>\s*\$`)
)

// PL-010: Insecure Randomness
var (
	randForSecurity = regexp.MustCompile(`\brand\s*\(`)
	srandTime       = regexp.MustCompile(`\bsrand\s*\(\s*time\b`)
	srandFixed      = regexp.MustCompile(`\bsrand\s*\(\s*\d+\s*\)`)
)

func init() {
	rules.Register(&CommandInjection{})
	rules.Register(&SQLInjection{})
	rules.Register(&CodeInjection{})
	rules.Register(&PathTraversal{})
	rules.Register(&RegexDoS{})
	rules.Register(&CGIXSS{})
	rules.Register(&InsecureFileOps{})
	rules.Register(&Deserialization{})
	rules.Register(&LDAPInjection{})
	rules.Register(&InsecureRandomness{})
}

// --- PL-001: Command Injection ---

type CommandInjection struct{}

func (r *CommandInjection) ID() string                      { return "GTSS-PL-001" }
func (r *CommandInjection) Name() string                    { return "PerlCommandInjection" }
func (r *CommandInjection) Description() string             { return "Detects Perl command injection via system/exec/backticks/qx with variable interpolation." }
func (r *CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CommandInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := systemSingleInterp.FindString(line); loc != "" {
			matched = loc
			desc = "system() with variable interpolation"
		} else if loc := systemConcatVar.FindString(line); loc != "" {
			matched = loc
			desc = "system() with variable argument"
		} else if loc := execWithVar.FindString(line); loc != "" {
			matched = loc
			desc = "exec() with variable interpolation"
		} else if loc := execConcatVar.FindString(line); loc != "" {
			matched = loc
			desc = "exec() with variable argument"
		} else if loc := backtickWithVar.FindString(line); loc != "" {
			matched = loc
			desc = "backtick command with variable interpolation"
		} else if loc := qxWithVar.FindString(line); loc != "" {
			matched = loc
			desc = "qx() with variable interpolation"
		} else if loc := openPipeWithVar.FindString(line); loc != "" {
			matched = loc
			desc = "open() with pipe and variable interpolation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl command injection via " + desc,
				Description:   "User-controlled data is interpolated into a shell command. An attacker can inject arbitrary commands via shell metacharacters (;, |, $(), etc.).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use list-form system() to avoid shell interpretation: system('command', @args). For backticks, use open() with list form or IPC::Run.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "command-injection", "os-command"},
			})
		}
	}

	return findings
}

// --- PL-002: SQL Injection ---

type SQLInjection struct{}

func (r *SQLInjection) ID() string                      { return "GTSS-PL-002" }
func (r *SQLInjection) Name() string                    { return "PerlSQLInjection" }
func (r *SQLInjection) Description() string             { return "Detects Perl DBI SQL injection via string interpolation or concatenation instead of placeholders." }
func (r *SQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SQLInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *SQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := dbiDoInterp.FindString(line); loc != "" {
			matched = loc
			desc = "$dbh->do() with variable interpolation"
		} else if loc := dbiDoConcatDot.FindString(line); loc != "" {
			matched = loc
			desc = "$dbh->do() with string concatenation"
		} else if loc := dbiPrepInterp.FindString(line); loc != "" {
			matched = loc
			desc = "$dbh->prepare() with variable interpolation"
		} else if loc := dbiPrepConcat.FindString(line); loc != "" {
			matched = loc
			desc = "$dbh->prepare() with string concatenation"
		} else if loc := dbiSelectInterp.FindString(line); loc != "" {
			matched = loc
			desc = "DBI selectrow/selectall with variable interpolation"
		} else if loc := dbiSelectConcat.FindString(line); loc != "" {
			matched = loc
			desc = "DBI selectrow/selectall with string concatenation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl SQL injection via " + desc,
				Description:   "User-controlled data is interpolated or concatenated into a SQL query string. An attacker can inject arbitrary SQL to extract data, modify records, or escalate privileges.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use DBI placeholders: $dbh->do(\"DELETE FROM users WHERE id = ?\", undef, $id) or $sth = $dbh->prepare(\"SELECT * FROM users WHERE name = ?\"); $sth->execute($name);",
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

// --- PL-003: Code Injection ---

type CodeInjection struct{}

func (r *CodeInjection) ID() string                      { return "GTSS-PL-003" }
func (r *CodeInjection) Name() string                    { return "PerlCodeInjection" }
func (r *CodeInjection) Description() string             { return "Detects Perl code injection via eval() with variable or string eval." }
func (r *CodeInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CodeInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *CodeInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		// eval with variable argument: eval($code), eval $var
		if loc := evalStringVar.FindString(line); loc != "" {
			matched = loc
			desc = "eval() with variable argument"
		} else if loc := evalDollar.FindString(line); loc != "" {
			matched = loc
			desc = "eval with variable expression"
		} else if loc := evalQuoteInterp.FindString(line); loc != "" {
			matched = loc
			desc = "eval with double-quoted string interpolation"
		} else if loc := evalStringQuoted.FindString(line); loc != "" {
			// Check it's not just an error-handling eval { } block
			if !strings.Contains(line, "eval {") && !strings.Contains(line, "eval{") {
				matched = loc
				desc = "eval() with interpolated string"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl code injection via " + desc,
				Description:   "User-controlled data is passed to eval(), enabling arbitrary Perl code execution. An attacker can execute any Perl code on the server, including system commands, file operations, and data exfiltration.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid string eval with user input. Use eval { } blocks only for exception handling. For dynamic dispatch, use a hash lookup of allowed subroutines.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "code-injection", "eval"},
			})
		}
	}

	return findings
}

// --- PL-004: Path Traversal ---

type PathTraversal struct{}

func (r *PathTraversal) ID() string                      { return "GTSS-PL-004" }
func (r *PathTraversal) Name() string                    { return "PerlPathTraversal" }
func (r *PathTraversal) Description() string             { return "Detects Perl path traversal via open() with user-controlled input or two-argument open." }
func (r *PathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *PathTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file has user input sources
	hasUserInput := strings.Contains(ctx.Content, "param(") ||
		strings.Contains(ctx.Content, "$cgi->") ||
		strings.Contains(ctx.Content, "$q->") ||
		strings.Contains(ctx.Content, "$c->param") ||
		strings.Contains(ctx.Content, "params->") ||
		strings.Contains(ctx.Content, "@ARGV") ||
		strings.Contains(ctx.Content, "<STDIN>") ||
		strings.Contains(ctx.Content, "$ENV{")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := twoArgOpen.FindString(line); loc != "" {
			// Two-arg open with variable is dangerous (allows |command)
			matched = loc
			desc = "two-argument open() with variable (allows pipe injection)"
		} else if hasUserInput {
			if loc := openWithUserVar.FindString(line); loc != "" {
				matched = loc
				desc = "open() with user-controlled path"
			} else if loc := openConcatPath.FindString(line); loc != "" {
				matched = loc
				desc = "open() with concatenated user path"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl path traversal via " + desc,
				Description:   "User-controlled data is used in a file path without validation. Two-argument open() is especially dangerous as it allows pipe injection (|command) in addition to directory traversal (../).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use three-argument open(): open(my $fh, '<', $filename). Validate paths with File::Spec->canonpath() and File::Basename::basename(). Check that resolved paths are within allowed directories.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "path-traversal", "file-access"},
			})
		}
	}

	return findings
}

// --- PL-005: Regex DoS ---

type RegexDoS struct{}

func (r *RegexDoS) ID() string                      { return "GTSS-PL-005" }
func (r *RegexDoS) Name() string                    { return "PerlRegexDoS" }
func (r *RegexDoS) Description() string             { return "Detects Perl regex denial of service via user input in regex without quotemeta/\\Q\\E." }
func (r *RegexDoS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RegexDoS) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *RegexDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for quotemeta or \Q..\E usage which mitigates this
	hasQuotemeta := strings.Contains(ctx.Content, "quotemeta") ||
		strings.Contains(ctx.Content, "\\Q")

	if hasQuotemeta {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := regexWithVar.FindString(line); loc != "" {
			matched = loc
			desc = "regex match with variable interpolation"
		} else if loc := regexWithInterp.FindString(line); loc != "" {
			matched = loc
			desc = "regex match with ${} interpolation"
		} else if loc := qrWithVar.FindString(line); loc != "" {
			matched = loc
			desc = "qr// with variable interpolation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl ReDoS risk via " + desc,
				Description:   "User-controlled data is interpolated into a regular expression without escaping. An attacker can inject regex metacharacters to cause catastrophic backtracking (ReDoS) or modify the matching behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use quotemeta() or \\Q...\\E to escape regex metacharacters: $input =~ /\\Q$user_input\\E/. Alternatively, use index() for literal substring matching.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "regex", "redos"},
			})
		}
	}

	return findings
}

// --- PL-006: CGI XSS ---

type CGIXSS struct{}

func (r *CGIXSS) ID() string                      { return "GTSS-PL-006" }
func (r *CGIXSS) Name() string                    { return "PerlCGIXSS" }
func (r *CGIXSS) Description() string             { return "Detects Perl CGI XSS via printing CGI parameters without HTML encoding." }
func (r *CGIXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *CGIXSS) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *CGIXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for HTML encoding which mitigates XSS
	hasEncoding := strings.Contains(ctx.Content, "encode_entities") ||
		strings.Contains(ctx.Content, "escapeHTML") ||
		strings.Contains(ctx.Content, "escape_html") ||
		strings.Contains(ctx.Content, "HTML::Entities") ||
		strings.Contains(ctx.Content, "HTML::Escape")

	if hasEncoding {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := printParamDirect.FindString(line); loc != "" {
			matched = loc
			desc = "print with $cgi->param() without encoding"
		} else if loc := printQParam.FindString(line); loc != "" {
			matched = loc
			desc = "print with $q->param() without encoding"
		} else if loc := headerWithParam.FindString(line); loc != "" {
			matched = loc
			desc = "CGI header with variable interpolation"
		} else if loc := printUserVar.FindString(line); loc != "" {
			matched = loc
			desc = "print with user-controlled variable"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl CGI XSS via " + desc,
				Description:   "CGI parameters are printed directly to the HTTP response without HTML encoding. An attacker can inject JavaScript via the parameter value to steal cookies, redirect users, or deface the page.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use HTML::Entities::encode_entities() or CGI::escapeHTML() to encode output: print encode_entities($cgi->param('name'));",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "xss", "cgi"},
			})
		}
	}

	return findings
}

// --- PL-007: Insecure File Operations ---

type InsecureFileOps struct{}

func (r *InsecureFileOps) ID() string                      { return "GTSS-PL-007" }
func (r *InsecureFileOps) Name() string                    { return "PerlInsecureFileOps" }
func (r *InsecureFileOps) Description() string             { return "Detects Perl insecure file operations: two-argument open, chmod 0777, world-writable permissions." }
func (r *InsecureFileOps) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureFileOps) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *InsecureFileOps) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string
		severity := r.DefaultSeverity()

		if loc := twoArgOpenBare.FindString(line); loc != "" {
			// Only flag two-arg open with variable (bare filehandle form)
			if !strings.Contains(line, ", '<',") && !strings.Contains(line, ", '>',") &&
				!strings.Contains(line, ", '>>',") && !strings.Contains(line, ", '<',") {
				matched = loc
				desc = "two-argument open() allows pipe injection"
			}
		} else if loc := chmod0777.FindString(line); loc != "" {
			matched = loc
			desc = "chmod 0777 sets world-readable/writable/executable"
			severity = rules.High
		} else if loc := chmodWorldWrite.FindString(line); loc != "" {
			matched = loc
			desc = "chmod 0666 sets world-readable/writable"
			severity = rules.Medium
		} else if loc := mkdirWorldWrite.FindString(line); loc != "" {
			matched = loc
			desc = "mkdir with 0777 creates world-writable directory"
			severity = rules.High
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				SeverityLabel: severity.String(),
				Title:         "Perl insecure file operation: " + desc,
				Description:   "Insecure file operation detected. Two-argument open() is vulnerable to pipe injection when the filename starts with '|'. World-writable permissions allow any user on the system to read/modify the file.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use three-argument open(): open(my $fh, '<', $file). Use restrictive permissions: chmod(0600, $file) for sensitive files or 0644 for readable files.",
				CWEID:         "CWE-732",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "file-permissions", "insecure-defaults"},
			})
		}
	}

	return findings
}

// --- PL-008: Deserialization ---

type Deserialization struct{}

func (r *Deserialization) ID() string                      { return "GTSS-PL-008" }
func (r *Deserialization) Name() string                    { return "PerlDeserialization" }
func (r *Deserialization) Description() string             { return "Detects Perl unsafe deserialization via Storable thaw/retrieve or YAML::Load from untrusted input." }
func (r *Deserialization) DefaultSeverity() rules.Severity { return rules.High }
func (r *Deserialization) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *Deserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string
		severity := r.DefaultSeverity()

		if loc := storableThaw.FindString(line); loc != "" {
			matched = loc
			desc = "Storable::thaw() with variable input"
			severity = rules.Critical
		} else if loc := storableRetrieve.FindString(line); loc != "" {
			matched = loc
			desc = "Storable::retrieve() with variable input"
			severity = rules.Critical
		} else if loc := yamlLoadVar.FindString(line); loc != "" {
			matched = loc
			desc = "YAML::Load() with variable input"
			severity = rules.High
		} else if loc := yamlLoadFile.FindString(line); loc != "" {
			matched = loc
			desc = "YAML::LoadFile() with variable input"
			severity = rules.High
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				SeverityLabel: severity.String(),
				Title:         "Perl unsafe deserialization via " + desc,
				Description:   "Untrusted data is deserialized using an unsafe method. Storable::thaw() can execute arbitrary code during deserialization via DESTROY methods. YAML::Load() can instantiate arbitrary Perl objects.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use safe alternatives: YAML::Safe::Load() or YAML::XS with SafeMode for YAML. Avoid Storable for untrusted input; use JSON for data interchange instead.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "deserialization", "storable", "yaml"},
			})
		}
	}

	return findings
}

// --- PL-009: LDAP Injection ---

type LDAPInjection struct{}

func (r *LDAPInjection) ID() string                      { return "GTSS-PL-009" }
func (r *LDAPInjection) Name() string                    { return "PerlLDAPInjection" }
func (r *LDAPInjection) Description() string             { return "Detects Perl LDAP injection via Net::LDAP search with interpolated filter." }
func (r *LDAPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *LDAPInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *LDAPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !strings.Contains(ctx.Content, "Net::LDAP") && !strings.Contains(ctx.Content, "$ldap->search") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := ldapSearchInterp.FindString(line); loc != "" {
			matched = loc
			desc = "Net::LDAP search with interpolated filter"
		} else if loc := ldapSearchConcat.FindString(line); loc != "" {
			matched = loc
			desc = "Net::LDAP search with concatenated filter"
		} else if loc := ldapFilterVar.FindString(line); loc != "" {
			matched = loc
			desc = "LDAP filter from variable"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl LDAP injection via " + desc,
				Description:   "User-controlled data is interpolated into an LDAP filter string. An attacker can modify the LDAP query to bypass authentication, access unauthorized entries, or enumerate directory data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use Net::LDAP::Filter to construct filters safely, or escape special LDAP characters (*, (, ), \\, NUL) from user input with Net::LDAP::Util::escape_filter_value().",
				CWEID:         "CWE-90",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"perl", "ldap-injection", "net-ldap"},
			})
		}
	}

	return findings
}

// --- PL-010: Insecure Randomness ---

type InsecureRandomness struct{}

func (r *InsecureRandomness) ID() string                      { return "GTSS-PL-010" }
func (r *InsecureRandomness) Name() string                    { return "PerlInsecureRandomness" }
func (r *InsecureRandomness) Description() string             { return "Detects Perl insecure random number generation via rand() or srand(time) in security contexts." }
func (r *InsecureRandomness) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureRandomness) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }

func (r *InsecureRandomness) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag rand()/srand() in security-relevant contexts
	hasCryptoContext := strings.Contains(ctx.Content, "token") ||
		strings.Contains(ctx.Content, "secret") ||
		strings.Contains(ctx.Content, "password") ||
		strings.Contains(ctx.Content, "session") ||
		strings.Contains(ctx.Content, "nonce") ||
		strings.Contains(ctx.Content, "salt") ||
		strings.Contains(ctx.Content, "key") ||
		strings.Contains(ctx.Content, "otp") ||
		strings.Contains(ctx.Content, "csrf") ||
		strings.Contains(ctx.Content, "random_id") ||
		strings.Contains(ctx.Content, "api_key")

	// Skip if using Crypt::URandom or similar
	if strings.Contains(ctx.Content, "Crypt::URandom") ||
		strings.Contains(ctx.Content, "Crypt::Random") ||
		strings.Contains(ctx.Content, "Math::Random::Secure") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isPerlComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := srandTime.FindString(line); loc != "" {
			matched = loc
			desc = "srand(time) uses predictable seed"
		} else if loc := srandFixed.FindString(line); loc != "" {
			matched = loc
			desc = "srand() with fixed seed"
		} else if hasCryptoContext {
			if loc := randForSecurity.FindString(line); loc != "" {
				matched = loc
				desc = "rand() used in security-sensitive context"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Perl insecure randomness: " + desc,
				Description:   "Perl's rand() function uses a non-cryptographic PRNG that is predictable. srand(time) seeds with second-precision time, making the sequence reproducible. These should not be used for tokens, passwords, session IDs, or other security-sensitive values.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use Crypt::URandom for cryptographically secure random bytes, or Math::Random::Secure::rand() as a drop-in replacement for rand().",
				CWEID:         "CWE-338",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"perl", "insecure-random", "prng"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func isPerlComment(line string) bool {
	return strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "=pod") ||
		strings.HasPrefix(line, "=head") ||
		strings.HasPrefix(line, "=cut") ||
		strings.HasPrefix(line, "=over") ||
		strings.HasPrefix(line, "=item") ||
		strings.HasPrefix(line, "=back")
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
