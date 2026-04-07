package injection

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for C/C++ injection rules
// ---------------------------------------------------------------------------

// BATOU-INJ-025: C/C++ SQL injection via sprintf/snprintf/strcat with SQL keywords
var (
	// sprintf/snprintf with SQL keywords and %s format specifier
	reCSQLSprintf = regexp.MustCompile(`(?i)\b(?:sprintf|snprintf)\s*\([^;]*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*%`)
	// strcpy/strcat building SQL query (string literal contains SQL keyword)
	reCSQLStrcat = regexp.MustCompile(`(?i)\b(?:strcpy|strcat)\s*\(\s*\w+\s*,\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b`)
	// String concat with + operator (C++) containing SQL keyword
	reCSQLConcatCpp = regexp.MustCompile(`(?i)"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*"\s*\+\s*\w`)
	// std::string append (+=) with SQL keyword
	reCSQLAppendCpp = regexp.MustCompile(`(?i)\+=\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b`)
	// std::string assignment with SQL keyword (multi-line build: var = "SELECT..." then var += input)
	reCSQLAssignCpp = regexp.MustCompile(`(?i)=\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*["'];\s*$`)
	// ostringstream << with SQL keyword
	reCSQLOstream = regexp.MustCompile(`(?i)<<\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*"\s*<<\s*\w`)
	// Safe patterns: parameterized queries
	reCSQLSafeBind = regexp.MustCompile(`(?i)sqlite3_bind|sqlite3_prepare|mysql_stmt_bind|PQexecParams|PQprepare`)
)

// BATOU-INJ-026: C/C++ command injection via system()/popen() with variable
var (
	// system() with a variable argument (not a string literal)
	reCCmdSystem = regexp.MustCompile(`\bsystem\s*\(\s*[a-zA-Z_]\w*`)
	// system() with string literal only (safe)
	reCCmdSystemLiteral = regexp.MustCompile(`\bsystem\s*\(\s*"[^"]*"\s*\)`)
	// popen() with a variable argument
	reCCmdPopen = regexp.MustCompile(`\bpopen\s*\(\s*[a-zA-Z_]\w*`)
	// popen() with string literal only (safe)
	reCCmdPopenLiteral = regexp.MustCompile(`\bpopen\s*\(\s*"[^"]*"\s*,`)
	// sprintf/snprintf building command string then system()/popen()
	reCCmdSprintf = regexp.MustCompile(`(?i)\b(?:sprintf|snprintf)\s*\(\s*(\w+)`)
)

func init() {
	rules.Register(&CSQLInjection{})
	rules.Register(&CCommandInjection{})
}

// ---------------------------------------------------------------------------
// BATOU-INJ-025: C/C++ SQL Injection
// ---------------------------------------------------------------------------

type CSQLInjection struct{}

func (r *CSQLInjection) ID() string                     { return "BATOU-INJ-025" }
func (r *CSQLInjection) Name() string                   { return "CSQLInjection" }
func (r *CSQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CSQLInjection) Description() string {
	return "Detects SQL queries built via sprintf, snprintf, strcat, or string concatenation in C/C++ code, which may allow SQL injection."
}
func (r *CSQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *CSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if the file uses parameterized queries (safe pattern).
	hasSafeBind := reCSQLSafeBind.MatchString(ctx.Content)

	type pattern struct {
		re   *regexp.Regexp
		conf string
		lang rules.Language // rules.LangAny means any
	}
	patterns := []pattern{
		{reCSQLSprintf, "high", rules.LangAny},
		{reCSQLStrcat, "high", rules.LangAny},
		{reCSQLConcatCpp, "high", rules.LangCPP},
		{reCSQLAppendCpp, "medium", rules.LangCPP},
		{reCSQLOstream, "high", rules.LangCPP},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if p.lang != rules.LangAny && p.lang != ctx.Language {
				continue
			}
			if loc := p.re.FindStringIndex(line); loc != nil {
				// If the entire file uses parameterized queries, reduce confidence.
				conf := p.conf
				if hasSafeBind {
					conf = "low"
				}
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "C/C++ SQL Injection: query built with sprintf/strcat/string concatenation",
					Description:   "SQL queries constructed via sprintf, snprintf, strcat, or C++ string concatenation with user input are vulnerable to SQL injection attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use parameterized queries: sqlite3_prepare_v2 + sqlite3_bind_text, mysql_stmt_prepare + mysql_stmt_bind_param, or PQexecParams instead of string formatting.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    conf,
					Tags:          []string{"injection", "sql", "c-cpp"},
				})
				break
			}
		}
	}

	// C++ multi-line SQL build: var = "SELECT..." then var += input on nearby line.
	if ctx.Language == rules.LangCPP && !hasSafeBind {
		for i, line := range lines {
			if isCommentLine(line) {
				continue
			}
			if reCSQLAssignCpp.MatchString(line) {
				// Look ahead for += with a variable (not a string literal) within 5 lines.
				for j := i + 1; j < len(lines) && j <= i+5; j++ {
					trimmed := strings.TrimSpace(lines[j])
					if strings.Contains(trimmed, "+=") && !strings.Contains(trimmed, `+= "`) {
						findings = append(findings, rules.Finding{
							RuleID:        r.ID(),
							Severity:      r.DefaultSeverity(),
							SeverityLabel: r.DefaultSeverity().String(),
							Title:         "C/C++ SQL Injection: query built with string append",
							Description:   "A SQL query string is initialized with SQL keywords and then appended with a variable, which may allow SQL injection.",
							FilePath:      ctx.FilePath,
							LineNumber:    i + 1,
							MatchedText:   truncate(strings.TrimSpace(line), 120),
							Suggestion:    "Use parameterized queries: sqlite3_prepare_v2 + sqlite3_bind_text instead of string concatenation.",
							CWEID:         "CWE-89",
							OWASPCategory: "A03:2021-Injection",
							Language:      ctx.Language,
							Confidence:    "medium",
							Tags:          []string{"injection", "sql", "c-cpp"},
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-026: C/C++ Command Injection
// ---------------------------------------------------------------------------

type CCommandInjection struct{}

func (r *CCommandInjection) ID() string                     { return "BATOU-INJ-026" }
func (r *CCommandInjection) Name() string                   { return "CCommandInjection" }
func (r *CCommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CCommandInjection) Description() string {
	return "Detects OS command injection via system(), popen(), or command strings built with sprintf/snprintf in C/C++ code."
}
func (r *CCommandInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *CCommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track variables that hold sprintf-built strings (potential command buffers).
	sprintfVars := make(map[string]int) // var name -> line number

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)

		// Track sprintf/snprintf destination buffers.
		if m := reCCmdSprintf.FindStringSubmatch(line); m != nil {
			sprintfVars[m[1]] = i + 1
		}

		// system(variable) -- not a literal
		if reCCmdSystem.MatchString(line) && !reCCmdSystemLiteral.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C/C++ Command Injection: system() with variable argument",
				Description:   "Calling system() with a variable argument allows OS command injection if the variable contains user-controlled data. An attacker can inject shell metacharacters to execute arbitrary commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use execvp/execv with a separate argument array instead of system(). Validate and sanitize all inputs. Never pass user input through a shell interpreter.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"injection", "command", "c-cpp"},
			})
		}

		// popen(variable) -- not a literal
		if reCCmdPopen.MatchString(line) && !reCCmdPopenLiteral.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C/C++ Command Injection: popen() with variable argument",
				Description:   "Calling popen() with a variable argument allows OS command injection. popen() passes the command to the shell, enabling shell metacharacter attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use pipe/fork/exec with a separate argument array instead of popen(). Never pass user-controlled input to popen().",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"injection", "command", "c-cpp"},
			})
		}
	}
	return findings
}
