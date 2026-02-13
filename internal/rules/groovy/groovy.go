package groovy

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// GVY-001: Command Injection
var (
	stringExecute    = regexp.MustCompile(`"[^"]*"\s*\.execute\s*\(`)
	gstringExecute   = regexp.MustCompile(`"[^"]*\$\{[^}]+\}[^"]*"\s*\.execute\s*\(`)
	varExecute       = regexp.MustCompile(`\w+\s*\.execute\s*\(`)
	listExecute      = regexp.MustCompile(`\[.*\]\s*\.execute\s*\(`)
	runtimeExec      = regexp.MustCompile(`Runtime\.(?:getRuntime\s*\(\s*\)\s*\.)?exec\s*\(`)
	processBuilderRe = regexp.MustCompile(`new\s+ProcessBuilder\s*\(`)
)

// GVY-002: Code Injection
var (
	groovyShellEvaluate = regexp.MustCompile(`(?:new\s+GroovyShell\s*\(\s*\)\s*\.evaluate|shell\.evaluate)\s*\(`)
	groovyShellParse    = regexp.MustCompile(`(?:new\s+GroovyShell\s*\(\s*\)\s*\.parse|shell\.parse)\s*\(`)
	evalMe              = regexp.MustCompile(`Eval\.(?:me|x|xy|xyz)\s*\(`)
	groovyScriptEngine  = regexp.MustCompile(`(?:GroovyScriptEngine|ScriptEngine).*\.(?:run|eval)\s*\(|engine\.(?:run|eval)\s*\(`)
)

// GVY-003: SQL Injection (GString interpolation in SQL)
var (
	sqlExecuteGString  = regexp.MustCompile(`\.execute\s*\(\s*"[^"]*\$\{`)
	sqlRowsGString     = regexp.MustCompile(`\.rows\s*\(\s*"[^"]*\$\{`)
	sqlFirstRowGString = regexp.MustCompile(`\.firstRow\s*\(\s*"[^"]*\$\{`)
	sqlEachRowGString  = regexp.MustCompile(`\.eachRow\s*\(\s*"[^"]*\$\{`)
	sqlUpdateGString   = regexp.MustCompile(`\.executeUpdate\s*\(\s*"[^"]*\$\{`)
	sqlExecuteConcat   = regexp.MustCompile(`\.execute\s*\(\s*"[^"]*"\s*\+`)
	sqlRowsConcat      = regexp.MustCompile(`\.rows\s*\(\s*"[^"]*"\s*\+`)
	sqlFirstRowConcat  = regexp.MustCompile(`\.firstRow\s*\(\s*"[^"]*"\s*\+`)
)

// GVY-004: Jenkins Pipeline Injection
var (
	shGString       = regexp.MustCompile(`sh\s*(?:\(\s*)?"[^"]*\$\{`)
	shTripleGString = regexp.MustCompile(`sh\s*(?:\(\s*)?"""[^"]*\$\{`)
	batGString      = regexp.MustCompile(`bat\s*(?:\(\s*)?"[^"]*\$\{`)
	loadVariable    = regexp.MustCompile(`load\s+\$\{|load\s*\(\s*\$\{`)
	shScriptGString = regexp.MustCompile(`sh\s*\(\s*script\s*:\s*"[^"]*\$\{`)
)

// GVY-005: GString Injection in security-sensitive contexts
var (
	gstringInSQL  = regexp.MustCompile(`(?:execute|query|rows|firstRow)\s*\(\s*"[^"]*\$\{`)
	gstringInLDAP = regexp.MustCompile(`(?:search|lookup|bind)\s*\(\s*"[^"]*\$\{`)
)

// GVY-006: Grails Mass Assignment
var (
	newDomainParams    = regexp.MustCompile(`new\s+\w+\s*\(\s*params\s*\)`)
	domainProperties   = regexp.MustCompile(`\w+\.properties\s*=\s*params`)
	bindDataParams     = regexp.MustCompile(`bindData\s*\(\s*\w+\s*,\s*params\s*\)`)
	allowedFieldsCheck = regexp.MustCompile(`allowedFields|bindData\s*\(\s*\w+\s*,\s*params\s*,\s*\[`)
	commandObject      = regexp.MustCompile(`@Validateable|class\s+\w+Command\b`)
)

// GVY-007: XXE via XmlSlurper/XmlParser
var (
	xmlSlurperNew = regexp.MustCompile(`new\s+XmlSlurper\s*\(\s*\)`)
	xmlParserNew  = regexp.MustCompile(`new\s+XmlParser\s*\(\s*\)`)
	xxeProtection = regexp.MustCompile(`disallow-doctype-decl|FEATURE_SECURE_PROCESSING|setFeature`)
)

// GVY-008: Insecure Deserialization
var (
	objectInputStream = regexp.MustCompile(`new\s+ObjectInputStream\s*\(|ObjectInputStream.*\.readObject\s*\(`)
	xstreamFromXML    = regexp.MustCompile(`XStream\s*\(\s*\)\s*\.fromXML\s*\(|xstream\.fromXML\s*\(`)
	snakeYAMLLoad     = regexp.MustCompile(`new\s+Yaml\s*\(\s*\)\s*\.load\s*\(|yaml\.load\s*\(`)
)

// GVY-009: Jenkins Credentials Leak
var (
	credentialsInSh   = regexp.MustCompile(`sh\s*(?:\(\s*)?"[^"]*\$\{.*(?:PASSWORD|TOKEN|SECRET|CREDENTIAL|API_KEY)`)
	credentialsInEcho = regexp.MustCompile(`echo\s+"[^"]*\$\{.*(?:PASSWORD|TOKEN|SECRET|CREDENTIAL|API_KEY)`)
	credentialsPrint  = regexp.MustCompile(`println?\s*\(?\s*.*(?:PASSWORD|TOKEN|SECRET|CREDENTIAL|API_KEY)`)
	withCredentials   = regexp.MustCompile(`withCredentials\s*\(`)
)

// GVY-010: Grails XSS
var (
	gspRawOutput    = regexp.MustCompile(`\$\{[^}]+\}`)
	gspRawMethod    = regexp.MustCompile(`\.raw\s*\(`)
	encodeAsHTML    = regexp.MustCompile(`encodeAsHTML`)
	gspDefaultCodec = regexp.MustCompile(`defaultCodec\s*=\s*["']HTML["']|grails\.views\.default\.codec\s*=\s*["']html["']`)
)

func init() {
	rules.Register(&CommandInjection{})
	rules.Register(&CodeInjection{})
	rules.Register(&SQLInjection{})
	rules.Register(&JenkinsPipelineInjection{})
	rules.Register(&GStringInjection{})
	rules.Register(&GrailsMassAssignment{})
	rules.Register(&XXEViaXmlSlurper{})
	rules.Register(&InsecureDeserialization{})
	rules.Register(&JenkinsCredentialsLeak{})
	rules.Register(&GrailsXSS{})
}

// --- GVY-001: Command Injection ---

type CommandInjection struct{}

func (r *CommandInjection) ID() string                      { return "GTSS-GVY-001" }
func (r *CommandInjection) Name() string                    { return "GroovyCommandInjection" }
func (r *CommandInjection) Description() string             { return "Detects command injection via Groovy's String.execute(), Runtime.exec, or ProcessBuilder with user-controlled input." }
func (r *CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CommandInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := gstringExecute.FindString(line); loc != "" {
			matched = loc
			desc = "GString interpolation in .execute()"
		} else if loc := listExecute.FindString(line); loc != "" {
			matched = loc
			desc = "List.execute() command execution"
		} else if loc := runtimeExec.FindString(line); loc != "" {
			matched = loc
			desc = "Runtime.exec() command execution"
		} else if loc := processBuilderRe.FindString(line); loc != "" {
			matched = loc
			desc = "ProcessBuilder command execution"
		} else if loc := stringExecute.FindString(line); loc != "" {
			// Static string execute is lower risk, check for variable involvement
			context := surroundingContext(lines, i, 3)
			if strings.Contains(context, "+") || strings.Contains(context, "${") {
				matched = loc
				desc = "String.execute() with dynamic content"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Command injection via " + desc,
				Description:   "Groovy's .execute() method and Runtime.exec/ProcessBuilder run OS commands. When command strings include user-controlled data, attackers can inject arbitrary commands leading to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid using .execute() with dynamic strings. Use ProcessBuilder with a fixed command array, or validate/sanitize all user input. Never interpolate GStrings into command strings.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "command-injection", "rce"},
			})
		}
	}

	return findings
}

// --- GVY-002: Code Injection ---

type CodeInjection struct{}

func (r *CodeInjection) ID() string                      { return "GTSS-GVY-002" }
func (r *CodeInjection) Name() string                    { return "GroovyCodeInjection" }
func (r *CodeInjection) Description() string             { return "Detects code injection via GroovyShell.evaluate, Eval.me, and GroovyScriptEngine with user-controlled input." }
func (r *CodeInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CodeInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *CodeInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := groovyShellEvaluate.FindString(line); loc != "" {
			matched = loc
			desc = "GroovyShell.evaluate()"
		} else if loc := groovyShellParse.FindString(line); loc != "" {
			matched = loc
			desc = "GroovyShell.parse()"
		} else if loc := evalMe.FindString(line); loc != "" {
			matched = loc
			desc = "Eval.me()"
		} else if loc := groovyScriptEngine.FindString(line); loc != "" {
			matched = loc
			desc = "GroovyScriptEngine/ScriptEngine eval"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Code injection via " + desc,
				Description:   "Dynamic Groovy code evaluation allows arbitrary code execution. If the evaluated string contains user-controlled data, an attacker can execute arbitrary Groovy code on the server, leading to full system compromise.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid evaluating dynamic Groovy code from user input. Use a Groovy sandbox (SecureASTCustomizer, CompilerConfiguration) if dynamic evaluation is required. Consider using a DSL or predefined operations instead.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "code-injection", "rce"},
			})
		}
	}

	return findings
}

// --- GVY-003: SQL Injection ---

type SQLInjection struct{}

func (r *SQLInjection) ID() string                      { return "GTSS-GVY-003" }
func (r *SQLInjection) Name() string                    { return "GroovySQLInjection" }
func (r *SQLInjection) Description() string             { return "Detects SQL injection via GString interpolation or string concatenation in Groovy SQL methods." }
func (r *SQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SQLInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *SQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := sqlExecuteGString.FindString(line); loc != "" {
			matched = loc
			desc = "sql.execute() with GString interpolation"
		} else if loc := sqlRowsGString.FindString(line); loc != "" {
			matched = loc
			desc = "sql.rows() with GString interpolation"
		} else if loc := sqlFirstRowGString.FindString(line); loc != "" {
			matched = loc
			desc = "sql.firstRow() with GString interpolation"
		} else if loc := sqlEachRowGString.FindString(line); loc != "" {
			matched = loc
			desc = "sql.eachRow() with GString interpolation"
		} else if loc := sqlUpdateGString.FindString(line); loc != "" {
			matched = loc
			desc = "sql.executeUpdate() with GString interpolation"
		} else if loc := sqlExecuteConcat.FindString(line); loc != "" {
			matched = loc
			desc = "sql.execute() with string concatenation"
		} else if loc := sqlRowsConcat.FindString(line); loc != "" {
			matched = loc
			desc = "sql.rows() with string concatenation"
		} else if loc := sqlFirstRowConcat.FindString(line); loc != "" {
			matched = loc
			desc = "sql.firstRow() with string concatenation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQL injection via " + desc,
				Description:   "Groovy GString interpolation (${}) in SQL queries embeds values directly into the SQL string without parameterization. This allows SQL injection attacks. Note: Groovy's Sql class automatically parameterizes GStrings only when passed directly, but string concatenation always bypasses this.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries with Groovy SQL: sql.rows(\"SELECT * FROM users WHERE id = ?\", [userId]) or use GString parameters that Groovy Sql auto-parameterizes: sql.rows(\"SELECT * FROM users WHERE id = ${userId}\") only when passed directly to Sql methods (not pre-built strings).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "sql-injection", "gstring"},
			})
		}
	}

	return findings
}

// --- GVY-004: Jenkins Pipeline Injection ---

type JenkinsPipelineInjection struct{}

func (r *JenkinsPipelineInjection) ID() string                      { return "GTSS-GVY-004" }
func (r *JenkinsPipelineInjection) Name() string                    { return "JenkinsPipelineInjection" }
func (r *JenkinsPipelineInjection) Description() string             { return "Detects Jenkins pipeline script injection via GString interpolation in sh/bat steps or unsafe load." }
func (r *JenkinsPipelineInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JenkinsPipelineInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *JenkinsPipelineInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := shTripleGString.FindString(line); loc != "" {
			matched = loc
			desc = "sh step with GString interpolation (triple-quoted)"
		} else if loc := shScriptGString.FindString(line); loc != "" {
			matched = loc
			desc = "sh script parameter with GString interpolation"
		} else if loc := shGString.FindString(line); loc != "" {
			matched = loc
			desc = "sh step with GString interpolation"
		} else if loc := batGString.FindString(line); loc != "" {
			matched = loc
			desc = "bat step with GString interpolation"
		} else if loc := loadVariable.FindString(line); loc != "" {
			matched = loc
			desc = "load step with variable path"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Jenkins pipeline injection via " + desc,
				Description:   "GString interpolation in Jenkins sh/bat steps evaluates the variable before passing it to the shell. If the variable contains special characters (;, |, $, `, etc.), an attacker can inject arbitrary shell commands. This is especially dangerous with user-controlled parameters or untrusted branch names.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use single-quoted strings in sh steps to let the shell handle variable expansion: sh 'echo $MY_VAR'. For variables that must be Groovy-interpolated, sanitize them first or use the environment block to pass them safely.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "jenkins", "pipeline-injection"},
			})
		}
	}

	return findings
}

// --- GVY-005: GString Injection ---

type GStringInjection struct{}

func (r *GStringInjection) ID() string                      { return "GTSS-GVY-005" }
func (r *GStringInjection) Name() string                    { return "GStringInjection" }
func (r *GStringInjection) Description() string             { return "Detects GString interpolation used in security-sensitive contexts like SQL, shell commands, or LDAP queries." }
func (r *GStringInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *GStringInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GStringInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := gstringInLDAP.FindString(line); loc != "" {
			matched = loc
			desc = "LDAP query with GString interpolation"
		}

		// Only flag GString in SQL if not already caught by GVY-003
		// This catches patterns like variable assignment then use
		if matched == "" && gstringInSQL.MatchString(line) {
			// Skip if GVY-003 would catch this (direct Sql method calls)
			if !sqlExecuteGString.MatchString(line) &&
				!sqlRowsGString.MatchString(line) &&
				!sqlFirstRowGString.MatchString(line) &&
				!sqlEachRowGString.MatchString(line) &&
				!sqlUpdateGString.MatchString(line) {
				matched = gstringInSQL.FindString(line)
				desc = "SQL-like context with GString interpolation"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GString injection in " + desc,
				Description:   "Groovy GString interpolation (${}) in security-sensitive contexts (SQL, LDAP, shell) embeds values directly without escaping. This can lead to injection attacks when the interpolated values contain user-controlled data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries or proper escaping instead of GString interpolation in security-sensitive contexts. For SQL, use positional parameters (?). For LDAP, use proper LDAP encoding.",
				CWEID:         "CWE-74",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"groovy", "gstring", "injection"},
			})
		}
	}

	return findings
}

// --- GVY-006: Grails Mass Assignment ---

type GrailsMassAssignment struct{}

func (r *GrailsMassAssignment) ID() string                      { return "GTSS-GVY-006" }
func (r *GrailsMassAssignment) Name() string                    { return "GrailsMassAssignment" }
func (r *GrailsMassAssignment) Description() string             { return "Detects Grails mass assignment via direct params binding without allowed fields or command objects." }
func (r *GrailsMassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r *GrailsMassAssignment) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GrailsMassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if file uses command objects or allowedFields
	if allowedFieldsCheck.MatchString(ctx.Content) || commandObject.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := newDomainParams.FindString(line); loc != "" {
			matched = loc
			desc = "domain object created with params"
		} else if loc := domainProperties.FindString(line); loc != "" {
			matched = loc
			desc = "domain properties assigned from params"
		} else if loc := bindDataParams.FindString(line); loc != "" {
			matched = loc
			desc = "bindData with unfiltered params"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Grails mass assignment via " + desc,
				Description:   "Binding HTTP request parameters directly to domain objects without restricting allowed fields enables mass assignment attacks. An attacker can set any domain property (including admin flags, roles, or internal fields) by adding unexpected request parameters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use command objects with @Validateable, or restrict fields with bindData(obj, params, [include: ['name', 'email']]). Alternatively, set static bindable = false on sensitive domain properties.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "grails", "mass-assignment"},
			})
		}
	}

	return findings
}

// --- GVY-007: XXE via XmlSlurper/XmlParser ---

type XXEViaXmlSlurper struct{}

func (r *XXEViaXmlSlurper) ID() string                      { return "GTSS-GVY-007" }
func (r *XXEViaXmlSlurper) Name() string                    { return "XXEViaXmlSlurper" }
func (r *XXEViaXmlSlurper) Description() string             { return "Detects XML parsing via XmlSlurper/XmlParser without disabling external entities (XXE)." }
func (r *XXEViaXmlSlurper) DefaultSeverity() rules.Severity { return rules.High }
func (r *XXEViaXmlSlurper) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *XXEViaXmlSlurper) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if XXE protections are present
	if xxeProtection.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := xmlSlurperNew.FindString(line); loc != "" {
			matched = loc
			desc = "XmlSlurper"
		} else if loc := xmlParserNew.FindString(line); loc != "" {
			matched = loc
			desc = "XmlParser"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE vulnerability via " + desc + " without entity protection",
				Description:   desc + " is instantiated without disabling external entity processing. If the XML input comes from an untrusted source, an attacker can use XXE to read local files, perform SSRF, or cause denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Disable external entities: def slurper = new XmlSlurper(); slurper.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true). Or use SAXParserFactory with FEATURE_SECURE_PROCESSING.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"groovy", "xxe", "xml"},
			})
		}
	}

	return findings
}

// --- GVY-008: Insecure Deserialization ---

type InsecureDeserialization struct{}

func (r *InsecureDeserialization) ID() string                      { return "GTSS-GVY-008" }
func (r *InsecureDeserialization) Name() string                    { return "GroovyInsecureDeserialization" }
func (r *InsecureDeserialization) Description() string             { return "Detects insecure deserialization via ObjectInputStream, XStream, or SnakeYAML in Groovy context." }
func (r *InsecureDeserialization) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *InsecureDeserialization) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *InsecureDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := objectInputStream.FindString(line); loc != "" {
			matched = loc
			desc = "ObjectInputStream deserialization"
		} else if loc := xstreamFromXML.FindString(line); loc != "" {
			matched = loc
			desc = "XStream XML deserialization"
		} else if loc := snakeYAMLLoad.FindString(line); loc != "" {
			// Skip if SafeConstructor is used nearby
			context := surroundingContext(lines, i, 3)
			if !strings.Contains(context, "SafeConstructor") {
				matched = loc
				desc = "SnakeYAML unsafe load"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure deserialization via " + desc,
				Description:   "Deserializing untrusted data can lead to remote code execution. Groovy on the classpath provides additional gadget chains that make exploitation easier. ObjectInputStream, XStream without type restrictions, and SnakeYAML's load() are all dangerous with untrusted input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "For ObjectInputStream: use an allowlist-based ObjectInputFilter (Java 9+). For XStream: call XStream.allowTypes() or use XStream.allowTypesByWildcard(). For SnakeYAML: use new Yaml(new SafeConstructor()) instead of new Yaml().load().",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "deserialization", "rce"},
			})
		}
	}

	return findings
}

// --- GVY-009: Jenkins Credentials Leak ---

type JenkinsCredentialsLeak struct{}

func (r *JenkinsCredentialsLeak) ID() string                      { return "GTSS-GVY-009" }
func (r *JenkinsCredentialsLeak) Name() string                    { return "JenkinsCredentialsLeak" }
func (r *JenkinsCredentialsLeak) Description() string             { return "Detects Jenkins credentials leaked via sh/echo steps or print statements in pipeline scripts." }
func (r *JenkinsCredentialsLeak) DefaultSeverity() rules.Severity { return rules.High }
func (r *JenkinsCredentialsLeak) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *JenkinsCredentialsLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag in files that use withCredentials (indicating credential usage)
	if !withCredentials.MatchString(ctx.Content) && !strings.Contains(ctx.Content, "credentials(") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := credentialsInSh.FindString(line); loc != "" {
			matched = loc
			desc = "credential variable in sh step"
		} else if loc := credentialsInEcho.FindString(line); loc != "" {
			matched = loc
			desc = "credential variable in echo"
		} else if loc := credentialsPrint.FindString(line); loc != "" {
			matched = loc
			desc = "credential variable in print statement"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Jenkins credentials leak via " + desc,
				Description:   "Credentials bound via withCredentials() are being used in sh/echo/print statements where they may be exposed in build logs. Jenkins masks credentials in console output, but echo and sh with set -x can still leak them. Credentials in GStrings are interpolated before masking.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use single-quoted strings in sh steps to prevent Groovy interpolation of credentials: sh 'echo $SECRET_VAR'. Never echo or print credential values. Use the credentials binding plugin and reference credentials only as environment variables within shell steps.",
				CWEID:         "CWE-532",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "jenkins", "credentials", "secret-leak"},
			})
		}
	}

	return findings
}

// --- GVY-010: Grails XSS ---

type GrailsXSS struct{}

func (r *GrailsXSS) ID() string                      { return "GTSS-GVY-010" }
func (r *GrailsXSS) Name() string                    { return "GrailsXSS" }
func (r *GrailsXSS) Description() string             { return "Detects XSS via unescaped output in Grails GSP views using ${} without encodeAsHTML or raw()." }
func (r *GrailsXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *GrailsXSS) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GrailsXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only check GSP-like files or files using Grails view patterns
	isGSP := strings.HasSuffix(ctx.FilePath, ".gsp") ||
		strings.Contains(ctx.Content, "<%@") ||
		strings.Contains(ctx.Content, "<g:") ||
		strings.Contains(ctx.Content, "<!DOCTYPE html")

	if !isGSP {
		return nil
	}

	// If default codec is HTML, ${} is auto-escaped
	if gspDefaultCodec.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) || strings.HasPrefix(trimmed, "<%--") {
			continue
		}

		// Check for raw() usage
		if loc := gspRawMethod.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Grails XSS via raw() output",
				Description:   "The raw() method outputs content without HTML encoding, which can lead to XSS if the content contains user-controlled data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Remove raw() and let Grails auto-encode output, or manually encode with .encodeAsHTML() if raw output is required.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "grails", "xss", "gsp"},
			})
		}

		// Check for ${} in HTML context without encoding
		if gspRawOutput.MatchString(line) && !encodeAsHTML.MatchString(line) {
			// Only in HTML context (check for HTML tags nearby)
			if strings.Contains(line, "<") || strings.Contains(line, ">") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Grails XSS via unescaped ${} in GSP",
					Description:   "The ${} expression in a GSP view outputs data without HTML encoding when the default codec is not set to HTML. User-controlled data rendered this way enables cross-site scripting attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Set grails.views.default.codec = 'html' in Config.groovy, or use ${value.encodeAsHTML()} for explicit encoding. Alternatively, use <g:encodeAs codec='HTML'>${value}</g:encodeAs>.",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"groovy", "grails", "xss", "gsp"},
				})
			}
		}
	}

	return findings
}

// --- Helpers ---

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "#")
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
