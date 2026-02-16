package groovy

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Groovy extension rules (GTSS-GVY-011 .. GTSS-GVY-016)
// ---------------------------------------------------------------------------

// GVY-011: GroovyShell.evaluate with user input
var (
	reShellEvalUserInput = regexp.MustCompile(`(?:shell|groovyShell|gshell)\s*\.\s*evaluate\s*\(\s*(?:params|request|input|body|data|payload)`)
	reShellEvalGString   = regexp.MustCompile(`(?:shell|groovyShell|gshell)\s*\.\s*evaluate\s*\(\s*"[^"]*\$\{`)
	reShellEvalConcat    = regexp.MustCompile(`(?:shell|groovyShell|gshell)\s*\.\s*evaluate\s*\(\s*"[^"]*"\s*\+`)
	reNewShellEval       = regexp.MustCompile(`new\s+GroovyShell\s*\(\s*\)\s*\.\s*evaluate\s*\(\s*(?:[a-zA-Z_]\w*|"[^"]*\$\{)`)
)

// GVY-012: GString SQL injection (interpolated GString in query)
var (
	reGStringSQLVar      = regexp.MustCompile(`(?i)(?:execute|rows|firstRow|eachRow|executeUpdate)\s*\(\s*\$?"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+[^"]*\$\{`)
	reGStringSQLPrebuilt = regexp.MustCompile(`(?i)(?:def|String|var)\s+\w+\s*=\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*\$\{`)
)

// GVY-013: @Grab with untrusted coordinates
var (
	reGrabAnnotation     = regexp.MustCompile(`@Grab\s*\(`)
	reGrabVar            = regexp.MustCompile(`@Grab\s*\(\s*(?:group\s*=\s*|module\s*=\s*|version\s*=\s*)?\s*(?:\$\{|[a-zA-Z_]\w*\s*[,)])`)
	reGrabStringInterp   = regexp.MustCompile(`@Grab\s*\(\s*(?:group|module|version)\s*=\s*"[^"]*\$\{`)
	reGrabWithResolver   = regexp.MustCompile(`@GrabResolver\s*\(\s*(?:root|name)\s*=`)
)

// GVY-014: Jenkins Groovy sandbox escape
var (
	reSandboxEscape      = regexp.MustCompile(`\.class\.forName\s*\(|\.getClass\s*\(\s*\)\s*\.forName|java\.lang\.Runtime`)
	reMetaClass          = regexp.MustCompile(`\.metaClass\s*\.\s*(?:invokeMethod|getProperty)|\.metaClass\s*=`)
	reGetDeclared        = regexp.MustCompile(`\.getDeclaredMethod|\.getDeclaredField|\.getDeclaredConstructor`)
	reReflectionAccess   = regexp.MustCompile(`java\.lang\.reflect\.|AccessibleObject\.setAccessible`)
)

// GVY-015: GroovyClassLoader with user input
var (
	reClassLoaderNew     = regexp.MustCompile(`new\s+GroovyClassLoader\s*\(`)
	reClassLoaderParse   = regexp.MustCompile(`(?:classLoader|gcl|loader)\s*\.\s*parseClass\s*\(\s*(?:[a-zA-Z_]\w*|"[^"]*\$\{)`)
	reClassLoaderLoad    = regexp.MustCompile(`(?:classLoader|gcl|loader)\s*\.\s*loadClass\s*\(\s*(?:[a-zA-Z_]\w*|"[^"]*\$\{)`)
)

// GVY-016: XmlSlurper without DTD protection (different from GVY-007)
var (
	reXmlSlurperParse     = regexp.MustCompile(`(?:xmlSlurper|slurper|parser)\s*\.\s*parse(?:Text)?\s*\(`)
	reXmlSlurperNoFeature = regexp.MustCompile(`new\s+XmlSlurper\s*\(\s*(?:false\s*,\s*false|true\s*,\s*false)`)
	reExternalEntityProt  = regexp.MustCompile(`(?i)disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|external-parameter-entities`)
)

func init() {
	rules.Register(&GroovyShellEvalUser{})
	rules.Register(&GroovyGStringSQLInj{})
	rules.Register(&GroovyGrabUntrusted{})
	rules.Register(&GroovyJenkinsSandboxEscape{})
	rules.Register(&GroovyClassLoaderUser{})
	rules.Register(&GroovyXmlSlurperDTD{})
}

// ---------------------------------------------------------------------------
// GTSS-GVY-011: Groovy GroovyShell.evaluate with user input
// ---------------------------------------------------------------------------

type GroovyShellEvalUser struct{}

func (r *GroovyShellEvalUser) ID() string                      { return "GTSS-GVY-011" }
func (r *GroovyShellEvalUser) Name() string                    { return "GroovyShellEvalUser" }
func (r *GroovyShellEvalUser) Description() string             { return "Detects Groovy GroovyShell.evaluate() with user-controlled input (params, request, GString interpolation), enabling arbitrary code execution." }
func (r *GroovyShellEvalUser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *GroovyShellEvalUser) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GroovyShellEvalUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string

		if m := reShellEvalUserInput.FindString(line); m != "" {
			matched = m
		} else if m := reShellEvalGString.FindString(line); m != "" {
			matched = m
		} else if m := reShellEvalConcat.FindString(line); m != "" {
			matched = m
		} else if m := reNewShellEval.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Groovy GroovyShell.evaluate() with user input",
				Description:   "GroovyShell.evaluate() compiles and executes arbitrary Groovy code. If the evaluated string includes user-controlled data (params, request body, GString interpolation), an attacker can execute arbitrary code on the server, access the filesystem, or pivot to other systems.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user-controlled data to GroovyShell.evaluate(). Use a Groovy sandbox with SecureASTCustomizer and CompilerConfiguration to restrict allowed operations. Consider using a DSL or predefined operations instead of dynamic evaluation.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "groovyshell", "code-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-GVY-012: Groovy GString SQL injection
// ---------------------------------------------------------------------------

type GroovyGStringSQLInj struct{}

func (r *GroovyGStringSQLInj) ID() string                      { return "GTSS-GVY-012" }
func (r *GroovyGStringSQLInj) Name() string                    { return "GroovyGStringSQLInj" }
func (r *GroovyGStringSQLInj) Description() string             { return "Detects Groovy GString interpolation (${}) in SQL queries including pre-built query strings with SQL keywords." }
func (r *GroovyGStringSQLInj) DefaultSeverity() rules.Severity { return rules.High }
func (r *GroovyGStringSQLInj) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GroovyGStringSQLInj) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reGStringSQLVar.FindString(line); m != "" {
			matched = m
			desc = "GString interpolation (${}) is used directly in a Groovy SQL method call with SQL keywords. The interpolated values are embedded directly into the SQL string."
		} else if m := reGStringSQLPrebuilt.FindString(line); m != "" {
			matched = m
			desc = "A SQL query string with GString interpolation (${}) is pre-built in a variable. When this variable is passed to a SQL method, Groovy's auto-parameterization does not apply because the interpolation has already occurred."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Groovy GString SQL injection",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries: sql.rows(\"SELECT * FROM users WHERE id = ?\", [userId]). Note that Groovy Sql auto-parameterizes GStrings ONLY when passed directly to Sql methods, not pre-built. Build the query directly in the method call.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "gstring", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-GVY-013: Groovy @Grab with untrusted coordinates
// ---------------------------------------------------------------------------

type GroovyGrabUntrusted struct{}

func (r *GroovyGrabUntrusted) ID() string                      { return "GTSS-GVY-013" }
func (r *GroovyGrabUntrusted) Name() string                    { return "GroovyGrabUntrusted" }
func (r *GroovyGrabUntrusted) Description() string             { return "Detects Groovy @Grab annotation with variable or interpolated coordinates that could load malicious dependencies." }
func (r *GroovyGrabUntrusted) DefaultSeverity() rules.Severity { return rules.High }
func (r *GroovyGrabUntrusted) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GroovyGrabUntrusted) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reGrabAnnotation.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string

		if m := reGrabVar.FindString(line); m != "" {
			matched = m
		} else if m := reGrabStringInterp.FindString(line); m != "" {
			matched = m
		} else if m := reGrabWithResolver.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Groovy @Grab with untrusted coordinates",
				Description:   "@Grab dynamically downloads and loads JAR dependencies at runtime. If the group, module, version, or resolver is user-controlled or comes from untrusted config, an attacker can inject a malicious dependency that executes arbitrary code when loaded.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use hardcoded @Grab coordinates only. Never use variables or GString interpolation in @Grab parameters. Use @GrabResolver only with trusted, internal repositories. Consider pre-loading dependencies via build tools (Gradle, Maven) instead.",
				CWEID:         "CWE-829",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "grab", "dependency-injection", "supply-chain"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-GVY-014: Jenkins Groovy sandbox escape patterns
// ---------------------------------------------------------------------------

type GroovyJenkinsSandboxEscape struct{}

func (r *GroovyJenkinsSandboxEscape) ID() string                      { return "GTSS-GVY-014" }
func (r *GroovyJenkinsSandboxEscape) Name() string                    { return "GroovyJenkinsSandboxEscape" }
func (r *GroovyJenkinsSandboxEscape) Description() string             { return "Detects Jenkins Groovy sandbox escape patterns: reflection, metaClass manipulation, Class.forName, and getDeclaredMethod." }
func (r *GroovyJenkinsSandboxEscape) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *GroovyJenkinsSandboxEscape) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GroovyJenkinsSandboxEscape) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reSandboxEscape.FindString(line); m != "" {
			matched = m
			desc = "Class.forName() or Runtime access in Groovy script. This is a common Jenkins sandbox escape technique that accesses restricted classes to execute arbitrary commands."
		} else if m := reMetaClass.FindString(line); m != "" {
			matched = m
			desc = "MetaClass manipulation (invokeMethod, setProperty, metaClass=) can be used to bypass Groovy sandbox restrictions by dynamically modifying class behavior at runtime."
		} else if m := reGetDeclared.FindString(line); m != "" {
			matched = m
			desc = "getDeclaredMethod/Field/Constructor is a reflection technique used to access private members. In Jenkins, this can bypass sandbox restrictions to access Runtime.exec() or ProcessBuilder."
		} else if m := reReflectionAccess.FindString(line); m != "" {
			matched = m
			desc = "Java reflection API (java.lang.reflect, setAccessible) is used to bypass access controls. In Jenkins, this is a known sandbox escape vector."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Jenkins Groovy sandbox escape pattern",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Move sensitive operations to shared libraries (@Library) that run outside the sandbox. Use script approval for trusted scripts. Audit all Groovy scripts for reflection, metaClass manipulation, and Class.forName usage.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "jenkins", "sandbox-escape", "reflection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-GVY-015: Groovy new GroovyClassLoader with user input
// ---------------------------------------------------------------------------

type GroovyClassLoaderUser struct{}

func (r *GroovyClassLoaderUser) ID() string                      { return "GTSS-GVY-015" }
func (r *GroovyClassLoaderUser) Name() string                    { return "GroovyClassLoaderUser" }
func (r *GroovyClassLoaderUser) Description() string             { return "Detects Groovy GroovyClassLoader.parseClass/loadClass with user input, enabling arbitrary class loading and code execution." }
func (r *GroovyClassLoaderUser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *GroovyClassLoaderUser) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GroovyClassLoaderUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reClassLoaderNew.MatchString(ctx.Content) && !strings.Contains(ctx.Content, "GroovyClassLoader") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reClassLoaderParse.FindString(line); m != "" {
			matched = m
			desc = "GroovyClassLoader.parseClass() compiles Groovy source code into a class. If the source is user-controlled, arbitrary code runs during class loading (static initializers, @Grab)."
		} else if m := reClassLoaderLoad.FindString(line); m != "" {
			matched = m
			desc = "GroovyClassLoader.loadClass() with a dynamic class name. If the class name is user-controlled, an attacker can load dangerous classes from the classpath."
		} else if reClassLoaderNew.MatchString(line) {
			matched = strings.TrimSpace(line)
			desc = "GroovyClassLoader instantiation. If this class loader is used to parse or load user-controlled code, it enables arbitrary code execution."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Groovy GroovyClassLoader with user input",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never parse or load user-controlled code via GroovyClassLoader. Use a Groovy sandbox with SecureASTCustomizer if dynamic class loading is required. Restrict the classpath and use a security manager.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"groovy", "classloader", "code-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-GVY-016: Groovy XmlSlurper without DTD protection
// ---------------------------------------------------------------------------

type GroovyXmlSlurperDTD struct{}

func (r *GroovyXmlSlurperDTD) ID() string                      { return "GTSS-GVY-016" }
func (r *GroovyXmlSlurperDTD) Name() string                    { return "GroovyXmlSlurperDTD" }
func (r *GroovyXmlSlurperDTD) Description() string             { return "Detects Groovy XmlSlurper parsing user input without disabling external entity processing (XXE)." }
func (r *GroovyXmlSlurperDTD) DefaultSeverity() rules.Severity { return rules.High }
func (r *GroovyXmlSlurperDTD) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }

func (r *GroovyXmlSlurperDTD) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if protections are present
	if reExternalEntityProt.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if m := reXmlSlurperNoFeature.FindString(line); m != "" {
			matched = m
			desc = "XmlSlurper is created with namespace/validation disabled but no external entity protection. This configuration allows XXE attacks when parsing untrusted XML."
		} else if reXmlSlurperParse.MatchString(line) && !reExternalEntityProt.MatchString(ctx.Content) {
			matched = strings.TrimSpace(line)
			desc = "XmlSlurper.parse/parseText is called without verifying that external entity processing is disabled. If the XML input is from an untrusted source, XXE attacks can read local files, perform SSRF, or cause denial of service."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Groovy XmlSlurper without DTD/entity protection",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Configure XmlSlurper to disable external entities: def slurper = new XmlSlurper(); slurper.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); slurper.setFeature(\"http://xml.org/sax/features/external-general-entities\", false).",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"groovy", "xxe", "xml", "dtd"},
			})
		}
	}
	return findings
}
