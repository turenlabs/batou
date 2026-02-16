package ssti

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-SSTI-001: Jinja2 render_template_string with user input
var (
	reJinja2RenderStr = regexp.MustCompile(`(?i)\brender_template_string\s*\(\s*(?:request\.|user_input|param|data|args|form|f["']|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format\()`)
	reJinja2RenderVar = regexp.MustCompile(`(?i)\brender_template_string\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
)

// BATOU-SSTI-002: Mako Template from string
var (
	reMakoTemplate     = regexp.MustCompile(`(?i)\bTemplate\s*\(\s*(?:request\.|user_input|param|data|f["']|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format\()`)
	reMakoFromString   = regexp.MustCompile(`(?i)(?:mako|mako\.template)\s*\.\s*Template\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
	reMakoTemplateLookup = regexp.MustCompile(`(?i)\bTemplateLookup\b.*\bget_template\s*\(\s*(?:request\.|user_input|param)`)
)

// BATOU-SSTI-003: Twig/Smarty user input in template string (PHP)
var (
	reTwigCreateTemplate = regexp.MustCompile(`(?i)\$twig\s*->\s*createTemplate\s*\(\s*\$(?:_GET|_POST|_REQUEST|input|param|data|user)`)
	reTwigRenderStr      = regexp.MustCompile(`(?i)\$twig\s*->\s*render\s*\(\s*\$(?:_GET|_POST|_REQUEST|input|param|data|user)`)
	reSmartyFetch        = regexp.MustCompile(`(?i)\$smarty\s*->\s*(?:fetch|display)\s*\(\s*["']string:\s*["']\s*\.\s*\$`)
	reTwigFromString     = regexp.MustCompile(`(?i)createTemplate\s*\(\s*["']string:["']\s*\.\s*\$`)
)

// BATOU-SSTI-004: Velocity evaluate with user input
var (
	reVelocityEval = regexp.MustCompile(`(?i)\.evaluate\s*\(\s*[^,]*,\s*[^,]*,\s*[^,]*,\s*(?:request\.getParameter|input|param|userData|userInput)`)
	reVelocityMerge = regexp.MustCompile(`(?i)Velocity\s*\.\s*(?:evaluate|mergeTemplate)\s*\(.*(?:request\.|getParameter|getQueryString)`)
	reVelocityTemplate = regexp.MustCompile(`(?i)new\s+StringResourceLoader\b.*(?:request|param|input|user)`)
)

// BATOU-SSTI-005: Thymeleaf fragment expression injection
var (
	reThymeleafFragment    = regexp.MustCompile(`(?i)(?:return|=)\s*["'][^"']*::.*["']\s*\+\s*(?:request\.getParameter|input|param|user)`)
	reThymeleafExpression  = regexp.MustCompile(`(?i)(?:templateEngine|engine)\s*\.\s*process\s*\(\s*["'][^"']*\$\{.*\}[^"']*["']\s*\+`)
	reThymeleafPreProcess  = regexp.MustCompile(`(?i)__\$\{.*(?:request|param|input|user).*\}__`)
	reThymeleafViewReturn  = regexp.MustCompile(`(?i)(?:return|view\s*=)\s*["'][^"']*["']\s*\+\s*(?:request\.getParameter|getParam|userInput|input)\s*\(`)
)

// BATOU-SSTI-006: Pebble template from user string
var (
	rePebbleLiteral   = regexp.MustCompile(`(?i)\bnew\s+PebbleEngine\b`)
	rePebbleCompile   = regexp.MustCompile(`(?i)\.compileTemplate\s*\(\s*(?:request\.|input|param|user|new\s+StringReader\s*\(\s*(?:request|input|param|user))`)
	rePebbleGetLiteral = regexp.MustCompile(`(?i)pebbleEngine\.getLiteralTemplate\s*\(\s*(?:request\.|input|param|user)`)
)

// BATOU-SSTI-007: Freemarker template from user string
var (
	reFreemarkerNew    = regexp.MustCompile(`(?i)\bnew\s+Template\s*\(\s*["'][^"']*["']\s*,\s*new\s+StringReader\s*\(\s*(?:request\.getParameter|input|param|user)`)
	reFreemarkerParse  = regexp.MustCompile(`(?i)\.(?:putTemplate|getTemplate)\s*\(\s*["'][^"']*["']\s*,\s*(?:request\.|input|param|user)`)
	reFreemarkerFromStr = regexp.MustCompile(`(?i)configuration\s*\.\s*getTemplate\s*\(\s*(?:request|input|param|user)`)
)

// BATOU-SSTI-008: ERB template new with user input (Ruby)
var (
	reERBNew       = regexp.MustCompile(`(?i)\bERB\.new\s*\(\s*(?:params|request|input|user_input|data)`)
	reERBNewConcat = regexp.MustCompile(`(?i)\bERB\.new\s*\(\s*["'][^"']*["']\s*\+`)
	reERBNewInterp = regexp.MustCompile(`\bERB\.new\s*\(\s*"[^"]*#\{`)
	reSlimEval     = regexp.MustCompile(`(?i)\bSlim::Template\.new\s*\(\s*(?:params|request|input)`)
	reHamlEval     = regexp.MustCompile(`(?i)\bHaml::Engine\.new\.render\s*\(\s*(?:params|request|input)`)
)

// BATOU-SSTI-009: Handlebars.compile with user data
var (
	reHandlebarsCompile   = regexp.MustCompile(`(?i)\bHandlebars\.compile\s*\(\s*(?:req\.|request\.|user|input|param|data\b|body\b)`)
	reHandlebarsPrecompile = regexp.MustCompile(`(?i)\bHandlebars\.precompile\s*\(\s*(?:req\.|request\.|user|input|param|data\b)`)
	reHandlebarsTemplate  = regexp.MustCompile(`(?i)\bHandlebars\.template\s*\(\s*(?:req\.|request\.|user|input|param)`)
)

// BATOU-SSTI-010: Nunjucks renderString with user input
var (
	reNunjucksRenderStr = regexp.MustCompile(`(?i)\bnunjucks\.renderString\s*\(\s*(?:req\.|request\.|user|input|param|data\b)`)
	reNunjucksCompile   = regexp.MustCompile(`(?i)\bnunjucks\.compile\s*\(\s*(?:req\.|request\.|user|input|param|data\b)`)
	reNunjucksFromStr   = regexp.MustCompile(`(?i)\bnew\s+nunjucks\.Environment\b`)
)

// BATOU-SSTI-011: Pug/Jade compile with user input
var (
	rePugCompile   = regexp.MustCompile(`(?i)\bpug\.compile\s*\(\s*(?:req\.|request\.|user|input|param|data\b|body\b)`)
	rePugRender    = regexp.MustCompile(`(?i)\bpug\.render\s*\(\s*(?:req\.|request\.|user|input|param|data\b|body\b)`)
	reJadeCompile  = regexp.MustCompile(`(?i)\bjade\.compile\s*\(\s*(?:req\.|request\.|user|input|param|data\b|body\b)`)
	reJadeRender   = regexp.MustCompile(`(?i)\bjade\.render\s*\(\s*(?:req\.|request\.|user|input|param|data\b|body\b)`)
)

// BATOU-SSTI-012: Golang template.New().Parse with user input
var (
	reGoTemplateParse    = regexp.MustCompile(`(?i)template\.(?:New|Must)\s*\([^)]*\)\s*\.\s*Parse\s*\(\s*(?:r\.(?:FormValue|URL\.Query|Body|PostForm)|input|param|user|req\.)`)
	reGoTemplateParseVar = regexp.MustCompile(`(?i)template\.(?:New|Must)\s*\([^)]*\)\s*\.\s*Parse\s*\(\s*[a-zA-Z_]\w*\s*\)`)
	reGoHTMLTemplateParse = regexp.MustCompile(`(?i)(?:html/template|text/template).*\.Parse\s*\(\s*(?:r\.|input|param|user)`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-001: Jinja2 render_template_string with user input
// ---------------------------------------------------------------------------

type Jinja2SSTI struct{}

func (r *Jinja2SSTI) ID() string                     { return "BATOU-SSTI-001" }
func (r *Jinja2SSTI) Name() string                   { return "Jinja2SSTI" }
func (r *Jinja2SSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *Jinja2SSTI) Description() string {
	return "Detects Jinja2 render_template_string called with user-controlled input, enabling server-side template injection and remote code execution."
}
func (r *Jinja2SSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *Jinja2SSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJinja2RenderStr, reJinja2RenderVar} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Jinja2 render_template_string with user input",
					Description:   "render_template_string() renders a Jinja2 template from a string. If this string contains user-controlled input, an attacker can inject Jinja2 expressions like {{config}} or {{''.__class__.__mro__}} to achieve remote code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use render_template() with a file path instead. Pass user data as template variables: render_template('page.html', data=user_input)",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "jinja2", "rce"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-002: Mako template.Template from string
// ---------------------------------------------------------------------------

type MakoSSTI struct{}

func (r *MakoSSTI) ID() string                     { return "BATOU-SSTI-002" }
func (r *MakoSSTI) Name() string                   { return "MakoSSTI" }
func (r *MakoSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *MakoSSTI) Description() string {
	return "Detects Mako Template() instantiated with user-controlled string input, enabling server-side template injection."
}
func (r *MakoSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *MakoSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reMakoTemplate, reMakoFromString, reMakoTemplateLookup} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Mako Template from user-controlled string",
					Description:   "Mako Template() created from a user-controlled string can execute arbitrary Python code via template expressions like ${__import__('os').system('cmd')}.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use Template(filename='template.html') to load from a file path. Pass user data via render() keyword arguments.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "mako", "rce"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-003: Twig/Smarty user input in template string (PHP)
// ---------------------------------------------------------------------------

type TwigSmartySSTI struct{}

func (r *TwigSmartySSTI) ID() string                     { return "BATOU-SSTI-003" }
func (r *TwigSmartySSTI) Name() string                   { return "TwigSmartySSTI" }
func (r *TwigSmartySSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *TwigSmartySSTI) Description() string {
	return "Detects Twig or Smarty template engines rendering user-controlled strings in PHP, enabling server-side template injection."
}
func (r *TwigSmartySSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *TwigSmartySSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reTwigCreateTemplate, reTwigRenderStr, reSmartyFetch, reTwigFromString} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Twig/Smarty template with user input",
					Description:   "Twig or Smarty template engine is rendering a template string that includes user input. An attacker can inject template directives like {{_self.env.registerUndefinedFilterCallback('exec')}} (Twig) or {php}system('cmd'){/php} (Smarty).",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load templates from files, not from user-supplied strings. Pass user data as template variables via the render context.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "twig", "smarty", "php"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-004: Velocity evaluate with user input
// ---------------------------------------------------------------------------

type VelocitySSTI struct{}

func (r *VelocitySSTI) ID() string                     { return "BATOU-SSTI-004" }
func (r *VelocitySSTI) Name() string                   { return "VelocitySSTI" }
func (r *VelocitySSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *VelocitySSTI) Description() string {
	return "Detects Apache Velocity template engine evaluate() or merge with user-controlled input, enabling server-side template injection."
}
func (r *VelocitySSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *VelocitySSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reVelocityEval, reVelocityMerge, reVelocityTemplate} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Velocity evaluate with user input",
					Description:   "Apache Velocity's evaluate() or merge methods with user-controlled templates allow injection of Velocity directives like #set($x='')+#set($rt=$x.class.forName('java.lang.Runtime')) for RCE.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load Velocity templates from files only. Pass user data as VelocityContext values, never as template source code.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "velocity", "java"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-005: Thymeleaf fragment expression injection
// ---------------------------------------------------------------------------

type ThymeleafSSTI struct{}

func (r *ThymeleafSSTI) ID() string                     { return "BATOU-SSTI-005" }
func (r *ThymeleafSSTI) Name() string                   { return "ThymeleafSSTI" }
func (r *ThymeleafSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *ThymeleafSSTI) Description() string {
	return "Detects Thymeleaf template expression injection via fragment expressions, view names, or preprocessing directives with user input."
}
func (r *ThymeleafSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *ThymeleafSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reThymeleafFragment, reThymeleafExpression, reThymeleafPreProcess, reThymeleafViewReturn} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Thymeleaf expression injection",
					Description:   "Thymeleaf fragment expressions, view names, or preprocessing directives (__${...}__) constructed with user input allow injection of SpEL expressions that lead to remote code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Never concatenate user input into Thymeleaf view names or fragment expressions. Use @RequestMapping return values from a fixed set. Avoid __${...}__ preprocessing with user data.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "thymeleaf", "java", "spel"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-006: Pebble template from user string
// ---------------------------------------------------------------------------

type PebbleSSTI struct{}

func (r *PebbleSSTI) ID() string                     { return "BATOU-SSTI-006" }
func (r *PebbleSSTI) Name() string                   { return "PebbleSSTI" }
func (r *PebbleSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *PebbleSSTI) Description() string {
	return "Detects Pebble template engine compiling user-controlled strings, enabling server-side template injection."
}
func (r *PebbleSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *PebbleSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{rePebbleCompile, rePebbleGetLiteral} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Pebble template compiled from user input",
					Description:   "Pebble template engine compiling a user-controlled string allows injection of template expressions for RCE via Java reflection.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load templates from files using PebbleEngine.getTemplate(filename). Pass user data as template context variables.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "pebble", "java"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-007: Freemarker Template from user string
// ---------------------------------------------------------------------------

type FreemarkerSSTI struct{}

func (r *FreemarkerSSTI) ID() string                     { return "BATOU-SSTI-007" }
func (r *FreemarkerSSTI) Name() string                   { return "FreemarkerSSTI" }
func (r *FreemarkerSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *FreemarkerSSTI) Description() string {
	return "Detects FreeMarker Template constructed from user-controlled strings, enabling server-side template injection and RCE."
}
func (r *FreemarkerSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *FreemarkerSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reFreemarkerNew, reFreemarkerParse, reFreemarkerFromStr} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: FreeMarker template from user string",
					Description:   "FreeMarker Template created from user-controlled string allows injection of template directives like <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cmd\")} for remote code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load FreeMarker templates from files using Configuration.getTemplate(filename). Pass user data as the data model, never as template source.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "freemarker", "java"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-008: ERB template new with user input (Ruby)
// ---------------------------------------------------------------------------

type ERBSSTI struct{}

func (r *ERBSSTI) ID() string                     { return "BATOU-SSTI-008" }
func (r *ERBSSTI) Name() string                   { return "ERBSSTI" }
func (r *ERBSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *ERBSSTI) Description() string {
	return "Detects Ruby ERB.new, Slim, or Haml template engines instantiated with user-controlled input, enabling server-side template injection."
}
func (r *ERBSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *ERBSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reERBNew, reERBNewConcat, reERBNewInterp, reSlimEval, reHamlEval} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: ERB/Slim/Haml template from user input",
					Description:   "ERB.new() (or Slim/Haml) with user-controlled input allows injection of Ruby code via <%= %> tags, leading to remote code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load ERB templates from files. Pass user data as binding variables, never as the template source string.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "erb", "ruby"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-009: Handlebars.compile with user data
// ---------------------------------------------------------------------------

type HandlebarsSSTI struct{}

func (r *HandlebarsSSTI) ID() string                     { return "BATOU-SSTI-009" }
func (r *HandlebarsSSTI) Name() string                   { return "HandlebarsSSTI" }
func (r *HandlebarsSSTI) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *HandlebarsSSTI) Description() string {
	return "Detects Handlebars.compile or precompile called with user-controlled input, which can lead to template injection."
}
func (r *HandlebarsSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *HandlebarsSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reHandlebarsCompile, reHandlebarsPrecompile, reHandlebarsTemplate} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Handlebars.compile with user data",
					Description:   "Handlebars.compile() with user input as the template source can lead to prototype pollution and information disclosure. Custom helpers may enable further exploitation.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Precompile Handlebars templates at build time. Never pass user input as the template source. Pass user data as the context object to the compiled template.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"ssti", "template-injection", "handlebars"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-010: Nunjucks renderString with user input
// ---------------------------------------------------------------------------

type NunjucksSSTI struct{}

func (r *NunjucksSSTI) ID() string                     { return "BATOU-SSTI-010" }
func (r *NunjucksSSTI) Name() string                   { return "NunjucksSSTI" }
func (r *NunjucksSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *NunjucksSSTI) Description() string {
	return "Detects Nunjucks renderString or compile called with user-controlled input, enabling server-side template injection."
}
func (r *NunjucksSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NunjucksSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reNunjucksRenderStr, reNunjucksCompile} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Nunjucks renderString with user input",
					Description:   "nunjucks.renderString() or nunjucks.compile() with user-controlled input allows injection of Nunjucks template expressions that can access server-side objects and execute code.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use nunjucks.render() with a file path. Pass user data as template context variables, never as the template string itself.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "nunjucks"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-011: Pug/Jade compile with user input
// ---------------------------------------------------------------------------

type PugSSTI struct{}

func (r *PugSSTI) ID() string                     { return "BATOU-SSTI-011" }
func (r *PugSSTI) Name() string                   { return "PugSSTI" }
func (r *PugSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *PugSSTI) Description() string {
	return "Detects Pug (Jade) compile or render called with user-controlled input, enabling server-side template injection."
}
func (r *PugSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PugSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{rePugCompile, rePugRender, reJadeCompile, reJadeRender} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Pug/Jade compile with user input",
					Description:   "pug.compile() or pug.render() with user-controlled template source allows injection of Pug code including unbuffered code blocks (- var x = ...) for server-side code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use pug.renderFile() with a file path. Pass user data as template locals, never as the template source string.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "pug", "jade"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SSTI-012: Golang template.New().Parse with user input
// ---------------------------------------------------------------------------

type GoTemplateSSTI struct{}

func (r *GoTemplateSSTI) ID() string                     { return "BATOU-SSTI-012" }
func (r *GoTemplateSSTI) Name() string                   { return "GoTemplateSSTI" }
func (r *GoTemplateSSTI) DefaultSeverity() rules.Severity { return rules.High }
func (r *GoTemplateSSTI) Description() string {
	return "Detects Go template.New().Parse() called with user-controlled input, enabling server-side template injection via Go template actions."
}
func (r *GoTemplateSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangGo}
}

func (r *GoTemplateSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reGoTemplateParse, reGoHTMLTemplateParse} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSTI: Go template.Parse with user input",
					Description:   "template.New().Parse() with user-controlled input allows injection of Go template actions. With text/template, attackers can call arbitrary methods on objects passed to Execute(). Even html/template only escapes HTML, not template directives.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load templates from files using template.ParseFiles() or template.ParseGlob(). Pass user data via the data parameter of Execute(), never as the template source.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ssti", "template-injection", "go"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&Jinja2SSTI{})
	rules.Register(&MakoSSTI{})
	rules.Register(&TwigSmartySSTI{})
	rules.Register(&VelocitySSTI{})
	rules.Register(&ThymeleafSSTI{})
	rules.Register(&PebbleSSTI{})
	rules.Register(&FreemarkerSSTI{})
	rules.Register(&ERBSSTI{})
	rules.Register(&HandlebarsSSTI{})
	rules.Register(&NunjucksSSTI{})
	rules.Register(&PugSSTI{})
	rules.Register(&GoTemplateSSTI{})
}
