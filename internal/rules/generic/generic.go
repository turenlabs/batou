package generic

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-GEN-001: Debug mode patterns
var (
	reDjangoDebug   = regexp.MustCompile(`(?i)DEBUG\s*=\s*True`)
	reFlaskDebug    = regexp.MustCompile(`(?i)app\.debug\s*=\s*True`)
	reFlaskRunDebug = regexp.MustCompile(`app\.run\s*\([^)]*debug\s*=\s*True`)
	reGinDebugMode  = regexp.MustCompile(`gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)`)
	reNodeDebug     = regexp.MustCompile(`(?i)NODE_ENV\s*(?:!==?|!=)\s*['"]production['"]`)
	reRailsDevMode  = regexp.MustCompile(`(?i)config\.consider_all_requests_local\s*=\s*true`)
	reLaravelDebug  = regexp.MustCompile(`(?i)APP_DEBUG\s*=\s*true`)
	reSpringDebug   = regexp.MustCompile(`(?i)spring\.profiles\.active\s*=\s*dev`)
)

// GTSS-GEN-002: Unsafe deserialization patterns
var (
	rePickleLoads       = regexp.MustCompile(`(?:c?[Pp]ickle|_pickle|dill|cloudpickle)\.loads?\s*\(`)
	reYAMLUnsafe        = regexp.MustCompile(`yaml\.load\s*\(`)
	reYAMLSafeLoader    = regexp.MustCompile(`Loader\s*=\s*(?:yaml\.)?SafeLoader`)
	reYAMLFullLoader    = regexp.MustCompile(`Loader\s*=\s*(?:yaml\.)?FullLoader`)
	reJavaObjectStream  = regexp.MustCompile(`(?:new\s+)?ObjectInputStream\s*\(`)
	reRubyMarshalLoad   = regexp.MustCompile(`Marshal\.load\s*\(`)
	rePHPUnserialize    = regexp.MustCompile(`unserialize\s*\(`)
	reNodeSerialize     = regexp.MustCompile(`(?:node-serialize|serialize)\.unserialize\s*\(`)
	rePickleUnpickler   = regexp.MustCompile(`Unpickler\s*\(`)
	// JS/TS: eval() with variable (not string literal) — code injection/deserialization
	reJSEval            = regexp.MustCompile(`\beval\s*\(\s*[a-zA-Z_]\w*`)
	// JS/TS: new Function() with variable — code injection
	reJSNewFunction     = regexp.MustCompile(`\bnew\s+Function\s*\(`)
	// JS/TS: vm.runInNewContext / vm.runInThisContext with variable
	reJSVMRun           = regexp.MustCompile(`\bvm\.run(?:In(?:New|This)?Context)\s*\(\s*[a-zA-Z_]\w*`)
)

// GTSS-GEN-003: XXE patterns
var (
	rePythonXMLParse     = regexp.MustCompile(`xml\.(?:etree|dom|sax|parsers)`)
	reDefusedXML         = regexp.MustCompile(`defusedxml`)
	reJavaDocBuilder     = regexp.MustCompile(`DocumentBuilderFactory`)
	reJavaDisallowDTD    = regexp.MustCompile(`disallow-doctype-decl.*true|FEATURE_SECURE_PROCESSING.*true`)
	reGoXMLDecoder       = regexp.MustCompile(`xml\.NewDecoder\s*\(`)
	rePHPLoadXML         = regexp.MustCompile(`(?:simplexml_load_string|simplexml_load_file|DOMDocument.*loadXML|DOMDocument.*load)\s*\(`)
	rePHPDisableEntities = regexp.MustCompile(`libxml_disable_entity_loader\s*\(\s*true\s*\)`)
	reCSharpXMLReader    = regexp.MustCompile(`XmlReader\.Create|XmlDocument\(\)`)
	reCSharpDtdProhibit  = regexp.MustCompile(`DtdProcessing\.Prohibit|ProhibitDtd\s*=\s*true`)
)

// GTSS-GEN-004: Open redirect patterns
var (
	rePyRedirect    = regexp.MustCompile(`redirect\s*\(\s*request\.(?:args|GET|POST|params)`)
	reJSRedirect    = regexp.MustCompile(`res\.redirect\s*\(\s*req\.(?:query|params|body)`)
	// Go: http.Redirect with direct user input reference
	reGoRedirect    = regexp.MustCompile(`http\.Redirect\s*\([^,]+,[^,]+,\s*r\.(?:URL\.Query\(\)|FormValue|Form\.Get)`)
	// Go: http.Redirect with variable — needs nearby user input source
	reGoRedirectVar = regexp.MustCompile(`http\.Redirect\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*`)
	// JS: res.redirect with variable — needs nearby user input source
	reJSRedirectVar = regexp.MustCompile(`res\.redirect\s*\(\s*[a-zA-Z_]\w*`)
	rePHPRedirect   = regexp.MustCompile(`header\s*\(\s*['"]Location:\s*['"]?\s*\.\s*\$_(?:GET|POST|REQUEST)`)
	reRubyRedirect  = regexp.MustCompile(`redirect_to\s+params\[`)
	reJavaRedirect  = regexp.MustCompile(`sendRedirect\s*\(\s*request\.getParameter`)
	reGenericRedirect = regexp.MustCompile(`(?i)(?:redirect|location)\s*(?:=|:)\s*(?:req|request)\.(?:query|params|body|args|GET|POST)`)
	// Patterns indicating user input source nearby
	reGoUserInputSource = regexp.MustCompile(`r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|Form\.Get)\s*\(`)
	reJSUserInputSource = regexp.MustCompile(`req\.(?:query|params|body)\b`)
)

// GTSS-GEN-005: Log injection patterns
var (
	reGoLogUserInput  = regexp.MustCompile(`(?:log\.(?:Print|Fatal|Panic)(?:f|ln)?\s*\(|logger\.(?:Info|Warn|Error|Debug)(?:f|w)?\s*\().*(?:r\.(?:FormValue|URL\.Query)|req\.)`)
	rePyLogUserInput  = regexp.MustCompile(`(?:logger|logging)\.(?:info|warn|warning|error|debug|critical)\s*\(.*request\.`)
	reJSLogUserInput  = regexp.MustCompile(`console\.(?:log|warn|error|info)\s*\(.*req\.(?:body|query|params)`)
	reGenericLogInput = regexp.MustCompile(`(?:log|logger|logging)\.\w+\s*\(.*(?:user_?input|user_?data|params|request\.|req\.)`)
)

// GTSS-GEN-006: Race condition (TOCTOU) patterns
var (
	reFileExistsCheck   = regexp.MustCompile(`(?:os\.(?:Stat|Lstat|Access)|os\.path\.exists|fs\.(?:exists|existsSync|access|accessSync)|File\.exist\?|file_exists)\s*\(`)
	reFileOperation     = regexp.MustCompile(`(?:os\.(?:Open|Create|Remove|Rename|Chmod|WriteFile|ReadFile)|open\s*\(|fs\.(?:readFile|writeFile|unlink|rename)|File\.(?:open|delete|rename))\s*\(`)
	reGoMutexLock       = regexp.MustCompile(`\.(?:Lock|RLock)\(\)`)
	rePermCheck         = regexp.MustCompile(`(?i)(?:has_?perm|check_?perm|is_?allowed|can_?access|authorize)\s*\(`)
)

// GTSS-GEN-007: Mass assignment patterns
var (
	reGoBindJSON        = regexp.MustCompile(`\.(?:ShouldBindJSON|BindJSON|ShouldBind|Bind)\s*\(\s*&`)
	reGoDecodeBody      = regexp.MustCompile(`\.Decode\s*\(\s*&`)
	reGoNewDecoder      = regexp.MustCompile(`(?:NewDecoder|NewReader)\s*\(\s*r\.Body`)
	reRailsPermitAll    = regexp.MustCompile(`params\.permit!`)
	reRailsPermitLax    = regexp.MustCompile(`\.permit\s*\(\s*!\s*\)`)
	reDjangoExcludeNone = regexp.MustCompile(`exclude\s*=\s*\[\s*\]`)
	reDjangoFieldsAll   = regexp.MustCompile(`fields\s*=\s*['"]__all__['"]`)
	reJSSpreadBody      = regexp.MustCompile(`\{\s*\.\.\.req\.body\s*\}`)
	reGoStructTag       = regexp.MustCompile(`json:"-"`)
)

// GTSS-GEN-008: Code-as-string analysis — dangerous calls inside eval/vm string args
var (
	// Matches vm.runInContext / vm.runInNewContext / eval / new Function containing dangerous calls in the string arg
	reVMRunDangerous = regexp.MustCompile(`(?i)vm\.run(?:In(?:New)?Context|InThisContext)\s*\(\s*['"].*(?:yaml\.(?:unsafe_)?load|parseXml|pickle\.loads?|marshal\.load|unserialize|\.exec\s*\(|\.system\s*\(|Command\s*\()`)
	reEvalDangerous  = regexp.MustCompile(`(?i)\beval\s*\(\s*['"].*(?:yaml\.(?:unsafe_)?load|parseXml|pickle\.loads?|marshal\.load|unserialize|\.exec\s*\(|\.system\s*\(|Command\s*\()`)
	reFuncCtorDanger = regexp.MustCompile(`(?i)\bnew\s+Function\s*\(\s*['"].*(?:yaml\.(?:unsafe_)?load|parseXml|pickle\.loads?|marshal\.load|unserialize|\.exec\s*\(|\.system\s*\(|Command\s*\()`)
	// Template-literal variant (backtick strings)
	reVMRunDangerousBT = regexp.MustCompile("(?i)vm\\.run(?:In(?:New)?Context|InThisContext)\\s*\\(\\s*`[^`]*(?:yaml\\.(?:unsafe_)?load|parseXml|pickle\\.loads?|marshal\\.load|unserialize|\\.exec\\s*\\(|\\.system\\s*\\(|Command\\s*\\()")
	reEvalDangerousBT  = regexp.MustCompile("(?i)\\beval\\s*\\(\\s*`[^`]*(?:yaml\\.(?:unsafe_)?load|parseXml|pickle\\.loads?|marshal\\.load|unserialize|\\.exec\\s*\\(|\\.system\\s*\\(|Command\\s*\\()")
)

// GTSS-GEN-009: XML parser misconfiguration (XXE enablement)
var (
	// noent: true in libxml/XML parsing options — enables external entity substitution
	reXMLNoentTrue        = regexp.MustCompile(`(?i)noent\s*:\s*true`)
	// resolveExternals set to true (.NET / general)
	reResolveExternals    = regexp.MustCompile(`(?i)resolveExternals\s*(?:=|:)\s*true`)
	// Java: FEATURE with external-general-entities set to true
	reFeatureExtEntities  = regexp.MustCompile(`(?i)FEATURE.*external-general-entities.*true|setFeature\s*\([^)]*external-general-entities[^)]*,\s*true`)
	// libxml context: parseXml/parseXmlString with noent
	reLibxmlParseNoent    = regexp.MustCompile(`(?i)(?:parseXml|parseXmlString|libxml)\s*\([^)]*noent\s*:\s*true`)
)

// --- Rule 1: Debug Mode Enabled ---

type DebugModeEnabled struct{}

func (r *DebugModeEnabled) ID() string                     { return "GTSS-GEN-001" }
func (r *DebugModeEnabled) Name() string                   { return "DebugModeEnabled" }
func (r *DebugModeEnabled) DefaultSeverity() rules.Severity { return rules.High }
func (r *DebugModeEnabled) Description() string {
	return "Detects debug or development mode configurations that should not be enabled in production, exposing detailed error messages and internal state."
}
func (r *DebugModeEnabled) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangGo, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangRuby, rules.LangPHP,
		rules.LangJava, rules.LangYAML,
	}
}

func (r *DebugModeEnabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	patterns := []*regexp.Regexp{
		reDjangoDebug, reFlaskDebug, reFlaskRunDebug, reGinDebugMode,
		reRailsDevMode, reLaravelDebug, reSpringDebug,
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, pat := range patterns {
			if m := pat.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Debug mode enabled in configuration",
					Description:   "Debug/development mode is enabled. In production, this exposes detailed error messages, stack traces, and internal application state to attackers.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   m,
					Suggestion:    "Disable debug mode for production deployments. Use environment variables to control debug settings.",
					CWEID:         "CWE-489",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"config", "debug", "production"},
				})
				break
			}
		}
	}
	return findings
}

// --- Rule 2: Unsafe Deserialization ---

type UnsafeDeserialization struct{}

func (r *UnsafeDeserialization) ID() string                     { return "GTSS-GEN-002" }
func (r *UnsafeDeserialization) Name() string                   { return "UnsafeDeserialization" }
func (r *UnsafeDeserialization) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UnsafeDeserialization) Description() string {
	return "Detects deserialization of untrusted data using dangerous functions that can lead to remote code execution."
}
func (r *UnsafeDeserialization) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangRuby,
		rules.LangPHP, rules.LangJavaScript, rules.LangTypeScript,
	}
}

func (r *UnsafeDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangPython:
			if m := rePickleLoads.FindString(line); m != "" {
				matched = m
				detail = "pickle deserialization can execute arbitrary code. Use JSON or a safe serialization format."
			} else if m := rePickleUnpickler.FindString(line); m != "" {
				matched = m
				detail = "Unpickler can execute arbitrary code during deserialization."
			} else if reYAMLUnsafe.MatchString(line) && !reYAMLSafeLoader.MatchString(line) {
				matched = reYAMLUnsafe.FindString(line)
				if reYAMLFullLoader.MatchString(line) {
					detail = "yaml.load() with FullLoader is NOT safe for untrusted input — it can still instantiate arbitrary Python objects via !!python/object tags. Use yaml.safe_load() or Loader=SafeLoader."
				} else {
					detail = "yaml.load() without SafeLoader can execute arbitrary Python code. Use yaml.safe_load() or specify Loader=SafeLoader."
				}
			}
		case rules.LangJava:
			if m := reJavaObjectStream.FindString(line); m != "" {
				matched = m
				detail = "ObjectInputStream deserializes untrusted data which can lead to RCE. Use allowlists or safe alternatives like JSON."
			}
		case rules.LangRuby:
			if m := reRubyMarshalLoad.FindString(line); m != "" {
				matched = m
				detail = "Marshal.load can execute arbitrary code. Use JSON.parse for untrusted data."
			}
		case rules.LangPHP:
			if m := rePHPUnserialize.FindString(line); m != "" {
				matched = m
				detail = "unserialize() can lead to object injection and RCE. Use json_decode() for untrusted data."
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if m := reNodeSerialize.FindString(line); m != "" {
				matched = m
				detail = "node-serialize unserialize() executes arbitrary code. Use JSON.parse() instead."
			} else if m := reJSEval.FindString(line); m != "" {
				matched = m
				detail = "eval() executes arbitrary code from a string. If the input is user-controlled, this leads to remote code execution. Use JSON.parse() for data or a safe sandbox."
			} else if m := reJSNewFunction.FindString(line); m != "" {
				matched = m
				detail = "new Function() constructor creates executable code from strings. If arguments include user input, this leads to code injection. Use safe alternatives."
			} else if m := reJSVMRun.FindString(line); m != "" {
				matched = m
				detail = "vm.runInNewContext/runInThisContext executes arbitrary code. If the code string is user-controlled, this leads to remote code execution."
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe deserialization of untrusted data",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use safe serialization formats like JSON. If deserialization is required, use allowlists and validate input before deserializing.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "injection"},
			})
		}
	}
	return findings
}

// --- Rule 3: XXE Vulnerability ---

type XXEVulnerability struct{}

func (r *XXEVulnerability) ID() string                     { return "GTSS-GEN-003" }
func (r *XXEVulnerability) Name() string                   { return "XXEVulnerability" }
func (r *XXEVulnerability) DefaultSeverity() rules.Severity { return rules.High }
func (r *XXEVulnerability) Description() string {
	return "Detects XML parsing configurations that do not disable external entity processing, enabling XXE attacks for file disclosure and SSRF."
}
func (r *XXEVulnerability) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangGo,
		rules.LangPHP, rules.LangCSharp,
	}
}

func (r *XXEVulnerability) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	switch ctx.Language {
	case rules.LangPython:
		// Check if defusedxml is imported anywhere in the file
		if reDefusedXML.MatchString(ctx.Content) {
			break
		}
		for i, line := range lines {
			if m := rePythonXMLParse.FindString(line); m != "" {
				findings = append(findings, r.makeFinding(ctx, i+1, m,
					"Python's built-in XML libraries are vulnerable to XXE. Use defusedxml instead."))
			}
		}

	case rules.LangJava:
		hasProtection := reJavaDisallowDTD.MatchString(ctx.Content)
		if !hasProtection {
			for i, line := range lines {
				if m := reJavaDocBuilder.FindString(line); m != "" {
					findings = append(findings, r.makeFinding(ctx, i+1, m,
						"DocumentBuilderFactory without disabling external entities is vulnerable to XXE. Set FEATURE_SECURE_PROCESSING or disallow-doctype-decl."))
				}
			}
		}

	case rules.LangGo:
		for i, line := range lines {
			if m := reGoXMLDecoder.FindString(line); m != "" {
				findings = append(findings, r.makeFinding(ctx, i+1, m,
					"Go xml.NewDecoder does not restrict external entities by default. Consider validating XML input and restricting entity expansion."))
			}
		}

	case rules.LangPHP:
		hasProtection := rePHPDisableEntities.MatchString(ctx.Content)
		if !hasProtection {
			for i, line := range lines {
				if m := rePHPLoadXML.FindString(line); m != "" {
					findings = append(findings, r.makeFinding(ctx, i+1, m,
						"XML parsing without libxml_disable_entity_loader(true) is vulnerable to XXE."))
				}
			}
		}

	case rules.LangCSharp:
		hasProtection := reCSharpDtdProhibit.MatchString(ctx.Content)
		if !hasProtection {
			for i, line := range lines {
				if m := reCSharpXMLReader.FindString(line); m != "" {
					findings = append(findings, r.makeFinding(ctx, i+1, m,
						"XML reader without DtdProcessing.Prohibit is vulnerable to XXE."))
				}
			}
		}
	}

	return findings
}

func (r *XXEVulnerability) makeFinding(ctx *rules.ScanContext, line int, matched, desc string) rules.Finding {
	return rules.Finding{
		RuleID:        r.ID(),
		Severity:      r.DefaultSeverity(),
		SeverityLabel: r.DefaultSeverity().String(),
		Title:         "XML parsing vulnerable to XXE",
		Description:   desc,
		FilePath:      ctx.FilePath,
		LineNumber:    line,
		MatchedText:   matched,
		Suggestion:    "Disable external entity processing. Python: use defusedxml. Java: set disallow-doctype-decl feature. PHP: libxml_disable_entity_loader(true).",
		CWEID:         "CWE-611",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      ctx.Language,
		Confidence:    "high",
		Tags:          []string{"xxe", "xml", "injection"},
	}
}

// --- Rule 4: Open Redirect ---

type OpenRedirect struct{}

func (r *OpenRedirect) ID() string                     { return "GTSS-GEN-004" }
func (r *OpenRedirect) Name() string                   { return "OpenRedirect" }
func (r *OpenRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *OpenRedirect) Description() string {
	return "Detects HTTP redirects to user-controlled URLs without validation, enabling phishing and credential theft through open redirect attacks."
}
func (r *OpenRedirect) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangGo, rules.LangPHP, rules.LangRuby, rules.LangJava,
	}
}

func (r *OpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	patterns := map[rules.Language][]*regexp.Regexp{
		rules.LangPython:     {rePyRedirect},
		rules.LangJavaScript: {reJSRedirect},
		rules.LangTypeScript: {reJSRedirect},
		rules.LangGo:         {reGoRedirect},
		rules.LangPHP:        {rePHPRedirect},
		rules.LangRuby:       {reRubyRedirect},
		rules.LangJava:       {reJavaRedirect},
	}

	langPatterns, ok := patterns[ctx.Language]
	if !ok {
		langPatterns = []*regexp.Regexp{reGenericRedirect}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		matched := ""
		for _, pat := range langPatterns {
			if m := pat.FindString(line); m != "" {
				matched = m
				break
			}
		}

		// Fallback: for Go, check http.Redirect with a variable if user input is nearby
		if matched == "" && ctx.Language == rules.LangGo {
			if m := reGoRedirectVar.FindString(line); m != "" {
				if hasNearbyUserInput(lines, i, reGoUserInputSource) {
					matched = m
				}
			}
		}

		// Fallback: for JS/TS, check res.redirect with a variable if user input is nearby
		if matched == "" && (ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript) {
			if m := reJSRedirectVar.FindString(line); m != "" {
				if hasNearbyUserInput(lines, i, reJSUserInputSource) {
					matched = m
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Open redirect using user-controlled URL",
				Description:   "HTTP redirect target is taken directly from user input without validation. Attackers can craft URLs that redirect users to malicious sites for phishing.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate redirect URLs against an allowlist of permitted destinations. Reject absolute URLs and URLs pointing to external domains.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"redirect", "phishing", "input-validation"},
			})
		}
	}
	return findings
}

// hasNearbyUserInput checks lines within a window for user input source patterns.
func hasNearbyUserInput(lines []string, idx int, sourcePattern *regexp.Regexp) bool {
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if sourcePattern.MatchString(l) {
			return true
		}
	}
	return false
}

// --- Rule 5: Log Injection ---

type LogInjection struct{}

func (r *LogInjection) ID() string                     { return "GTSS-GEN-005" }
func (r *LogInjection) Name() string                   { return "LogInjection" }
func (r *LogInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LogInjection) Description() string {
	return "Detects logging of unsanitized user input that could contain newlines or control characters for log forging attacks."
}
func (r *LogInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangJava,
	}
}

func (r *LogInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var langPatterns []*regexp.Regexp
	switch ctx.Language {
	case rules.LangGo:
		langPatterns = []*regexp.Regexp{reGoLogUserInput}
	case rules.LangPython:
		langPatterns = []*regexp.Regexp{rePyLogUserInput}
	case rules.LangJavaScript, rules.LangTypeScript:
		langPatterns = []*regexp.Regexp{reJSLogUserInput}
	default:
		langPatterns = []*regexp.Regexp{reGenericLogInput}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, pat := range langPatterns {
			if m := pat.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Unsanitized user input in log statement",
					Description:   "User-controlled input is logged without sanitization. Attackers can inject newlines and control characters to forge log entries, hide malicious activity, or exploit log analysis tools.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   m,
					Suggestion:    "Sanitize user input before logging by stripping newlines and control characters. Use structured logging with parameterized fields instead of string interpolation.",
					CWEID:         "CWE-117",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"logging", "injection", "sanitization"},
				})
				break
			}
		}
	}
	return findings
}

// --- Rule 6: Race Condition (TOCTOU) ---

type RaceCondition struct{}

func (r *RaceCondition) ID() string                     { return "GTSS-GEN-006" }
func (r *RaceCondition) Name() string                   { return "RaceCondition" }
func (r *RaceCondition) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RaceCondition) Description() string {
	return "Detects time-of-check-time-of-use (TOCTOU) patterns where a check is performed and the resource is used in separate steps without proper synchronization."
}
func (r *RaceCondition) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangRuby, rules.LangPHP,
	}
}

func (r *RaceCondition) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file has mutex/lock usage (reduces false positives)
	hasLocking := reGoMutexLock.MatchString(ctx.Content) ||
		strings.Contains(ctx.Content, "synchronized") ||
		strings.Contains(ctx.Content, "threading.Lock") ||
		strings.Contains(ctx.Content, "flock")

	if hasLocking {
		return findings
	}

	for i, line := range lines {
		if !reFileExistsCheck.MatchString(line) && !rePermCheck.MatchString(line) {
			continue
		}

		// Look ahead up to 10 lines for a file operation without locking
		end := i + 10
		if end > len(lines) {
			end = len(lines)
		}

		for j := i + 1; j < end; j++ {
			if reFileOperation.MatchString(lines[j]) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Potential TOCTOU race condition",
					Description:   "A check is performed on a resource followed by an operation on it without atomicity guarantees. An attacker may alter the resource between the check and use.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Use atomic operations or proper locking. For files, use O_CREAT|O_EXCL flags for exclusive creation, or use flock/fcntl for advisory locking.",
					CWEID:         "CWE-367",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"race-condition", "toctou", "concurrency"},
				})
				break
			}
		}
	}
	return findings
}

// --- Rule 7: Mass Assignment ---

type MassAssignment struct{}

func (r *MassAssignment) ID() string                     { return "GTSS-GEN-007" }
func (r *MassAssignment) Name() string                   { return "MassAssignment" }
func (r *MassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r *MassAssignment) Description() string {
	return "Detects patterns where all fields from user input are accepted for model or struct updates without field restrictions, enabling privilege escalation."
}
func (r *MassAssignment) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangRuby, rules.LangPython,
		rules.LangJavaScript, rules.LangTypeScript,
	}
}

func (r *MassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangGo:
			if m := reGoBindJSON.FindString(line); m != "" {
				matched = m
				detail = "Binding all JSON fields directly to a struct without restricting allowed fields. Use a dedicated input DTO or explicitly select fields."
			} else if m := reGoDecodeBody.FindString(line); m != "" {
				// Only flag .Decode(&) when r.Body is used as the decoder source nearby
				start := i - 5
				if start < 0 {
					start = 0
				}
				hasBodySource := false
				for j := start; j <= i; j++ {
					if reGoNewDecoder.MatchString(lines[j]) {
						hasBodySource = true
						break
					}
				}
				if hasBodySource {
					matched = m
					detail = "Decoding HTTP request body directly into a struct without restricting allowed fields. Use a dedicated input DTO or explicitly select fields."
				}
			}
		case rules.LangRuby:
			if m := reRailsPermitAll.FindString(line); m != "" {
				matched = m
				detail = "params.permit! allows all parameters, enabling mass assignment of any attribute including admin flags."
			} else if m := reRailsPermitLax.FindString(line); m != "" {
				matched = m
				detail = "Permitting all parameters enables mass assignment attacks."
			}
		case rules.LangPython:
			if m := reDjangoExcludeNone.FindString(line); m != "" {
				matched = m
				detail = "Empty exclude list on a ModelForm allows all model fields to be set from user input."
			} else if m := reDjangoFieldsAll.FindString(line); m != "" {
				matched = m
				detail = "fields = '__all__' on a ModelForm exposes all model fields to user input. Explicitly list allowed fields."
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if m := reJSSpreadBody.FindString(line); m != "" {
				matched = m
				detail = "Spreading req.body directly into an object passes all user-supplied fields without filtering. Destructure only the fields you need."
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Mass assignment vulnerability",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Explicitly allowlist the fields that can be set from user input. Use separate DTOs/input types that only include safe fields.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"mass-assignment", "input-validation", "authorization"},
			})
		}
	}
	return findings
}

// --- Rule 8: Code-as-String Analysis (dangerous calls inside eval/vm string args) ---

type CodeAsStringEval struct{}

func (r *CodeAsStringEval) ID() string                     { return "GTSS-GEN-008" }
func (r *CodeAsStringEval) Name() string                   { return "CodeAsStringEval" }
func (r *CodeAsStringEval) DefaultSeverity() rules.Severity { return rules.High }
func (r *CodeAsStringEval) Description() string {
	return "Detects dangerous function calls (deserialization, command execution, XML parsing) hidden inside string arguments to eval(), vm.runInContext(), or new Function()."
}
func (r *CodeAsStringEval) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPython, rules.LangRuby, rules.LangPHP,
	}
}

func (r *CodeAsStringEval) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
	}

	patterns := []pattern{
		{reVMRunDangerous, "vm.runInContext/runInNewContext with dangerous call in string argument"},
		{reVMRunDangerousBT, "vm.runInContext/runInNewContext with dangerous call in template literal"},
		{reEvalDangerous, "eval() with dangerous call in string argument"},
		{reEvalDangerousBT, "eval() with dangerous call in template literal"},
		{reFuncCtorDanger, "new Function() with dangerous call in string argument"},
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, p := range patterns {
			if m := p.re.FindString(line); m != "" {
				if len(m) > 120 {
					m = m[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Dangerous call inside code-as-string: " + p.desc,
					Description:   "A dangerous function (deserialization, command execution, or unsafe XML parsing) is called inside a string passed to an eval/vm execution function. These calls are easily missed by static analysis since they are embedded in strings.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   m,
					Suggestion:    "Avoid embedding dangerous calls inside eval/vm string arguments. Refactor to call the function directly so it can be analyzed by security tools, or use safe alternatives (e.g., yaml.safe_load instead of yaml.load).",
					CWEID:         "CWE-94",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"code-as-string", "eval", "deserialization", "injection"},
				})
				break
			}
		}
	}
	return findings
}

// --- Rule 9: XML Parser Misconfiguration (XXE enablement) ---

type XMLParserMisconfig struct{}

func (r *XMLParserMisconfig) ID() string                     { return "GTSS-GEN-009" }
func (r *XMLParserMisconfig) Name() string                   { return "XMLParserMisconfig" }
func (r *XMLParserMisconfig) DefaultSeverity() rules.Severity { return rules.High }
func (r *XMLParserMisconfig) Description() string {
	return "Detects XML parser configurations that explicitly enable external entity processing (noent: true, resolveExternals, external-general-entities), leading to XXE vulnerabilities."
}
func (r *XMLParserMisconfig) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangCSharp,
		rules.LangPython, rules.LangPHP, rules.LangRuby,
	}
}

func (r *XMLParserMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
	}

	patterns := []pattern{
		{reLibxmlParseNoent, "XML parser with noent: true enables external entity substitution (XXE)"},
		{reXMLNoentTrue, "noent: true enables external entity substitution in XML parsing (XXE)"},
		{reResolveExternals, "resolveExternals set to true allows external entity resolution (XXE)"},
		{reFeatureExtEntities, "external-general-entities feature enabled allows XXE attacks"},
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, p := range patterns {
			if m := p.re.FindString(line); m != "" {
				if len(m) > 120 {
					m = m[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "XML parser misconfiguration: " + p.desc,
					Description:   "The XML parser is configured to resolve external entities. This enables XML External Entity (XXE) attacks, which can lead to file disclosure, SSRF, and denial of service.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   m,
					Suggestion:    "Disable external entity processing. For libxml: set noent to false. For Java: disable external-general-entities feature. For .NET: do not set resolveExternals to true.",
					CWEID:         "CWE-611",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"xxe", "xml", "misconfiguration"},
				})
				break
			}
		}
	}
	return findings
}

// --- Registration ---

func init() {
	rules.Register(&DebugModeEnabled{})
	rules.Register(&UnsafeDeserialization{})
	rules.Register(&XXEVulnerability{})
	rules.Register(&OpenRedirect{})
	rules.Register(&LogInjection{})
	rules.Register(&RaceCondition{})
	rules.Register(&MassAssignment{})
	rules.Register(&CodeAsStringEval{})
	rules.Register(&XMLParserMisconfig{})
}
