package deser

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-DESER-001: Extended deserialization patterns (beyond GEN-002)
var (
	// Python: shelve.open() with variable — stores pickled objects
	reShelveOpen = regexp.MustCompile(`\bshelve\.open\s*\(`)
	// Python: marshal.loads() / marshal.load() — unsafe for untrusted data
	reMarshalLoads = regexp.MustCompile(`\bmarshal\.loads?\s*\(`)
	// Java: XStream.fromXML() — XML deserialization, many CVEs
	reXStreamFromXML = regexp.MustCompile(`\bXStream\s*\(\s*\)|\.fromXML\s*\(`)
	// Java: Kryo.readObject() / readClassAndObject()
	reKryoRead = regexp.MustCompile(`\b(?:kryo|Kryo)\s*\.\s*(?:readObject|readClassAndObject)\s*\(`)
	// Java: XMLDecoder (java.beans.XMLDecoder)
	reJavaXMLDecoder = regexp.MustCompile(`\bnew\s+XMLDecoder\s*\(`)
	// Java: SnakeYAML Yaml().load() without SafeConstructor
	reSnakeYAMLLoad     = regexp.MustCompile(`\bnew\s+Yaml\s*\(`)
	reSnakeYAMLSafeCtor = regexp.MustCompile(`SafeConstructor`)
	reSnakeYAMLLoadCall = regexp.MustCompile(`\.load\s*\(`)
	// .NET: BinaryFormatter.Deserialize, LosFormatter.Deserialize
	reDotNetBinaryFmt = regexp.MustCompile(`\b(?:BinaryFormatter|LosFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter)\s*\(`)
	// .NET: TypeNameHandling in JSON.NET
	reJsonNetTypeName = regexp.MustCompile(`(?i)TypeNameHandling\s*[=:]\s*(?:TypeNameHandling\.)?(?:All|Auto|Objects|Arrays)`)
)

// GTSS-DESER-002: Ruby dangerous dynamic execution
var (
	// Ruby: Kernel.eval / eval() with variable (not string literal)
	reRubyEval = regexp.MustCompile(`\b(?:Kernel\.)?eval\s*\(\s*[^"'\s)]`)
	// Ruby: instance_eval / class_eval / module_eval with variable
	reRubyInstanceEval = regexp.MustCompile(`\b(?:instance_eval|class_eval|module_eval)\s*\(\s*[^"'\s)]`)
	// Ruby: send / public_send with user input indicators
	reRubySend       = regexp.MustCompile(`\b(?:send|public_send|__send__)\s*\(\s*(?:params|request|session)`)
	reRubySendVar    = regexp.MustCompile(`\b(?:send|public_send|__send__)\s*\(\s*[a-zA-Z_]\w*`)
	reRubyUserSource = regexp.MustCompile(`\bparams\b|\brequest\b|\bsession\b`)
	// Ruby: constantize with user input (turns string into class name)
	reRubyConstantize = regexp.MustCompile(`\bconstantize\b`)
	// Ruby: system / exec with variable interpolation already covered by INJ-002
)

// GTSS-DESER-003: PHP dangerous patterns (beyond INJ-003 and TRV-002)
var (
	// PHP: preg_replace with /e modifier — code execution
	rePHPPregE = regexp.MustCompile(`\bpreg_replace\s*\(\s*['"][^'"]*\/e['"imsxuADSUXJ]*['"]`)
	// PHP: extract($_GET) / extract($_POST) / extract($_REQUEST) — variable injection
	rePHPExtract = regexp.MustCompile(`\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`)
	// PHP: assert() with string variable (not a boolean expression)
	rePHPAssert = regexp.MustCompile(`\bassert\s*\(\s*\$`)
	// PHP: create_function — deprecated, eval-like
	rePHPCreateFunc = regexp.MustCompile(`\bcreate_function\s*\(`)
	// PHP: variable function calls $$var() or $obj->$method()
	rePHPVarFunc = regexp.MustCompile(`\$\$\w+\s*\(`)
)

// GTSS-DESER-004: JS/TS additional dangerous patterns
var (
	// JS/TS: setTimeout / setInterval with string + user input nearby
	reJSTimerString   = regexp.MustCompile(`\b(?:setTimeout|setInterval)\s*\(\s*[a-zA-Z_]\w*`)
	reJSTimerLiteral  = regexp.MustCompile(`\b(?:setTimeout|setInterval)\s*\(\s*['"]`)
	reJSUserInputHint = regexp.MustCompile(`\breq\.(?:query|params|body)\b|\bprocess\.argv\b|\b(?:user_?input|userInput|user_?data|userData)\b`)
)

// ---------------------------------------------------------------------------
// GTSS-DESER-001: Extended Unsafe Deserialization
// ---------------------------------------------------------------------------

type ExtendedDeserialization struct{}

func (r *ExtendedDeserialization) ID() string                     { return "GTSS-DESER-001" }
func (r *ExtendedDeserialization) Name() string                   { return "ExtendedDeserialization" }
func (r *ExtendedDeserialization) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ExtendedDeserialization) Description() string {
	return "Detects additional deserialization sinks beyond the core set: Python shelve/marshal, Java XStream/Kryo/XMLDecoder/SnakeYAML, .NET BinaryFormatter/JSON.NET TypeNameHandling."
}
func (r *ExtendedDeserialization) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangCSharp,
	}
}

func (r *ExtendedDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		var matched string
		var detail string
		sev := r.DefaultSeverity()

		switch ctx.Language {
		case rules.LangPython:
			if m := reShelveOpen.FindString(line); m != "" {
				matched = m
				detail = "shelve.open() uses pickle internally. If the shelf file path is user-controlled or the file content is untrusted, this leads to arbitrary code execution via pickle deserialization."
			} else if m := reMarshalLoads.FindString(line); m != "" {
				matched = m
				detail = "marshal.loads()/load() is not safe for untrusted data. The marshal format is not designed to be secure against malicious input and can crash the interpreter."
			}

		case rules.LangJava:
			if m := reXStreamFromXML.FindString(line); m != "" {
				matched = m
				detail = "XStream deserialization has numerous CVEs allowing remote code execution. Configure a security framework with an allowlist of permitted classes."
			} else if m := reKryoRead.FindString(line); m != "" {
				matched = m
				detail = "Kryo deserialization with untrusted data can lead to arbitrary code execution. Use setRegistrationRequired(true) and register only safe classes."
				sev = rules.High
			} else if m := reJavaXMLDecoder.FindString(line); m != "" {
				matched = m
				detail = "XMLDecoder can execute arbitrary code from XML input. Never use XMLDecoder with untrusted data."
			} else if reSnakeYAMLLoad.MatchString(line) || reSnakeYAMLLoadCall.MatchString(line) {
				// Check for SnakeYAML new Yaml() without SafeConstructor
				if reSnakeYAMLLoad.MatchString(line) && !reSnakeYAMLSafeCtor.MatchString(ctx.Content) {
					m := reSnakeYAMLLoad.FindString(line)
					matched = m
					detail = "SnakeYAML Yaml() without SafeConstructor deserializes arbitrary Java objects via !!java.lang.Runtime and similar tags, leading to RCE. Use new Yaml(new SafeConstructor())."
				}
			}

		case rules.LangCSharp:
			if m := reDotNetBinaryFmt.FindString(line); m != "" {
				matched = m
				detail = "BinaryFormatter/LosFormatter/SoapFormatter deserialization is inherently insecure and can execute arbitrary code. Microsoft recommends not using BinaryFormatter. Use System.Text.Json or DataContractSerializer with known types."
			} else if m := reJsonNetTypeName.FindString(line); m != "" {
				matched = m
				detail = "JSON.NET TypeNameHandling set to All/Auto/Objects/Arrays allows type-discriminated deserialization, enabling remote code execution via crafted JSON payloads. Use TypeNameHandling.None or a custom SerializationBinder."
				sev = rules.High
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title:         "Unsafe deserialization of untrusted data",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use safe serialization formats like JSON. If deserialization is required, use allowlists/SafeConstructor and validate input before deserializing.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-DESER-002: Ruby Dangerous Dynamic Execution
// ---------------------------------------------------------------------------

type RubyDynamicExecution struct{}

func (r *RubyDynamicExecution) ID() string                     { return "GTSS-DESER-002" }
func (r *RubyDynamicExecution) Name() string                   { return "RubyDynamicExecution" }
func (r *RubyDynamicExecution) DefaultSeverity() rules.Severity { return rules.High }
func (r *RubyDynamicExecution) Description() string {
	return "Detects Ruby dynamic code execution patterns (eval, instance_eval, class_eval, send, public_send, constantize) that can lead to RCE when used with user input."
}
func (r *RubyDynamicExecution) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RubyDynamicExecution) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		var matched string
		var detail string
		confidence := "high"
		sev := r.DefaultSeverity()

		if m := reRubyEval.FindString(line); m != "" {
			matched = m
			detail = "eval() with a dynamic argument executes arbitrary Ruby code. If the argument is user-controlled, this leads to remote code execution."
			sev = rules.Critical
		} else if m := reRubyInstanceEval.FindString(line); m != "" {
			matched = m
			detail = "instance_eval/class_eval/module_eval with a dynamic argument can execute arbitrary code in the context of the receiver object. If the argument is user-controlled, this leads to RCE."
			sev = rules.Critical
		} else if m := reRubySend.FindString(line); m != "" {
			matched = m
			detail = "send()/public_send() with user-controlled method name allows calling arbitrary methods on an object, potentially including dangerous methods like system(), eval(), or exit."
		} else if m := reRubySendVar.FindString(line); m != "" {
			// Lower confidence unless user input source is nearby
			if hasNearbyPattern(lines, i, reRubyUserSource) {
				matched = m
				detail = "send()/public_send()/__send__() with a variable that may originate from user input. This allows arbitrary method invocation."
				confidence = "medium"
			}
		} else if reRubyConstantize.MatchString(line) {
			if hasNearbyPattern(lines, i, reRubyUserSource) {
				matched = reRubyConstantize.FindString(line)
				detail = "constantize converts a user-controlled string to a Ruby class constant. An attacker can instantiate arbitrary classes, leading to code execution."
				confidence = "medium"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title:         "Dangerous dynamic code execution in Ruby",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid eval/instance_eval/class_eval with user input. For send(), use an allowlist of permitted method names. For constantize, validate against a strict allowlist of class names.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"eval", "rce", "dynamic-execution"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-DESER-003: PHP Dangerous Patterns
// ---------------------------------------------------------------------------

type PHPDangerousPatterns struct{}

func (r *PHPDangerousPatterns) ID() string                     { return "GTSS-DESER-003" }
func (r *PHPDangerousPatterns) Name() string                   { return "PHPDangerousPatterns" }
func (r *PHPDangerousPatterns) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPDangerousPatterns) Description() string {
	return "Detects PHP-specific dangerous patterns: preg_replace /e modifier, extract() with superglobals, assert() with variable, create_function(), and variable function calls."
}
func (r *PHPDangerousPatterns) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *PHPDangerousPatterns) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		var matched string
		var detail string
		sev := r.DefaultSeverity()

		if m := rePHPPregE.FindString(line); m != "" {
			matched = m
			detail = "preg_replace() with /e modifier evaluates the replacement string as PHP code. This was removed in PHP 7.0 due to security risks. An attacker can achieve arbitrary code execution."
			sev = rules.Critical
		} else if m := rePHPExtract.FindString(line); m != "" {
			matched = m
			detail = "extract() with superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE) overwrites local variables with user-controlled values. This can lead to authentication bypass, variable injection, and other logic flaws."
		} else if m := rePHPAssert.FindString(line); m != "" {
			matched = m
			detail = "assert() with a string argument evaluates it as PHP code (in PHP < 8.0). If the argument contains user input, this leads to arbitrary code execution."
			sev = rules.Critical
		} else if m := rePHPCreateFunc.FindString(line); m != "" {
			matched = m
			detail = "create_function() is deprecated and uses eval() internally. If any argument is user-controlled, this leads to code injection."
			sev = rules.Critical
		} else if m := rePHPVarFunc.FindString(line); m != "" {
			matched = m
			detail = "Variable variable function call ($$var()) can invoke arbitrary functions. If the variable name comes from user input, this leads to code execution."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title:         "PHP dangerous pattern detected",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove /e modifier (use preg_replace_callback). Avoid extract() with user data. Replace assert() with proper conditional checks. Replace create_function() with anonymous functions.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "code-execution", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-DESER-004: JS/TS setTimeout/setInterval with String (enhanced)
// ---------------------------------------------------------------------------

type JSTimerStringExec struct{}

func (r *JSTimerStringExec) ID() string                     { return "GTSS-DESER-004" }
func (r *JSTimerStringExec) Name() string                   { return "JSTimerStringExec" }
func (r *JSTimerStringExec) DefaultSeverity() rules.Severity { return rules.High }
func (r *JSTimerStringExec) Description() string {
	return "Detects setTimeout/setInterval with string arguments containing user input, which acts as implicit eval() and can lead to code injection."
}
func (r *JSTimerStringExec) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JSTimerStringExec) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasUserInput := reJSUserInputHint.MatchString(ctx.Content)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		var matched string

		// setTimeout/setInterval with string literal argument
		if m := reJSTimerLiteral.FindString(line); m != "" {
			matched = m
		} else if m := reJSTimerString.FindString(line); m != "" {
			// setTimeout/setInterval with variable — only flag if user input nearby
			if hasUserInput || hasNearbyPattern(lines, i, reJSUserInputHint) {
				matched = m
			}
		}

		if matched != "" {
			confidence := "medium"
			if hasUserInput {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "setTimeout/setInterval with string argument (implicit eval)",
				Description:   "Passing a string to setTimeout/setInterval causes it to be evaluated as code (equivalent to eval()). If the string is user-controlled or constructed from user input, this leads to arbitrary code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Pass a function reference instead of a string: setTimeout(() => { ... }, delay) instead of setTimeout('code', delay).",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"eval", "timer", "code-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// hasNearbyPattern checks lines within a window for a given pattern.
func hasNearbyPattern(lines []string, idx int, pat *regexp.Regexp) bool {
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if pat.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&ExtendedDeserialization{})
	rules.Register(&RubyDynamicExecution{})
	rules.Register(&PHPDangerousPatterns{})
	rules.Register(&JSTimerStringExec{})
}
