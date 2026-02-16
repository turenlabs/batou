package validation

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended validation rules
// ---------------------------------------------------------------------------

// BATOU-VAL-006: Missing input length validation
var (
	reAcceptBodyNoLimit = regexp.MustCompile(`(?i)(?:req\.body|request\.data|request\.POST|request\.json|request\.form|request\.args|r\.Body|request\.getParameter|params\[|FormValue)\b`)
	reLimitPresent      = regexp.MustCompile(`(?i)(?:maxlength|max_length|maxLen|\.length\s*[<>]|len\s*\([^)]+\)\s*[<>]|\.size\s*[<>]|ContentLength|content.?length|max.?size|limit|truncate|\.slice\s*\(|\.substring\s*\(|[:=]\s*\d{1,4}\b)`)
)

// BATOU-VAL-007: ReDoS - catastrophic backtracking
var (
	reRedosPattern = regexp.MustCompile(`(?:new\s+RegExp\s*\(|regexp\.MustCompile\s*\(|regexp\.Compile\s*\(|re\.compile\s*\(|/[^/\n]+/|Regex\s*\(|Pattern\.compile\s*\()`)
	reNestedQuant  = regexp.MustCompile(`(?:\([^)]*[+*][^)]*\)\s*[+*]|\[[^\]]*\]\s*[+*]\s*[+*]|\.\*\.\*|(?:\w\+){2,}|\(\.\*\)\+|\([^)]+\+\)\+|\([^)]+\*\)\+|\([^)]+\+\)\*|\([^)]+\*\)\*)`)
)

// BATOU-VAL-008: Integer overflow from unchecked conversion
var (
	reStrToIntGo     = regexp.MustCompile(`strconv\.(?:Atoi|ParseInt|ParseUint)\s*\(`)
	reStrToIntPy     = regexp.MustCompile(`\bint\s*\(\s*(?:request\.|input\(|sys\.argv|os\.environ)`)
	reStrToIntJS     = regexp.MustCompile(`(?:parseInt|Number)\s*\(\s*(?:req\.|request\.|params|query|body|process\.argv)`)
	reStrToIntJava   = regexp.MustCompile(`(?:Integer\.parseInt|Long\.parseLong|Short\.parseShort)\s*\(\s*(?:request\.getParameter|args\[)`)
	reOverflowCheck  = regexp.MustCompile(`(?i)(?:overflow|MaxInt|MinInt|MAX_VALUE|MIN_VALUE|max_value|min_value|Number\.MAX_SAFE_INTEGER|Number\.isSafeInteger|math\.MaxInt|math\.MinInt|int32|int16|bounds|range\s*check)`)
)

// BATOU-VAL-009: Email validation using regex only
var (
	reEmailRegex      = regexp.MustCompile(`(?i)(?:email|e_mail|mail).*(?:regex|regexp|pattern|match|test|re\.compile|MustCompile|Pattern\.compile)\s*[\(\[]?\s*['"\x60/]`)
	reEmailRegexAlt   = regexp.MustCompile(`(?i)(?:regex|regexp|pattern|re\.compile|MustCompile|Pattern\.compile)\s*[\(\[]?\s*['"\x60/][^'"]*@[^'"]*['"\x60/]`)
	reDomainValidation = regexp.MustCompile(`(?i)(?:dns\.lookup|dns\.resolve|checkdnsrr|getmxrr|MX\s*record|validate.*domain|domain.*valid|socket\.getaddrinfo|nslookup|dig\s+)`)
)

// BATOU-VAL-010: Missing null/undefined check before use
var (
	reOptionalChainMissing = regexp.MustCompile(`(?:req\.body|req\.query|req\.params|request\.body)\.\w+\.\w+`)
	reNullCheckPresent     = regexp.MustCompile(`(?:\?\.|!= null|!== null|!= undefined|!== undefined|!= nil|if\s*\(.*(?:req\.body|req\.query|req\.params)|typeof\s+\w+\s*[!=]==?\s*['"]undefined['"])`)
)

// BATOU-VAL-011: Trusting client-side validation only
var (
	reClientSideOnly = regexp.MustCompile(`(?i)(?:<!--\s*|//\s*|/\*\s*)(?:client.?side|front.?end|browser)\s+(?:only|validation)`)
	reFormPattern    = regexp.MustCompile(`(?i)(?:pattern\s*=\s*['"][^'"]+['"]|required\s*[=>]|minlength\s*=|maxlength\s*=|type\s*=\s*['"]email['"])`)
	reNoServerVal    = regexp.MustCompile(`(?i)//\s*(?:no\s+)?(?:server|backend)\s*(?:side)?\s*validation\s*(?:needed|required|necessary)?`)
)

// BATOU-VAL-012: Type confusion from unvalidated JSON parsing
var (
	reJSONParseAccess = regexp.MustCompile(`JSON\.parse\s*\([^)]+\)\s*(?:\.\w+|\[['"])`)
	reJSONParseDirect = regexp.MustCompile(`JSON\.parse\s*\(\s*(?:req\.body|request\.body|data|input|payload|body)\s*\)`)
	reTypeCheckAfter  = regexp.MustCompile(`(?i)(?:typeof\s+|instanceof\s+|Array\.isArray\s*\(|Number\.isFinite\s*\(|Number\.isInteger\s*\(|\.constructor\s*===)`)
)

// BATOU-VAL-013: Missing array bounds check
var (
	reArrayIndexVar = regexp.MustCompile(`\w+\s*\[\s*(?:i|j|k|idx|index|n|pos|offset|count)\s*\]`)
	reBoundsCheck   = regexp.MustCompile(`(?i)(?:\.length|\.size|len\s*\(|\.count|bounds|IndexOutOfBounds|ArrayIndexOutOf|index\s*[<>]=?\s*|[<>]=?\s*(?:len|\.length|\.size|\.count))`)
)

// ---------------------------------------------------------------------------
// BATOU-VAL-006: Missing Input Length Validation
// ---------------------------------------------------------------------------

type MissingInputLengthValidation struct{}

func (r *MissingInputLengthValidation) ID() string                     { return "BATOU-VAL-006" }
func (r *MissingInputLengthValidation) Name() string                   { return "MissingInputLengthValidation" }
func (r *MissingInputLengthValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingInputLengthValidation) Description() string {
	return "Detects user input accepted without length or size validation, allowing unlimited data that can cause denial of service or buffer issues."
}
func (r *MissingInputLengthValidation) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangRuby, rules.LangPHP}
}

func (r *MissingInputLengthValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// File-level check: if there are limit checks anywhere, skip
	if reLimitPresent.MatchString(ctx.Content) {
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reAcceptBodyNoLimit.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "User input accepted without length validation",
				Description:   "User-supplied input is consumed without any length or size constraint. Unbounded input can lead to denial of service through memory exhaustion or database storage abuse.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add explicit length validation before processing user input. For example: if len(input) > MAX_LENGTH { return error }. Set max content-length on the HTTP server.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"validation", "length", "dos", "cwe-20"},
			})
			return findings // one finding per file for this rule
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-007: ReDoS - Catastrophic Backtracking
// ---------------------------------------------------------------------------

type ReDoSPattern struct{}

func (r *ReDoSPattern) ID() string                     { return "BATOU-VAL-007" }
func (r *ReDoSPattern) Name() string                   { return "ReDoSPattern" }
func (r *ReDoSPattern) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReDoSPattern) Description() string {
	return "Detects regular expressions with patterns susceptible to catastrophic backtracking (ReDoS), which can cause denial of service when processing crafted input."
}
func (r *ReDoSPattern) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangRuby, rules.LangPHP, rules.LangCSharp}
}

func (r *ReDoSPattern) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if !reRedosPattern.MatchString(line) {
			continue
		}
		if reNestedQuant.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
				Description:   "This regex contains nested quantifiers or overlapping alternations that can cause exponential backtracking on specially crafted input, leading to denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Rewrite the regex to avoid nested quantifiers (e.g., (a+)+ or (a*)*). Use atomic groups or possessive quantifiers where supported. Consider using a regex timeout or the re2 engine which guarantees linear time.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"validation", "redos", "dos", "regex", "cwe-1333"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-008: Integer Overflow from Unchecked String-to-Int
// ---------------------------------------------------------------------------

type IntegerOverflowConversion struct{}

func (r *IntegerOverflowConversion) ID() string                     { return "BATOU-VAL-008" }
func (r *IntegerOverflowConversion) Name() string                   { return "IntegerOverflowConversion" }
func (r *IntegerOverflowConversion) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *IntegerOverflowConversion) Description() string {
	return "Detects string-to-integer conversions of user input without overflow or range checking, which can lead to integer overflow vulnerabilities."
}
func (r *IntegerOverflowConversion) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *IntegerOverflowConversion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var patterns []*regexp.Regexp
	switch ctx.Language {
	case rules.LangGo:
		patterns = []*regexp.Regexp{reStrToIntGo}
	case rules.LangPython:
		patterns = []*regexp.Regexp{reStrToIntPy}
	case rules.LangJavaScript, rules.LangTypeScript:
		patterns = []*regexp.Regexp{reStrToIntJS}
	case rules.LangJava:
		patterns = []*regexp.Regexp{reStrToIntJava}
	default:
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, pat := range patterns {
			if loc := pat.FindStringIndex(line); loc != nil {
				if scopeHasPattern(lines, i, reOverflowCheck, 10) {
					continue
				}
				matched := line[loc[0]:loc[1]]
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Integer conversion without overflow/range check",
					Description:   "User input is converted from string to integer without checking for overflow or validating the resulting value is within expected bounds. This can cause integer overflow, wraparound, or unexpected behavior.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "After parsing, validate the integer is within expected bounds. In Go: check err from strconv.Atoi and compare against math.MaxInt32. In Java: catch NumberFormatException. In JS: use Number.isSafeInteger().",
					CWEID:         "CWE-190",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"validation", "integer-overflow", "cwe-190"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-009: Email Validation Using Regex Only
// ---------------------------------------------------------------------------

type EmailRegexOnlyValidation struct{}

func (r *EmailRegexOnlyValidation) ID() string                     { return "BATOU-VAL-009" }
func (r *EmailRegexOnlyValidation) Name() string                   { return "EmailRegexOnlyValidation" }
func (r *EmailRegexOnlyValidation) DefaultSeverity() rules.Severity { return rules.Low }
func (r *EmailRegexOnlyValidation) Description() string {
	return "Detects email validation that relies solely on regex pattern matching without DNS/MX record verification, which allows fake domains."
}
func (r *EmailRegexOnlyValidation) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *EmailRegexOnlyValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	if reDomainValidation.MatchString(ctx.Content) {
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		matched := ""
		if loc := reEmailRegex.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		} else if loc := reEmailRegexAlt.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Email validation using regex only (no domain verification)",
				Description:   "Email is validated using only a regex pattern. Regex-only validation allows emails with non-existent domains, disposable addresses, and other invalid addresses that pass pattern matching.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Supplement regex validation with DNS MX record lookup to verify the domain exists. Use a library like email-validator (Python) or validator.js (Node.js) that includes domain checks.",
				CWEID:         "CWE-20",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"validation", "email", "cwe-20"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-010: Missing Null/Undefined Check Before Use
// ---------------------------------------------------------------------------

type MissingNullCheck struct{}

func (r *MissingNullCheck) ID() string                     { return "BATOU-VAL-010" }
func (r *MissingNullCheck) Name() string                   { return "MissingNullCheck" }
func (r *MissingNullCheck) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingNullCheck) Description() string {
	return "Detects deep property access on request objects without null/undefined checks, which can cause runtime crashes."
}
func (r *MissingNullCheck) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *MissingNullCheck) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reOptionalChainMissing.FindStringIndex(line); loc != nil {
			// Skip if optional chaining or null check is present nearby
			if strings.Contains(line, "?.") || reNullCheckPresent.MatchString(line) {
				continue
			}
			if scopeHasPattern(lines, i, reNullCheckPresent, 5) {
				continue
			}
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing null/undefined check before property access",
				Description:   "Deep property access on a request object without null/undefined checking. If any intermediate property is undefined, this causes a TypeError crash that can lead to denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use optional chaining (req.body?.user?.name) or add explicit null checks before accessing nested properties. Consider using a validation library like Joi or zod.",
				CWEID:         "CWE-476",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"validation", "null-check", "cwe-476"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-011: Trusting Client-Side Validation Only
// ---------------------------------------------------------------------------

type ClientSideValidationOnly struct{}

func (r *ClientSideValidationOnly) ID() string                     { return "BATOU-VAL-011" }
func (r *ClientSideValidationOnly) Name() string                   { return "ClientSideValidationOnly" }
func (r *ClientSideValidationOnly) DefaultSeverity() rules.Severity { return rules.High }
func (r *ClientSideValidationOnly) Description() string {
	return "Detects code comments or patterns indicating reliance on client-side validation only, without server-side validation."
}
func (r *ClientSideValidationOnly) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *ClientSideValidationOnly) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		matched := ""
		if loc := reClientSideOnly.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		} else if loc := reNoServerVal.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Reliance on client-side validation only",
				Description:   "Code indicates validation is performed only on the client side. Client-side validation can be trivially bypassed by modifying requests directly. All input validation must be duplicated on the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Always implement server-side validation that mirrors client-side checks. Client-side validation is for UX only and provides no security. Validate all input on the server before processing.",
				CWEID:         "CWE-602",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"validation", "client-side", "cwe-602"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-012: Type Confusion from Unvalidated JSON Parsing
// ---------------------------------------------------------------------------

type TypeConfusionJSON struct{}

func (r *TypeConfusionJSON) ID() string                     { return "BATOU-VAL-012" }
func (r *TypeConfusionJSON) Name() string                   { return "TypeConfusionJSON" }
func (r *TypeConfusionJSON) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TypeConfusionJSON) Description() string {
	return "Detects JSON.parse of user input used directly without type validation, which can lead to type confusion vulnerabilities."
}
func (r *TypeConfusionJSON) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *TypeConfusionJSON) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		matched := ""
		if loc := reJSONParseDirect.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		} else if loc := reJSONParseAccess.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		}
		if matched != "" {
			if scopeHasPattern(lines, i, reTypeCheckAfter, 5) {
				continue
			}
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JSON.parse result used without type validation",
				Description:   "JSON.parse returns dynamic types (object, array, string, number, boolean, null). Using the parsed result without type checking can cause type confusion, where an attacker sends an unexpected type (e.g., array instead of object) to bypass security logic.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate the type of parsed JSON before use. Use typeof checks, Array.isArray(), or a schema validation library (zod, ajv, joi) to ensure the parsed data matches expected types.",
				CWEID:         "CWE-843",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"validation", "type-confusion", "json", "cwe-843"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-013: Missing Array Bounds Check
// ---------------------------------------------------------------------------

type MissingArrayBoundsCheck struct{}

func (r *MissingArrayBoundsCheck) ID() string                     { return "BATOU-VAL-013" }
func (r *MissingArrayBoundsCheck) Name() string                   { return "MissingArrayBoundsCheck" }
func (r *MissingArrayBoundsCheck) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingArrayBoundsCheck) Description() string {
	return "Detects array indexing with variable indices without bounds checking, which can cause out-of-bounds access."
}
func (r *MissingArrayBoundsCheck) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP, rules.LangGo, rules.LangJava}
}

func (r *MissingArrayBoundsCheck) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reArrayIndexVar.FindStringIndex(line); loc != nil {
			if scopeHasPattern(lines, i, reBoundsCheck, 5) {
				continue
			}
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Array index access without bounds check",
				Description:   "An array is accessed using a variable index without verifying the index is within bounds. In C/C++ this causes undefined behavior and potential memory corruption. In managed languages it causes runtime exceptions.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Check array bounds before indexing: if (idx >= 0 && idx < len(arr)). In C/C++, bounds checks are essential to prevent buffer overflows.",
				CWEID:         "CWE-129",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"validation", "bounds-check", "array", "cwe-129"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&MissingInputLengthValidation{})
	rules.Register(&ReDoSPattern{})
	rules.Register(&IntegerOverflowConversion{})
	rules.Register(&EmailRegexOnlyValidation{})
	rules.Register(&MissingNullCheck{})
	rules.Register(&ClientSideValidationOnly{})
	rules.Register(&TypeConfusionJSON{})
	rules.Register(&MissingArrayBoundsCheck{})
}
