package prototype

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended prototype pollution rules
// ---------------------------------------------------------------------------

// BATOU-PROTO-003: Object.assign with user-controlled source
var (
	reObjAssignUserCtrl = regexp.MustCompile(`Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.body|req\.query|req\.params|request\.body|JSON\.parse|body|payload|input|data)\b`)
)

// BATOU-PROTO-004: Lodash merge/defaultsDeep with untrusted input
var (
	reLodashMergeInput = regexp.MustCompile(`(?:_\.merge|_\.defaultsDeep|_\.assign|_\.assignIn|_\.extend|lodash\.merge|lodash\.defaultsDeep|require\s*\(\s*['"]lodash['"]\s*\)\s*\.(?:merge|defaultsDeep))\s*\([^,]*,\s*(?:req\.|request\.|body|payload|input|data|JSON\.parse)`)
)

// BATOU-PROTO-005: JSON.parse of user input assigned to object
var (
	reJSONParseAssign = regexp.MustCompile(`(?:Object\.assign|\.\.\.JSON\.parse|merge|extend|assign)\s*(?:\(\s*\w+\s*,\s*)?JSON\.parse\s*\(\s*(?:req\.body|req\.query|request\.body|body|payload|input|data|decodeURIComponent)`)
	reJSONParseSpread = regexp.MustCompile(`\{\s*\.\.\.JSON\.parse\s*\(\s*(?:req\.|request\.|body|payload|input|data|decodeURIComponent)`)
)

// BATOU-PROTO-006: Recursive merge/extend without proto check
var (
	reRecursiveMerge  = regexp.MustCompile(`(?i)function\s+(?:deep[Mm]erge|merge[Dd]eep|recursive[Mm]erge|extend[Dd]eep|deep[Ee]xtend|deep[Cc]opy|deepAssign)\s*\(`)
	reRecursiveMergeArrow = regexp.MustCompile(`(?i)(?:deep[Mm]erge|merge[Dd]eep|recursive[Mm]erge|extend[Dd]eep|deep[Ee]xtend)\s*=\s*(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>`)
	reProtoGuard      = regexp.MustCompile(`(?i)(?:__proto__|constructor|prototype)\b`)
)

// BATOU-PROTO-007: __proto__ or constructor.prototype in user input
var (
	reProtoInInput   = regexp.MustCompile(`(?:__proto__|constructor\.prototype)\s*(?:[:=]|['"]\s*[:=])`)
	reProtoInJSON    = regexp.MustCompile(`['"](?:__proto__|constructor)['"]`)
	reProtoPayload   = regexp.MustCompile(`\{\s*['"]__proto__['"]`)
)

// BATOU-PROTO-008: Prototype pollution via query parameter parsing
var (
	reQueryParserCustom   = regexp.MustCompile(`(?i)(?:qs\.parse|querystring\.parse|url\.parse|URLSearchParams)\s*\(`)
	reQueryToObj          = regexp.MustCompile(`(?i)(?:qs\.parse|querystring\.parse)\s*\(\s*(?:req\.url|req\.query|request\.url|location\.search|window\.location)`)
	reQSProtoFilter       = regexp.MustCompile(`(?i)(?:allowPrototypes\s*:\s*false|parameterLimit|depth\s*:\s*\d)`)
)

// ---------------------------------------------------------------------------
// BATOU-PROTO-003: Object.assign with User-Controlled Source
// ---------------------------------------------------------------------------

type ProtoObjAssignUser struct{}

func (r *ProtoObjAssignUser) ID() string                     { return "BATOU-PROTO-003" }
func (r *ProtoObjAssignUser) Name() string                   { return "ProtoObjAssignUser" }
func (r *ProtoObjAssignUser) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoObjAssignUser) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoObjAssignUser) Description() string {
	return "Detects Object.assign() with user-controlled source objects, which can enable prototype pollution if the source contains __proto__ keys."
}

func (r *ProtoObjAssignUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := reObjAssignUserCtrl.FindString(line); loc != "" {
			if hasProtoPollutionSanitization(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Object.assign with user-controlled source (prototype pollution risk)",
				Description:   "Object.assign() copies all enumerable own properties from source to target. If the source is user-controlled and contains __proto__ or constructor properties, it can pollute the Object prototype, affecting all objects in the application.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Validate user input to strip __proto__ and constructor keys before passing to Object.assign(). Use Object.create(null) for the target, or use a safe merge library that filters prototype-polluting keys.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"prototype-pollution", "object-assign", "cwe-1321"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-004: Lodash merge/defaultsDeep with Untrusted Input
// ---------------------------------------------------------------------------

type ProtoLodashMerge struct{}

func (r *ProtoLodashMerge) ID() string                     { return "BATOU-PROTO-004" }
func (r *ProtoLodashMerge) Name() string                   { return "ProtoLodashMerge" }
func (r *ProtoLodashMerge) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoLodashMerge) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoLodashMerge) Description() string {
	return "Detects lodash merge/defaultsDeep/assign with untrusted input. Older lodash versions are vulnerable to prototype pollution via these functions."
}

func (r *ProtoLodashMerge) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := reLodashMergeInput.FindString(line); loc != "" {
			if hasProtoPollutionSanitization(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Lodash merge/defaultsDeep with untrusted input (prototype pollution)",
				Description:   "Lodash merge, defaultsDeep, and similar functions recursively merge objects including __proto__ properties. CVE-2018-16487 and CVE-2019-10744 demonstrated prototype pollution through these functions. If user input is merged, attackers can pollute Object.prototype.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Update lodash to >= 4.17.12 which mitigates some prototype pollution vectors. Still, validate input to remove __proto__ and constructor keys before merging. Consider using structuredClone() or a safe alternative.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"prototype-pollution", "lodash", "merge", "cwe-1321"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-005: JSON.parse of User Input Assigned to Object
// ---------------------------------------------------------------------------

type ProtoJSONParseAssign struct{}

func (r *ProtoJSONParseAssign) ID() string                     { return "BATOU-PROTO-005" }
func (r *ProtoJSONParseAssign) Name() string                   { return "ProtoJSONParseAssign" }
func (r *ProtoJSONParseAssign) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ProtoJSONParseAssign) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoJSONParseAssign) Description() string {
	return "Detects JSON.parse of user input being spread or merged into objects, which can introduce __proto__ keys from the parsed JSON."
}

func (r *ProtoJSONParseAssign) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reJSONParseSpread.FindString(line); loc != "" {
			matched = loc
		} else if loc := reJSONParseAssign.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			if hasProtoPollutionSanitization(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JSON.parse of user input merged/spread into object",
				Description:   "User input is parsed with JSON.parse and then spread or merged into an object. JSON.parse preserves __proto__ keys from the JSON string, which can pollute the prototype when spread into an object.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a reviver function with JSON.parse to strip dangerous keys: JSON.parse(input, (key, val) => key === '__proto__' ? undefined : val). Or validate the parsed object before spreading.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"prototype-pollution", "json-parse", "cwe-1321"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-006: Recursive Merge/Extend Without Proto Check
// ---------------------------------------------------------------------------

type ProtoRecursiveMerge struct{}

func (r *ProtoRecursiveMerge) ID() string                     { return "BATOU-PROTO-006" }
func (r *ProtoRecursiveMerge) Name() string                   { return "ProtoRecursiveMerge" }
func (r *ProtoRecursiveMerge) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoRecursiveMerge) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoRecursiveMerge) Description() string {
	return "Detects custom recursive merge/extend functions that do not filter __proto__ or constructor keys, creating prototype pollution vectors."
}

func (r *ProtoRecursiveMerge) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reRecursiveMerge.FindString(line); loc != "" {
			matched = loc
		} else if loc := reRecursiveMergeArrow.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			// Check if the function body contains __proto__ guard
			end := i + 30
			if end > len(lines) {
				end = len(lines)
			}
			hasGuard := false
			for j := i; j < end; j++ {
				if reProtoGuard.MatchString(lines[j]) {
					hasGuard = true
					break
				}
			}
			if !hasGuard {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Recursive merge/extend function without __proto__ check",
					Description:   "A custom recursive merge or deep extend function does not filter __proto__, constructor, or prototype keys. Any caller passing user-controlled input to this function creates a prototype pollution vulnerability.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(matched, 120),
					Suggestion:    "Add __proto__ and constructor key filtering in the merge function: if (key === '__proto__' || key === 'constructor') continue. Or use Object.hasOwn(source, key) with an explicit skip list.",
					CWEID:         "CWE-1321",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"prototype-pollution", "recursive-merge", "cwe-1321"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-007: __proto__ or constructor.prototype in User Input
// ---------------------------------------------------------------------------

type ProtoInUserInput struct{}

func (r *ProtoInUserInput) ID() string                     { return "BATOU-PROTO-007" }
func (r *ProtoInUserInput) Name() string                   { return "ProtoInUserInput" }
func (r *ProtoInUserInput) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ProtoInUserInput) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoInUserInput) Description() string {
	return "Detects __proto__ or constructor.prototype references in code that handles user input, which is a direct indicator of prototype pollution vulnerability or exploit attempt."
}

func (r *ProtoInUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		// Skip defensive checks (delete, if, ===, !==)
		if isDefensiveProtoCheck(line) {
			continue
		}
		matched := ""
		if loc := reProtoPayload.FindString(line); loc != "" {
			matched = loc
		} else if loc := reProtoInInput.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "__proto__ or constructor.prototype reference in code (prototype pollution)",
				Description:   "Code contains __proto__ or constructor.prototype references in a non-defensive context. This is either an active prototype pollution vulnerability or test payload. Object prototype pollution can lead to RCE, authentication bypass, and property injection affecting all objects.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove __proto__ handling. Use Object.create(null) for property bags. Freeze prototypes with Object.freeze(Object.prototype). Use Map for user-keyed data instead of plain objects.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"prototype-pollution", "proto", "critical", "cwe-1321"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-008: Prototype Pollution via Query Parameter Parsing
// ---------------------------------------------------------------------------

type ProtoQueryParamParsing struct{}

func (r *ProtoQueryParamParsing) ID() string                     { return "BATOU-PROTO-008" }
func (r *ProtoQueryParamParsing) Name() string                   { return "ProtoQueryParamParsing" }
func (r *ProtoQueryParamParsing) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoQueryParamParsing) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoQueryParamParsing) Description() string {
	return "Detects query string parsing that may allow prototype pollution through nested object notation (e.g., ?__proto__[isAdmin]=true)."
}

func (r *ProtoQueryParamParsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := reQueryToObj.FindString(line); loc != "" {
			if reQSProtoFilter.MatchString(line) || reQSProtoFilter.MatchString(ctx.Content) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Query parameter parsing may allow prototype pollution",
				Description:   "Query string parsing with qs or querystring can create nested objects from bracket notation (e.g., ?__proto__[isAdmin]=true). Older versions of qs and some parsers allow __proto__ keys, enabling prototype pollution through URL parameters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use qs >= 6.10.0 with allowPrototypes: false (the default since 6.10). Set depth limit to prevent deeply nested objects: qs.parse(str, { depth: 5 }). Consider using URLSearchParams which does not create nested objects.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"prototype-pollution", "query-params", "qs", "cwe-1321"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&ProtoObjAssignUser{})
	rules.Register(&ProtoLodashMerge{})
	rules.Register(&ProtoJSONParseAssign{})
	rules.Register(&ProtoRecursiveMerge{})
	rules.Register(&ProtoInUserInput{})
	rules.Register(&ProtoQueryParamParsing{})
}
