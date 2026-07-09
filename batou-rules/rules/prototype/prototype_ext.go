package prototype

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
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
	reRecursiveMerge      = regexp.MustCompile(`(?i)function\s+(?:deep[Mm]erge|merge[Dd]eep|recursive[Mm]erge|extend[Dd]eep|deep[Ee]xtend|deep[Cc]opy|deepAssign)\s*\(`)
	reRecursiveMergeArrow = regexp.MustCompile(`(?i)(?:deep[Mm]erge|merge[Dd]eep|recursive[Mm]erge|extend[Dd]eep|deep[Ee]xtend)\s*=\s*(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>`)
	reProtoGuard          = regexp.MustCompile(`(?i)(?:__proto__|constructor|prototype)\b`)
)

// BATOU-PROTO-007: __proto__ or constructor.prototype in user input
var (
	reProtoInInput = regexp.MustCompile(`(?:__proto__|constructor\.prototype)\s*(?:[:=]|['"]\s*[:=])`)
	reProtoPayload = regexp.MustCompile(`\{\s*['"]__proto__['"]`)
)

// BATOU-PROTO-008: Prototype pollution via query parameter parsing
var (
	reQueryToObj    = regexp.MustCompile(`(?i)(?:qs\.parse|querystring\.parse)\s*\(\s*(?:req\.url|req\.query|request\.url|location\.search|window\.location)`)
	reQSProtoFilter = regexp.MustCompile(`(?i)(?:allowPrototypes\s*:\s*false|parameterLimit|depth\s*:\s*\d)`)
)

// ---------------------------------------------------------------------------
// BATOU-PROTO-003: Object.assign with User-Controlled Source
// ---------------------------------------------------------------------------

type ProtoObjAssignUser struct{}

func (r *ProtoObjAssignUser) ID() string                      { return "BATOU-PROTO-003" }
func (r *ProtoObjAssignUser) Name() string                    { return "ProtoObjAssignUser" }
func (r *ProtoObjAssignUser) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoObjAssignUser) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoObjAssignUser) Description() string {
	return "Detects Object.assign() with user-controlled source objects, which can enable prototype pollution if the source contains __proto__ keys."
}

func (r *ProtoObjAssignUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := rules.GFind(reObjAssignUserCtrl, line); loc != "" {
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

func (r *ProtoLodashMerge) ID() string                      { return "BATOU-PROTO-004" }
func (r *ProtoLodashMerge) Name() string                    { return "ProtoLodashMerge" }
func (r *ProtoLodashMerge) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoLodashMerge) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoLodashMerge) Description() string {
	return "Detects lodash merge/defaultsDeep/assign with untrusted input. Older lodash versions are vulnerable to prototype pollution via these functions."
}

func (r *ProtoLodashMerge) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := rules.GFind(reLodashMergeInput, line); loc != "" {
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

func (r *ProtoJSONParseAssign) ID() string                      { return "BATOU-PROTO-005" }
func (r *ProtoJSONParseAssign) Name() string                    { return "ProtoJSONParseAssign" }
func (r *ProtoJSONParseAssign) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ProtoJSONParseAssign) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoJSONParseAssign) Description() string {
	return "Detects JSON.parse of user input being spread or merged into objects, which can introduce __proto__ keys from the parsed JSON."
}

func (r *ProtoJSONParseAssign) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := rules.GFind(reJSONParseSpread, line); loc != "" {
			matched = loc
		} else if loc := rules.GFind(reJSONParseAssign, line); loc != "" {
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

func (r *ProtoRecursiveMerge) ID() string                      { return "BATOU-PROTO-006" }
func (r *ProtoRecursiveMerge) Name() string                    { return "ProtoRecursiveMerge" }
func (r *ProtoRecursiveMerge) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoRecursiveMerge) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoRecursiveMerge) Description() string {
	return "Detects custom recursive merge/extend functions that do not filter __proto__ or constructor keys, creating prototype pollution vectors."
}

func (r *ProtoRecursiveMerge) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := rules.GFind(reRecursiveMerge, line); loc != "" {
			matched = loc
		} else if loc := rules.GFind(reRecursiveMergeArrow, line); loc != "" {
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

func (r *ProtoInUserInput) ID() string                      { return "BATOU-PROTO-007" }
func (r *ProtoInUserInput) Name() string                    { return "ProtoInUserInput" }
func (r *ProtoInUserInput) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ProtoInUserInput) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoInUserInput) Description() string {
	return "Detects __proto__ or constructor.prototype references in code that handles user input, which is a direct indicator of prototype pollution vulnerability or exploit attempt."
}

func (r *ProtoInUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		// Skip defensive checks (delete, if, ===, !==)
		if isDefensiveProtoCheck(line) {
			continue
		}
		matched := ""
		if loc := rules.GFind(reProtoPayload, line); loc != "" {
			matched = loc
		} else if loc := rules.GFind(reProtoInInput, line); loc != "" {
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

func (r *ProtoQueryParamParsing) ID() string                      { return "BATOU-PROTO-008" }
func (r *ProtoQueryParamParsing) Name() string                    { return "ProtoQueryParamParsing" }
func (r *ProtoQueryParamParsing) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoQueryParamParsing) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoQueryParamParsing) Description() string {
	return "Detects query string parsing that may allow prototype pollution through nested object notation (e.g., ?__proto__[isAdmin]=true)."
}

func (r *ProtoQueryParamParsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := rules.GFind(reQueryToObj, line); loc != "" {
			if rules.GMatch(reQSProtoFilter, line) || rules.GMatchFile(reQSProtoFilter, ctx) {
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
// BATOU-PROTO-009: Lodash prototype-pollution sinks with import evidence
// ---------------------------------------------------------------------------
// Targets the CVE-2018-16487 / CVE-2019-10744 / CVE-2020-8203 sink shape
// WITHOUT requiring user input on the same line. The taint engine fails to
// track req.body through `app.post(callback)` wrapped handlers, so the
// existing BATOU-PROTO-001/004 (which demand `req.body` on the same line as
// the sink) misses the bench fixtures. This rule fires when:
//
//   1. The file imports lodash (require('lodash') OR import ... 'lodash').
//   2. A lodash prototype-pollution sink (_.defaultsDeep/_.merge/_.set/etc.)
//      is called with a non-string-literal first/second arg (i.e. a
//      variable, ruling out the safe-shape `_.template("Hello")`).
//
// Confidence: medium (regex tier only). Safe-fixtures use Object.assign with
// a literal hash + sanitized var, so neither (1) nor (2) holds.

var (
	reJSLodashImport = regexp.MustCompile(`(?:require\s*\(\s*['"]lodash['"]\s*\)|from\s+['"]lodash['"]|from\s+['"]lodash/(?:defaultsDeep|merge|mergeWith|set|setWith|zipObjectDeep)['"])`)
	// Sinks whose first arg is the *target* (so the second arg or any
	// following arg being a variable is the dangerous shape). Match the
	// entire call form `_.defaultsDeep(<arg>, <arg>...)` then verify in code
	// that there's at least one non-literal arg.
	reJSLodashProtoSink = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(_\.(?:defaultsDeep|merge|mergeWith|set|setWith|zipObjectDeep)|lodash\.(?:defaultsDeep|merge|mergeWith|set|setWith|zipObjectDeep))\s*\(`)
)

type ProtoLodashSinkImported struct{}

func (r *ProtoLodashSinkImported) ID() string                      { return "BATOU-PROTO-009" }
func (r *ProtoLodashSinkImported) Name() string                    { return "ProtoLodashSinkImported" }
func (r *ProtoLodashSinkImported) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoLodashSinkImported) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoLodashSinkImported) Description() string {
	return "Lodash prototype-pollution sink (_.defaultsDeep/_.merge/_.set/_.setWith/_.mergeWith/_.zipObjectDeep) invoked in a file that imports lodash — known sink shape from CVE-2018-16487 / CVE-2019-10744 / CVE-2020-8203."
}

func (r *ProtoLodashSinkImported) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Cheap file-scope gate first: only proceed if lodash is imported AND
	// a sink is referenced anywhere in the file.
	if !rules.GMatchFile(reJSLodashImport, ctx) {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		m := reJSLodashProtoSink.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		// Skip the safe shape: every call argument is a string literal
		// (e.g. `_.set(config, 'theme', 'light')`). The vulnerable shape
		// passes a variable as either the path or the value.
		argRegion := line[m[1]:]
		if !containsNonLiteralArg(argRegion) {
			continue
		}
		if hasProtoPollutionSanitization(lines, i) {
			continue
		}
		matched := line[m[2]:m[3]]
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Lodash prototype-pollution sink invoked with a variable argument",
			Description:   "Lodash _.defaultsDeep / _.merge / _.mergeWith / _.set / _.setWith / _.zipObjectDeep recursively assign user-controlled keys into a target. Older lodash versions (< 4.17.20) walk __proto__/constructor segments unconditionally; the safe pattern is to never pass attacker-derived objects or paths to these functions. CVE-2018-16487 / CVE-2019-10744 / CVE-2020-8203.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Sanitize the source object/path: drop __proto__/constructor/prototype keys before the call, or replace the sink with a shallow Object.assign({}, target, sanitized).",
			CWEID:         "CWE-1321",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"prototype-pollution", "lodash", "cwe-1321"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-010: hapi/Hoek prototype-pollution sinks with import evidence
// ---------------------------------------------------------------------------
// Same approach as BATOU-PROTO-009 but for hapi Hoek.merge /
// Hoek.applyToDefaults — CVE-2018-3728.

var (
	reJSHoekImport = regexp.MustCompile(`(?:require\s*\(\s*['"](?:@hapi/hoek|hoek)['"]\s*\)|from\s+['"](?:@hapi/hoek|hoek)['"])`)
	reJSHoekSink   = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])((?:Hoek|hoek|@hapi/hoek)\.(?:merge|applyToDefaults))\s*\(`)
)

type ProtoHoekSinkImported struct{}

func (r *ProtoHoekSinkImported) ID() string                      { return "BATOU-PROTO-010" }
func (r *ProtoHoekSinkImported) Name() string                    { return "ProtoHoekSinkImported" }
func (r *ProtoHoekSinkImported) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoHoekSinkImported) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoHoekSinkImported) Description() string {
	return "hapi Hoek.merge / Hoek.applyToDefaults invoked in a file that imports hoek — known sink shape from CVE-2018-3728."
}

func (r *ProtoHoekSinkImported) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !rules.GMatchFile(reJSHoekImport, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		m := reJSHoekSink.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		argRegion := line[m[1]:]
		if !containsNonLiteralArg(argRegion) {
			continue
		}
		if hasProtoPollutionSanitization(lines, i) {
			continue
		}
		matched := line[m[2]:m[3]]
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Hoek.merge / Hoek.applyToDefaults invoked with a variable argument",
			Description:   "hapi Hoek.merge(target, source) and Hoek.applyToDefaults(defaults, options) recursively deep-copy a user-controlled source without filtering __proto__/constructor keys. CVE-2018-3728.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Upgrade to @hapi/hoek >= 8.5.1 or pre-sanitize the source object to drop __proto__/constructor/prototype keys.",
			CWEID:         "CWE-1321",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"prototype-pollution", "hoek", "cwe-1321"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PROTO-011: Handlebars.compile / _.template with non-literal source
// ---------------------------------------------------------------------------
// Catches:
//   - Handlebars.compile(req.body.template) — CVE-2019-19919 (CWE-1336)
//   - _.template(req.body.template)        — CVE-2021-23337 (CWE-94)
// Both safe-fixture variants pass a string literal as the source; we skip
// those by requiring the first arg to start with an identifier (not a
// quote / template-literal backtick).

var (
	reHandlebarsImport      = regexp.MustCompile(`(?:require\s*\(\s*['"]handlebars['"]\s*\)|from\s+['"]handlebars['"])`)
	reHandlebarsCompileCall = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])((?:Handlebars|handlebars)\.(?:compile|precompile))\s*\(`)
	reLodashTemplateCall    = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])((?:_|lodash)\.template)\s*\(`)
)

type ProtoTemplateNonLiteral struct{}

func (r *ProtoTemplateNonLiteral) ID() string                      { return "BATOU-PROTO-011" }
func (r *ProtoTemplateNonLiteral) Name() string                    { return "ProtoTemplateNonLiteral" }
func (r *ProtoTemplateNonLiteral) DefaultSeverity() rules.Severity { return rules.High }
func (r *ProtoTemplateNonLiteral) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProtoTemplateNonLiteral) Description() string {
	return "Handlebars.compile / _.template invoked with a non-string-literal source — CVE-2019-19919 (Handlebars SSTI) / CVE-2021-23337 (lodash _.template RCE)."
}

func (r *ProtoTemplateNonLiteral) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasHandlebars := rules.GMatchFile(reHandlebarsImport, ctx)
	hasLodash := rules.GMatchFile(reJSLodashImport, ctx)
	if !hasHandlebars && !hasLodash {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		emit := func(kind string, matchSpan []int, cwe string) {
			argRegion := line[matchSpan[1]:]
			if !firstArgIsNonLiteral(argRegion) {
				return
			}
			matched := line[matchSpan[2]:matchSpan[3]]
			title := "Handlebars.compile() with non-literal template source"
			desc := "Handlebars.compile(source) walks the template AST via lookups that traverse object properties. A request-controlled template body can escape the sandbox via __proto__/constructor (CVE-2019-19919). Compile templates from trusted code at startup."
			suggestion := "Upgrade handlebars to >= 4.7.7 and compile templates from in-process string literals at startup. Use a lookup table keyed by a validated identifier from the request."
			tag := "handlebars"
			if kind == "lodash-template" {
				title = "_.template() with non-literal source — direct RCE"
				desc = "lodash _.template(src) compiles the source via new Function(...), so a request-controlled template body is direct RCE (CVE-2021-23337)."
				suggestion = "Compile templates from in-process string literals at startup and only allow callers to choose between them by name."
				tag = "lodash-template"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    suggestion,
				CWEID:         cwe,
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ssti", tag, strings.ToLower(strings.TrimPrefix(cwe, "CWE-"))},
			})
		}

		if hasHandlebars {
			if m := reHandlebarsCompileCall.FindStringSubmatchIndex(line); m != nil {
				emit("handlebars-compile", m, "CWE-1336")
			}
		}
		if hasLodash {
			if m := reLodashTemplateCall.FindStringSubmatchIndex(line); m != nil {
				emit("lodash-template", m, "CWE-94")
			}
		}
	}
	return findings
}

// containsNonLiteralArg reports true when the arg-region (everything from
// the opening "(" forward) contains a non-literal arg after the first
// positional arg (which is the target/path receiver — typically a variable
// like `config` or `obj` regardless of safety). The first arg is skipped
// because it is conventionally the *target* of the merge/set call: a target
// var is mandatory for any real call (safe or not), so checking it tells us
// nothing about whether attacker data flows in.
//
// Used to distinguish the vulnerable shape `_.set(obj, fieldPath, value)`
// (non-literal in args 1+ → flag) from the safe shape
// `_.set(config, "theme", "light")` (all later args are string literals).
func containsNonLiteralArg(argRegion string) bool {
	depth := 0
	argIndex := 0 // 0-based position in the argument list
	argStart := true
	for i := 0; i < len(argRegion); i++ {
		c := argRegion[i]
		switch {
		case c == '(':
			depth++
			argStart = false
		case c == ')':
			if depth == 0 {
				return false
			}
			depth--
		case c == ',' && depth == 0:
			argStart = true
			argIndex++
		case c == ' ' || c == '\t':
			// skip
		case c == '"' || c == '\'' || c == '`':
			// String literal — skip its content but consume the closing quote.
			quote := c
			i++
			for i < len(argRegion) {
				if argRegion[i] == '\\' && i+1 < len(argRegion) {
					i += 2
					continue
				}
				if argRegion[i] == quote {
					break
				}
				i++
			}
			argStart = false
		default:
			if argStart {
				// Skip arg 0 (the target / receiver). A variable target
				// alone doesn't indicate the vulnerable shape.
				if argIndex == 0 {
					argStart = false
					continue
				}
				if isLiteralStart(argRegion[i:]) {
					argStart = false
					continue
				}
				return true
			}
		}
	}
	return false
}

// firstArgIsNonLiteral reports whether the first argument in the arg-region
// (everything from the opening "(" forward) is a non-string-literal — i.e.
// the call is NOT `Handlebars.compile("...")` / `_.template("Hello")`.
func firstArgIsNonLiteral(argRegion string) bool {
	for i := 0; i < len(argRegion); i++ {
		c := argRegion[i]
		if c == ' ' || c == '\t' {
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			return false
		}
		// Numeric, true/false/null literals — treat as literal too.
		if isLiteralStart(argRegion[i:]) {
			return false
		}
		return true
	}
	return false
}

func isLiteralStart(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	if c >= '0' && c <= '9' {
		return true
	}
	for _, kw := range []string{"true", "false", "null", "undefined"} {
		if strings.HasPrefix(s, kw) {
			if len(s) == len(kw) {
				return true
			}
			next := s[len(kw)]
			if !isIdentChar(next) {
				return true
			}
		}
	}
	return false
}

func isIdentChar(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
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
	rules.Register(&ProtoLodashSinkImported{})
	rules.Register(&ProtoHoekSinkImported{})
	rules.Register(&ProtoTemplateNonLiteral{})
}
