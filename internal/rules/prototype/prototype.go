package prototype

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-PROTO-001: Prototype pollution via merge/extend/deep copy
var (
	// Lodash/underscore deep merge with user input
	jsMergeUserInput = regexp.MustCompile(`(?:_\.merge|_\.defaultsDeep|_\.extend|lodash\.merge|deepmerge|deep[Mm]erge|deepExtend|deep[Ee]xtend)\s*\([^,]*,\s*(?:req\.body|req\.query|req\.params|request\.body|userInput|user[Ii]nput|input|body|payload)`)
	// Object.assign with user input into model/target
	jsObjectAssignUser = regexp.MustCompile(`Object\.assign\s*\([^,]*,\s*(?:req\.body|req\.query|req\.params|request\.body|userInput|user[Ii]nput|input|body|payload)`)
	// Spread operator with user input: {...obj, ...req.body}
	jsSpreadUserInput = regexp.MustCompile(`\{\s*\.\.\.[\w.]+\s*,\s*\.\.\.(?:req\.body|req\.query|req\.params|request\.body|userInput|user[Ii]nput|input|body|payload)`)
	// Generic recursive merge pattern
	jsRecursiveMerge = regexp.MustCompile(`(?:merge|extend|assign|mixin)\s*\([^)]*(?:req\.body|req\.query|req\.params|request\.body)`)
)

// GTSS-PROTO-002: Direct __proto__ / constructor.prototype assignment
var (
	jsProtoAssign       = regexp.MustCompile(`\b\w+\s*\[\s*['"]__proto__['"]\s*\]`)
	jsProtoDirectAccess = regexp.MustCompile(`\.__proto__\s*=`)
	jsConstructorProto  = regexp.MustCompile(`\.constructor\s*\.\s*prototype`)
	// Dynamic property assignment with bracket notation where key comes from user input
	jsDynPropUserInput = regexp.MustCompile(`\w+\s*\[\s*(?:req\.body|req\.query|req\.params|request\.body|userInput|user[Ii]nput|key|prop|param)\s*(?:\[\s*['"]?\w+['"]?\s*\])?\s*\]\s*=`)
)

func init() {
	rules.Register(&PrototypePollutionMerge{})
	rules.Register(&PrototypePollutionDirect{})
}

// --- GTSS-PROTO-001: Prototype Pollution via Merge/Extend ---

type PrototypePollutionMerge struct{}

func (r *PrototypePollutionMerge) ID() string               { return "GTSS-PROTO-001" }
func (r *PrototypePollutionMerge) Name() string              { return "PrototypePollutionMerge" }
func (r *PrototypePollutionMerge) DefaultSeverity() rules.Severity { return rules.High }
func (r *PrototypePollutionMerge) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PrototypePollutionMerge) Description() string {
	return "Detects deep merge/extend operations with user-controlled input that may enable prototype pollution attacks."
}

func (r *PrototypePollutionMerge) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string

		// Check deep merge with user input (highest confidence)
		if loc := jsMergeUserInput.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
		}

		// Check Object.assign with user input
		if matched == "" {
			if loc := jsObjectAssignUser.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
			}
		}

		// Check spread with user input
		if matched == "" {
			if loc := jsSpreadUserInput.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
			}
		}

		// Check generic recursive merge with user input
		if matched == "" {
			if loc := jsRecursiveMerge.FindString(line); loc != "" {
				// Only match if not already caught by more specific patterns
				if !jsMergeUserInput.MatchString(line) {
					matched = loc
					confidence = "low"
				}
			}
		}

		if matched != "" {
			// Check for sanitization nearby
			if hasProtoPollutionSanitization(lines, i) {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Prototype pollution via deep merge/extend with user input",
				Description:   "User-controlled input is passed to a deep merge, extend, or Object.assign operation. An attacker could inject __proto__ properties to pollute Object.prototype, affecting all objects in the application.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a safe merge function that skips __proto__ and constructor properties. Consider using Object.create(null) for merge targets, or validate/sanitize input keys before merging.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"prototype-pollution", "merge", "user-input"},
			})
		}
	}

	return findings
}

// --- GTSS-PROTO-002: Direct __proto__ Assignment ---

type PrototypePollutionDirect struct{}

func (r *PrototypePollutionDirect) ID() string               { return "GTSS-PROTO-002" }
func (r *PrototypePollutionDirect) Name() string              { return "PrototypePollutionDirect" }
func (r *PrototypePollutionDirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *PrototypePollutionDirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PrototypePollutionDirect) Description() string {
	return "Detects direct access to __proto__ or constructor.prototype properties, which may indicate prototype pollution."
}

func (r *PrototypePollutionDirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string
		var title string

		// Check __proto__ bracket access: obj["__proto__"]
		if loc := jsProtoAssign.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
			title = "Direct __proto__ property access via bracket notation"
		}

		// Check __proto__ direct assignment: obj.__proto__ =
		if matched == "" {
			if loc := jsProtoDirectAccess.FindString(line); loc != "" {
				matched = loc
				confidence = "high"
				title = "Direct __proto__ property assignment"
			}
		}

		// Check constructor.prototype access
		if matched == "" {
			if loc := jsConstructorProto.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
				title = "Access to constructor.prototype (prototype pollution vector)"
			}
		}

		// Check dynamic property assignment with user-controlled key
		if matched == "" {
			if loc := jsDynPropUserInput.FindString(line); loc != "" {
				matched = loc
				confidence = "medium"
				title = "Dynamic property assignment with user-controlled key"
			}
		}

		if matched != "" {
			// Skip if it's a defensive check (reading __proto__ to delete/check it)
			if isDefensiveProtoCheck(line) {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Direct access to __proto__ or constructor.prototype can be used to pollute the prototype chain, affecting all objects in the application and potentially leading to RCE or authentication bypass.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never allow user input to control property keys that could reach __proto__ or constructor.prototype. Use Map instead of plain objects for user-keyed data, or filter out dangerous keys.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"prototype-pollution", "proto-assignment"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func hasProtoPollutionSanitization(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 3
	if end > len(lines) {
		end = len(lines)
	}

	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "sanitize") || strings.Contains(lower, "safeMerge") ||
			strings.Contains(lower, "safe_merge") || strings.Contains(lower, "cleaninput") ||
			strings.Contains(lower, "clean_input") || strings.Contains(lower, "stripproto") ||
			strings.Contains(lower, "strip_proto") || strings.Contains(lower, "hasownproperty") ||
			strings.Contains(lower, "object.create(null)") {
			return true
		}
	}
	return false
}

func isDefensiveProtoCheck(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "delete") || strings.Contains(lower, "===") ||
		strings.Contains(lower, "!==") || strings.Contains(lower, "typeof") ||
		strings.Contains(lower, "hasownproperty") || strings.Contains(lower, "if (") ||
		strings.Contains(lower, "if(")
}

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
