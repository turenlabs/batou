package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// jsFilterAllFindings applies JavaScript/TypeScript-specific false-positive
// suppression to ALL findings (regex + taint + AST). This runs at the scanner
// level after dedup, so it can suppress regex rule findings that the taint-level
// filter in taintrule/rule.go cannot reach.
//
// The approach: for each finding, check if the surrounding code contains a
// safety pattern (safe API, sanitizer, guard, type coercion) that neutralizes
// the specific CWE. If so, suppress the finding entirely.
func jsFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")
	kept := make([]rules.Finding, 0, len(findings))

	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			kept = append(kept, f)
			continue
		}

		cwe := strings.TrimPrefix(f.CWEID, "CWE-")

		suppressed := false
		switch cwe {
		case "89": // SQL Injection
			suppressed = jsScanHasSQLGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = jsScanHasXSSGuard(lines, lineIdx)
		case "78": // Command Injection
			suppressed = jsScanHasCmdiGuard(lines, lineIdx)
		case "22": // Path Traversal
			suppressed = jsScanHasPathGuard(lines, lineIdx)
		case "918": // SSRF
			suppressed = jsScanHasSSRFGuard(lines, lineIdx)
		case "943": // NoSQL Injection
			suppressed = jsScanHasNoSQLGuard(lines, lineIdx)
		case "502": // Deserialization
			suppressed = jsScanHasDeserGuard(lines, lineIdx)
		case "1336": // SSTI
			suppressed = jsScanHasSSTIGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = jsScanHasRedirectGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// --- Regex patterns for scanner-level JS FP filtering ---

// SQL safety patterns
var jsScParamQuery = regexp.MustCompile(`\?\s*['"]?\s*,\s*\[`)
var jsScKnexBuilder = regexp.MustCompile(`knex\s*\(\s*['"]`)
var jsScKnexRawSafe = regexp.MustCompile(`knex\.raw\s*\([^,]*\?\s*['"]?\s*,\s*\[`)
var jsScSequelize = regexp.MustCompile(`replacements|bind\s*:`)
var jsScPrisma = regexp.MustCompile("Prisma\\.sql\\s*`")

// XSS safety patterns
var jsScHTMLSanitizer = regexp.MustCompile(`\b(?:escapeHtml|DOMPurify\.sanitize|validator\.escape|sanitizeHtml|he\.encode|he\.escape|encodeURIComponent|xss)\s*\(`)
var jsScResJSON = regexp.MustCompile(`res\.json\s*\(`)
var jsScJSONStringify = regexp.MustCompile(`JSON\.stringify\s*\(`)
var jsScContentType = regexp.MustCompile(`['"]application/json['"]`)

// Command injection safety patterns
var jsScExecFile = regexp.MustCompile(`\bexecFile\s*\(`)
var jsScSpawnSafe = regexp.MustCompile(`\bspawn\s*\(`)
var jsScShellTrue = regexp.MustCompile(`shell\s*:\s*true`)
var jsScDNS = regexp.MustCompile(`dns\.(?:lookup|resolve)\s*\(`)
var jsScFsAPI = regexp.MustCompile(`fs\.(?:appendFile|writeFile|readFile)\s*\(`)

// Path traversal safety patterns
var jsScPathBasename = regexp.MustCompile(`path\.basename\s*\(`)
var jsScPathResolve = regexp.MustCompile(`path\.(?:resolve|normalize)\s*\(`)
var jsScStartsWith = regexp.MustCompile(`\.startsWith\s*\(`)
var jsScSendFileRoot = regexp.MustCompile(`\.sendFile\s*\([^)]*\{\s*root\s*:`)

// SSRF safety patterns
var jsScNewURL = regexp.MustCompile(`new\s+URL\s*\(`)
var jsScHostname = regexp.MustCompile(`\.(?:hostname|origin|protocol)\b`)
var jsScValidatorIsURL = regexp.MustCompile(`validator\.isURL\s*\(`)

// NoSQL safety patterns
var jsScMongoSanitize = regexp.MustCompile(`mongo-sanitize|express-mongo-sanitize`)
var jsScEqOperator = regexp.MustCompile(`\$eq\s*:`)

// Type coercion and allowlist patterns
var jsScTypeCoerce = regexp.MustCompile(`\b(?:parseInt|parseFloat|Number|String)\s*\(|new\s+Date\s*\(`)
var jsScAllowlist = regexp.MustCompile(`(?i)(?:ALLOWED|VALID|whitelist|SAFE)\w*\.(?:includes|has)\s*\(`)
var jsScMapLookup = regexp.MustCompile(`[A-Z_]{2,}\[\w+\]`)
var jsScRegexGuard = regexp.MustCompile(`/\^[^/]+\$/|\.test\s*\(\s*\w+\s*\)`)
var jsScSchemaValid = regexp.MustCompile(`(?:schema|Schema)\.(?:parse|safeParse|validate)\s*\(|ajv\.validate|Joi\.validate`)

// Redirect safety patterns
var jsScRelativeGuard = regexp.MustCompile(`startsWith\s*\(\s*['"](?:http|//|https)`)

// Deser safety patterns
var jsScJSONParse = regexp.MustCompile(`JSON\.parse\s*\(`)
var jsScYAMLSafe = regexp.MustCompile(`yaml\.safeLoad\s*\(|YAML\.parse\s*\(`)

// SSTI safety patterns
var jsScEJSStatic = regexp.MustCompile(`ejs\.render\s*\(\s*['"]`)
var jsScResRender = regexp.MustCompile(`res\.render\s*\(\s*['"]`)
var jsScHandlebars = regexp.MustCompile(`Handlebars\.compile\s*\(`)

// --- Per-CWE guard checks ---

func jsScanHasSQLGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScParamQuery.MatchString(line) || jsScKnexBuilder.MatchString(line) ||
			jsScKnexRawSafe.MatchString(line) || jsScSequelize.MatchString(line) ||
			jsScPrisma.MatchString(line) {
			return true
		}
	}
	return jsScanHasTypeCoercion(lines, sinkLine) || jsScanHasAllowlist(lines, sinkLine)
}

func jsScanHasXSSGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScHTMLSanitizer.MatchString(line) || jsScResJSON.MatchString(line) ||
			jsScJSONStringify.MatchString(line) || jsScContentType.MatchString(line) {
			return true
		}
	}
	return false
}

func jsScanHasCmdiGuard(lines []string, sinkLine int) bool {
	hasSpawn := false
	hasShellTrue := false
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScExecFile.MatchString(line) || jsScDNS.MatchString(line) ||
			jsScFsAPI.MatchString(line) {
			return true
		}
		if jsScSpawnSafe.MatchString(line) {
			hasSpawn = true
		}
		if jsScShellTrue.MatchString(line) {
			hasShellTrue = true
		}
	}
	// spawn() is safe only without shell: true
	if hasSpawn && !hasShellTrue {
		return true
	}
	return jsScanHasTypeCoercion(lines, sinkLine) ||
		jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

func jsScanHasPathGuard(lines []string, sinkLine int) bool {
	hasResolve := false
	hasStartsWith := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScPathBasename.MatchString(line) || jsScSendFileRoot.MatchString(line) {
			return true
		}
		if jsScPathResolve.MatchString(line) {
			hasResolve = true
		}
		if jsScStartsWith.MatchString(line) {
			hasStartsWith = true
		}
	}
	if hasResolve && hasStartsWith {
		return true
	}
	return jsScanHasTypeCoercion(lines, sinkLine) ||
		jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

// jsScHardcodedBaseURL matches hardcoded base URL constants used to prefix user path
var jsScHardcodedBaseURL = regexp.MustCompile(`(?:const|let|var)\s+\w+\s*=\s*['"]https?://`)

// jsScRegexReplace matches .replace() with regex to strip dangerous chars
var jsScRegexReplace = regexp.MustCompile(`\.replace\s*\(\s*/[^/]+/`)

func jsScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasURLParse := false
	hasHostCheck := false
	hasHardcodedBase := false
	hasRegexReplace := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScValidatorIsURL.MatchString(line) {
			return true
		}
		if jsScNewURL.MatchString(line) {
			hasURLParse = true
		}
		if jsScHostname.MatchString(line) {
			hasHostCheck = true
		}
		if jsScHardcodedBaseURL.MatchString(line) {
			hasHardcodedBase = true
		}
		if jsScRegexReplace.MatchString(line) {
			hasRegexReplace = true
		}
	}
	if hasURLParse && hasHostCheck {
		return true
	}
	// Hardcoded base URL + regex sanitization of the path component
	if hasHardcodedBase && hasRegexReplace {
		return true
	}
	return jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

func jsScanHasNoSQLGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScMongoSanitize.MatchString(line) || jsScSchemaValid.MatchString(line) ||
			jsScEqOperator.MatchString(line) {
			return true
		}
	}
	return jsScanHasTypeCoercion(lines, sinkLine)
}

func jsScanHasDeserGuard(lines []string, sinkLine int) bool {
	end := sinkLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	for i := max(0, sinkLine-10); i < end; i++ {
		line := lines[i]
		if jsScJSONParse.MatchString(line) || jsScYAMLSafe.MatchString(line) ||
			jsScSchemaValid.MatchString(line) {
			return true
		}
	}
	return jsScanHasAllowlist(lines, sinkLine)
}

func jsScanHasSSTIGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScEJSStatic.MatchString(line) || jsScResRender.MatchString(line) ||
			jsScHandlebars.MatchString(line) || jsScResJSON.MatchString(line) ||
			jsScJSONStringify.MatchString(line) {
			return true
		}
	}
	return jsScanHasAllowlist(lines, sinkLine)
}

func jsScanHasRedirectGuard(lines []string, sinkLine int) bool {
	hasURLParse := false
	hasCheck := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScRelativeGuard.MatchString(line) {
			return true
		}
		if jsScNewURL.MatchString(line) {
			hasURLParse = true
		}
		if jsScHostname.MatchString(line) || jsScStartsWith.MatchString(line) {
			hasCheck = true
		}
	}
	if hasURLParse && hasCheck {
		return true
	}
	return jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

// --- Shared helpers ---

func jsScanHasTypeCoercion(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if jsScTypeCoerce.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func jsScanHasAllowlist(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScAllowlist.MatchString(line) || jsScMapLookup.MatchString(line) {
			return true
		}
	}
	return false
}

func jsScanHasRegexGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if jsScRegexGuard.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

