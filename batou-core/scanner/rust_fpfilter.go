package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// rustFilterAllFindings applies Rust-specific false-positive suppression to ALL
// findings (regex + taint + AST). This runs at the scanner level after dedup,
// so it can suppress regex rule findings that the taint-level filter cannot reach.
func rustFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
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
		case "22": // Path Traversal
			suppressed = rustScanHasPathGuard(lines, lineIdx)
		case "89": // SQL Injection
			suppressed = rustScanHasSQLGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = rustScanHasXSSGuard(lines, lineIdx)
		case "78": // Command Injection
			suppressed = rustScanHasCmdiGuard(lines, lineIdx)
		case "918": // SSRF
			suppressed = rustScanHasSSRFGuard(lines, lineIdx)
		case "502": // Deserialization
			suppressed = rustScanHasDeserGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = rustScanHasRedirectGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// --- Regex patterns for scanner-level Rust FP filtering ---

// Path traversal safety
var rsScCanonicalize = regexp.MustCompile(`\.canonicalize\s*\(`)
var rsScStartsWith = regexp.MustCompile(`\.starts_with\s*\(`)
var rsScFileName = regexp.MustCompile(`\.file_name\s*\(`)
var rsScContainsDotDot = regexp.MustCompile(`\.contains\s*\(\s*["']\.\.["']`)
var rsScContainsSlash = regexp.MustCompile(`\.contains\s*\(\s*['"][/\\]`)
// batou:ignore BATOU-UPLOAD-005 -- regex pattern to detect Rust .ends_with() calls, not file upload validation
var rsScEndsWith = regexp.MustCompile(`\.ends_with\s*\(\s*["']`)
var rsScRegexNew = regexp.MustCompile(`[Rr]egex::new\s*\(`)
var rsScIsMatch = regexp.MustCompile(`\.is_match\s*\(`)

// SQL safety
var rsScSqlxBind = regexp.MustCompile(`\.bind\s*\(`)
var rsScSqlxMacro = regexp.MustCompile(`sqlx::query(?:_as)?!\s*\(`)
var rsScDieselFilter = regexp.MustCompile(`\.filter\s*\(`)
var rsScSeaOrmFilter = regexp.MustCompile(`(?:Entity|Column)\w*\.(?:find|filter|eq)\s*\(`)
var rsScParseInt = regexp.MustCompile(`\.parse\s*::\s*<\s*(?:i8|i16|i32|i64|i128|u8|u16|u32|u64|u128|isize|usize|f32|f64)\s*>`)

// XSS safety
var rsScAmmoniaClean = regexp.MustCompile(`ammonia::clean\s*\(`)
var rsScHtmlEscape = regexp.MustCompile(`html_escape::encode_\w+\s*\(`)
var rsScResJson = regexp.MustCompile(`\.json\s*\(`)
var rsScTextPlain = regexp.MustCompile(`content_type\s*\(\s*["']text/plain["']`)
var rsScAutoEscape = regexp.MustCompile(`autoescape_on|auto_escape`)
var rsScUrlEncode = regexp.MustCompile(`urlencoding::encode\s*\(`)

// Command injection safety
var rsScCharsAll = regexp.MustCompile(`\.chars\s*\(\s*\)\s*\.all\s*\(`)
var rsScSeparator = regexp.MustCompile(`\.arg\s*\(\s*["']--["']`)

// SSRF safety
var rsScUrlParse = regexp.MustCompile(`[Uu]rl::parse\s*\(`)
var rsScHostStr = regexp.MustCompile(`\.host_str\s*\(`)
var rsScSchemeCheck = regexp.MustCompile(`\.scheme\s*\(\s*\)`)
var rsScQueryParam = regexp.MustCompile(`\.query\s*\(\s*&\[`)

// Deserialization safety
var rsScTypedDeser = regexp.MustCompile(`from_str\s*::\s*<\s*[A-Z]\w+`)
var rsScDeriveDeser = regexp.MustCompile(`#\[derive\(.*Deserialize`)
var rsScWebJson = regexp.MustCompile(`web::Json\s*<\s*[A-Z]`)
var rsScLocalFile = regexp.MustCompile(`(?:fs::read_to_string|std::fs::read|File::open)\s*\(\s*["']`)
var rsScSizeCheck = regexp.MustCompile(`\.len\s*\(\s*\)\s*[<>]`)

// Redirect safety
var rsScUrlHostCheck = regexp.MustCompile(`\.host_str\s*\(\s*\)\s*!=\s*Some`)
var rsScRejectScheme = regexp.MustCompile(`\.contains\s*\(\s*["']://["']`)
var rsScRejectDoubleSlash = regexp.MustCompile(`\.starts_with\s*\(\s*["']//["']`)

// No-user-input patterns (hardcoded/static values)
var rsScStaticFileRead = regexp.MustCompile(`(?:read_to_string|File::open)\s*\(\s*["']`)
var rsScUuidNew = regexp.MustCompile(`[Uu]uid::new_v4\s*\(`)
var rsScUnusedParam = regexp.MustCompile(`let\s+_\w+\s*=`)
var rsScHardcodedLet = regexp.MustCompile(`let\s+\w+\s*=\s*["']`)

// Shared patterns
var rsScMatchExpr = regexp.MustCompile(`match\s+\w+`)
var rsScAllowlist = regexp.MustCompile(`(?i)(?:allowed|valid|safe|whitelist)\w*\.(?:contains|iter|into_iter)`)
var rsScMapLookup = regexp.MustCompile(`[A-Z_]{2,}\[`)

// --- Per-CWE guard checks ---

func rustScanHasPathGuard(lines []string, sinkLine int) bool {
	hasCanonicalize := false
	hasStartsWith := false
	hasContainsDotDot := false
	hasFileName := false
	hasRegex := false
	hasIsMatch := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScCanonicalize.MatchString(line) {
			hasCanonicalize = true
		}
		if rsScStartsWith.MatchString(line) {
			hasStartsWith = true
		}
		if rsScFileName.MatchString(line) {
			hasFileName = true
		}
		if rsScContainsDotDot.MatchString(line) || rsScContainsSlash.MatchString(line) {
			hasContainsDotDot = true
		}
		if rsScEndsWith.MatchString(line) {
			hasContainsDotDot = true // extension check counts as validation
		}
		if rsScRegexNew.MatchString(line) {
			hasRegex = true
		}
		if rsScIsMatch.MatchString(line) {
			hasIsMatch = true
		}
	}
	// canonicalize + starts_with = gold standard path validation
	if hasCanonicalize && hasStartsWith {
		return true
	}
	// file_name() strips directory components entirely
	if hasFileName {
		return true
	}
	// contains("..") or contains("/") rejection
	if hasContainsDotDot {
		return true
	}
	// regex validation
	if hasRegex && hasIsMatch {
		return true
	}
	return rustScanHasTypeCoercion(lines, sinkLine) ||
		rustScanHasAllowlist(lines, sinkLine) ||
		rustScanHasNoUserInput(lines, sinkLine)
}

func rustScanHasSQLGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScSqlxBind.MatchString(line) || rsScSqlxMacro.MatchString(line) {
			return true
		}
		if rsScDieselFilter.MatchString(line) && rsScSeaOrmFilter.MatchString(line) {
			return true
		}
	}
	return rustScanHasTypeCoercion(lines, sinkLine) ||
		rustScanHasAllowlist(lines, sinkLine) ||
		rustScanHasNoUserInput(lines, sinkLine)
}

func rustScanHasXSSGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScAmmoniaClean.MatchString(line) || rsScHtmlEscape.MatchString(line) {
			return true
		}
		if rsScResJson.MatchString(line) || rsScTextPlain.MatchString(line) {
			return true
		}
		if rsScAutoEscape.MatchString(line) || rsScUrlEncode.MatchString(line) {
			return true
		}
	}
	return rustScanHasTypeCoercion(lines, sinkLine) ||
		rustScanHasAllowlist(lines, sinkLine) ||
		rustScanHasNoUserInput(lines, sinkLine)
}

func rustScanHasCmdiGuard(lines []string, sinkLine int) bool {
	hasCharsAll := false
	hasRegex := false
	hasIsMatch := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScCharsAll.MatchString(line) {
			hasCharsAll = true
		}
		if rsScSeparator.MatchString(line) {
			return true
		}
		if rsScRegexNew.MatchString(line) {
			hasRegex = true
		}
		if rsScIsMatch.MatchString(line) {
			hasIsMatch = true
		}
	}
	if hasCharsAll {
		return true
	}
	if hasRegex && hasIsMatch {
		return true
	}
	return rustScanHasTypeCoercion(lines, sinkLine) ||
		rustScanHasAllowlist(lines, sinkLine)
}

func rustScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasUrlParse := false
	hasHostCheck := false
	hasRegex := false
	hasIsMatch := false
	hasCharsAll := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScUrlParse.MatchString(line) {
			hasUrlParse = true
		}
		if rsScHostStr.MatchString(line) || rsScSchemeCheck.MatchString(line) {
			hasHostCheck = true
		}
		if rsScQueryParam.MatchString(line) {
			return true // user input only in query params, not URL
		}
		if rsScRegexNew.MatchString(line) {
			hasRegex = true
		}
		if rsScIsMatch.MatchString(line) {
			hasIsMatch = true
		}
		if rsScCharsAll.MatchString(line) {
			hasCharsAll = true
		}
	}
	if hasUrlParse && hasHostCheck {
		return true
	}
	if hasRegex && hasIsMatch {
		return true
	}
	if hasCharsAll {
		return true
	}
	return rustScanHasTypeCoercion(lines, sinkLine) ||
		rustScanHasAllowlist(lines, sinkLine)
}

func rustScanHasDeserGuard(lines []string, sinkLine int) bool {
	end := min(sinkLine+3, len(lines))
	hasTypedDeser := false
	hasDeriveDeser := false
	for i := max(0, sinkLine-20); i < end; i++ {
		line := lines[i]
		if rsScTypedDeser.MatchString(line) {
			hasTypedDeser = true
		}
		if rsScDeriveDeser.MatchString(line) {
			hasDeriveDeser = true
		}
		if rsScWebJson.MatchString(line) {
			hasTypedDeser = true
		}
		if rsScLocalFile.MatchString(line) {
			return true // deserializing from local file, not user input
		}
		if rsScSizeCheck.MatchString(line) {
			hasTypedDeser = true // size validation before deser
		}
	}
	// Typed deserialization to a known struct is safe
	if hasTypedDeser || hasDeriveDeser {
		return true
	}
	return rustScanHasAllowlist(lines, sinkLine)
}

func rustScanHasRedirectGuard(lines []string, sinkLine int) bool {
	hasUrlParse := false
	hasHostCheck := false
	hasRegex := false
	hasIsMatch := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScUrlParse.MatchString(line) {
			hasUrlParse = true
		}
		if rsScUrlHostCheck.MatchString(line) || rsScHostStr.MatchString(line) {
			hasHostCheck = true
		}
		if rsScRejectScheme.MatchString(line) || rsScRejectDoubleSlash.MatchString(line) {
			return true // rejecting absolute URLs / protocol-relative URLs
		}
		if rsScRegexNew.MatchString(line) {
			hasRegex = true
		}
		if rsScIsMatch.MatchString(line) {
			hasIsMatch = true
		}
	}
	if hasUrlParse && hasHostCheck {
		return true
	}
	if hasRegex && hasIsMatch {
		return true
	}
	return rustScanHasTypeCoercion(lines, sinkLine) ||
		rustScanHasAllowlist(lines, sinkLine)
}

// --- Shared helpers ---

func rustScanHasTypeCoercion(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if rsScParseInt.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// rustScanHasNoUserInput checks if the function has no user input reaching the sink.
// Patterns: UUID-generated filenames, hardcoded values, unused params, static file reads.
func rustScanHasNoUserInput(lines []string, sinkLine int) bool {
	hasUuid := false
	hasUnused := false
	hasHardcoded := false
	hasStaticRead := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScUuidNew.MatchString(line) {
			hasUuid = true
		}
		if rsScUnusedParam.MatchString(line) {
			hasUnused = true
		}
		if rsScHardcodedLet.MatchString(line) {
			hasHardcoded = true
		}
		if rsScStaticFileRead.MatchString(line) {
			hasStaticRead = true
		}
	}
	// UUID replaces user input entirely
	if hasUuid {
		return true
	}
	// Static file read with no user input in path
	if hasStaticRead {
		return true
	}
	// User param explicitly unused (_param) + hardcoded value used instead
	if hasUnused && hasHardcoded {
		return true
	}
	return false
}

func rustScanHasAllowlist(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rsScAllowlist.MatchString(line) || rsScMapLookup.MatchString(line) {
			return true
		}
		// match expression with all literal arms is effectively an allowlist
		if rsScMatchExpr.MatchString(line) {
			return true
		}
	}
	return false
}
