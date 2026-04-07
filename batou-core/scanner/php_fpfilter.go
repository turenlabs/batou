package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// phpFilterAllFindings applies PHP-specific false-positive suppression to ALL
// findings (regex + taint + AST). This runs at the scanner level after dedup,
// so it can suppress regex rule findings that the taint-level filter cannot
// reach.
func phpFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
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
			suppressed = phpScanHasPathGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = phpScanHasXSSGuard(lines, lineIdx)
		case "78": // Command Injection
			suppressed = phpScanHasCmdiGuard(lines, lineIdx)
		case "89": // SQL Injection
			suppressed = phpScanHasSQLGuard(lines, lineIdx)
		case "918": // SSRF
			suppressed = phpScanHasSSRFGuard(lines, lineIdx)
		case "502": // Deserialization
			suppressed = phpScanHasDeserGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = phpScanHasRedirectGuard(lines, lineIdx)
		case "1336": // SSTI
			suppressed = phpScanHasSSTIGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// --- Regex patterns for scanner-level PHP FP filtering ---

// Path traversal safety
var phpScRealpath = regexp.MustCompile(`\brealpath\s*\(`)
var phpScStrpos = regexp.MustCompile(`\bstrpos\s*\(`)
var phpScBasename = regexp.MustCompile(`\bbasename\s*\(`)
var phpScPathinfo = regexp.MustCompile(`\bpathinfo\s*\(`)

// XSS safety
var phpScHtmlspecialchars = regexp.MustCompile(`\bhtmlspecialchars\s*\(`)
var phpScHtmlentities = regexp.MustCompile(`\bhtmlentities\s*\(`)
var phpScStripTags = regexp.MustCompile(`\bstrip_tags\s*\(`)
var phpScJsonEncode = regexp.MustCompile(`\bjson_encode\s*\(`)
var phpScUrlencode = regexp.MustCompile(`\burlencode\s*\(`)

// Command injection safety
var phpScEscapeshellarg = regexp.MustCompile(`\bescapeshellarg\s*\(`)
var phpScEscapeshellcmd = regexp.MustCompile(`\bescapeshellcmd\s*\(`)

// SQL injection safety
var phpScPrepare = regexp.MustCompile(`->prepare\s*\(`)
var phpScBindParam = regexp.MustCompile(`->bind_param\s*\(`)
var phpScRealEscapeString = regexp.MustCompile(`->real_escape_string\s*\(`)
var phpScMysqliRealEscape = regexp.MustCompile(`\bmysqli_real_escape_string\s*\(`)

// SSRF safety
var phpScParseURL = regexp.MustCompile(`\bparse_url\s*\(`)
var phpScHostCheck = regexp.MustCompile(`\$parsed\s*\[\s*['"]host['"]\s*\]`)
var phpScInArray = regexp.MustCompile(`\bin_array\s*\(`)
var phpScFilterValidateIP = regexp.MustCompile(`FILTER_VALIDATE_IP|FILTER_FLAG_NO_PRIV_RANGE`)
var phpScHardcodedURL = regexp.MustCompile(`(?:file_get_contents|curl_init)\s*\(\s*["']https?://`)
var phpScHardcodedBaseURL = regexp.MustCompile(`["']https?://[^"']+["']\s*\.`)

// Deserialization safety
var phpScJsonDecode = regexp.MustCompile(`\bjson_decode\s*\(`)
var phpScAllowedClasses = regexp.MustCompile(`['"]allowed_classes['"]`)
var phpScUnserialize = regexp.MustCompile(`\bunserialize\s*\(`)

// Redirect safety
var phpScRelativeCheck = regexp.MustCompile(`\bstrpos\s*\([^,]+,\s*['"]//['"]`)
var phpScSlashPrefix = regexp.MustCompile(`strpos\s*\([^,]+,\s*['"]/['"]`)
var phpScParseURLPath = regexp.MustCompile(`\bparse_url\s*\([^,]+,\s*PHP_URL_PATH\b`)

// Type coercion (shared)
var phpScIntval = regexp.MustCompile(`\bintval\s*\(`)
var phpScIntCast = regexp.MustCompile(`\(\s*int\s*\)`)
var phpScFilterInput = regexp.MustCompile(`\bfilter_input\s*\(`)
var phpScFilterVar = regexp.MustCompile(`\bfilter_var\s*\(`)
var phpScFilterValidateInt = regexp.MustCompile(`FILTER_VALIDATE_INT`)
var phpScFilterSanitize = regexp.MustCompile(`FILTER_SANITIZE_`)
var phpScPregMatch = regexp.MustCompile(`\bpreg_match\s*\(`)

// Allowlist (shared)
var phpScAllowlist = regexp.MustCompile(`\b(?:allowed|valid|safe|whitelist|allowlist|allowable)\b`)
var phpScInArrayCheck = regexp.MustCompile(`\bin_array\s*\(`)

// --- Per-CWE guard checks ---

func phpScanHasPathGuard(lines []string, sinkLine int) bool {
	hasRealpath := false
	hasStrpos := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScBasename.MatchString(line) || phpScPathinfo.MatchString(line) {
			return true
		}
		if phpScRealpath.MatchString(line) {
			hasRealpath = true
		}
		if phpScStrpos.MatchString(line) {
			hasStrpos = true
		}
	}
	if hasRealpath && hasStrpos {
		return true
	}
	return phpScanHasTypeCoercion(lines, sinkLine) || phpScanHasAllowlist(lines, sinkLine)
}

func phpScanHasXSSGuard(lines []string, sinkLine int) bool {
	// Look both backward and forward (finding may fire on source line, sanitizer on output line)
	lo := max(0, sinkLine-15)
	hi := min(len(lines)-1, sinkLine+5)
	for i := lo; i <= hi; i++ {
		line := lines[i]
		if phpScHtmlspecialchars.MatchString(line) || phpScHtmlentities.MatchString(line) {
			return true
		}
		if phpScStripTags.MatchString(line) || phpScJsonEncode.MatchString(line) {
			return true
		}
		if phpScUrlencode.MatchString(line) {
			return true
		}
	}
	return phpScanHasTypeCoercion(lines, sinkLine)
}

func phpScanHasCmdiGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScEscapeshellarg.MatchString(line) || phpScEscapeshellcmd.MatchString(line) {
			return true
		}
	}
	return phpScanHasTypeCoercion(lines, sinkLine) || phpScanHasAllowlist(lines, sinkLine)
}

func phpScanHasSQLGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScPrepare.MatchString(line) || phpScBindParam.MatchString(line) {
			return true
		}
		if phpScRealEscapeString.MatchString(line) || phpScMysqliRealEscape.MatchString(line) {
			return true
		}
	}
	return phpScanHasTypeCoercion(lines, sinkLine)
}

func phpScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasParseURL := false
	hasHostCheck := false
	hasHardcodedBase := false
	hasURLEncode := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScHardcodedURL.MatchString(line) {
			return true
		}
		if phpScParseURL.MatchString(line) {
			hasParseURL = true
		}
		if phpScHostCheck.MatchString(line) || phpScInArray.MatchString(line) {
			hasHostCheck = true
		}
		if phpScFilterValidateIP.MatchString(line) {
			hasHostCheck = true
		}
		// Hardcoded base URL with user input appended as path component
		if phpScHardcodedBaseURL.MatchString(line) {
			hasHardcodedBase = true
		}
		if phpScUrlencode.MatchString(line) {
			hasURLEncode = true
		}
	}
	if hasParseURL && hasHostCheck {
		return true
	}
	if hasHardcodedBase && hasURLEncode {
		return true
	}
	return phpScanHasTypeCoercion(lines, sinkLine) || phpScanHasAllowlist(lines, sinkLine)
}

func phpScanHasDeserGuard(lines []string, sinkLine int) bool {
	// json_decode is safe (not PHP object deserialization)
	hasJsonDecode := false
	hasUnserialize := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScJsonDecode.MatchString(line) {
			hasJsonDecode = true
		}
		if phpScUnserialize.MatchString(line) {
			hasUnserialize = true
		}
		if phpScAllowedClasses.MatchString(line) {
			return true // unserialize with allowed_classes restriction
		}
	}
	if hasJsonDecode && !hasUnserialize {
		return true
	}
	// Check if the source is not user-controlled (hardcoded file path)
	if !hasUnserialize {
		return false
	}
	return phpScanHasNoUserInput(lines, sinkLine)
}

func phpScanHasRedirectGuard(lines []string, sinkLine int) bool {
	hasParseURL := false
	hasHostCheck := false
	hasSlashPrefix := false
	hasDoubleSlashReject := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScParseURL.MatchString(line) {
			hasParseURL = true
		}
		if phpScHostCheck.MatchString(line) || phpScInArray.MatchString(line) {
			hasHostCheck = true
		}
		if phpScSlashPrefix.MatchString(line) {
			hasSlashPrefix = true
		}
		if phpScRelativeCheck.MatchString(line) {
			hasDoubleSlashReject = true
		}
	}
	if hasParseURL && hasHostCheck {
		return true
	}
	if hasSlashPrefix && hasDoubleSlashReject {
		return true
	}
	// parse_url with PHP_URL_PATH extracts only the path component (no host control)
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		if phpScParseURLPath.MatchString(lines[i]) {
			return true
		}
	}
	return phpScanHasTypeCoercion(lines, sinkLine) || phpScanHasAllowlist(lines, sinkLine)
}

func phpScanHasSSTIGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		// File-based template loaders are safe
		if strings.Contains(line, "FilesystemLoader") {
			return true
		}
		// ArrayLoader with hardcoded template content is safe
		if strings.Contains(line, "ArrayLoader") && strings.Contains(line, "=>") {
			return true
		}
	}
	return phpScanHasAllowlist(lines, sinkLine)
}

// --- Shared helpers ---

func phpScanHasTypeCoercion(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScIntval.MatchString(line) || phpScIntCast.MatchString(line) {
			return true
		}
		if phpScFilterInput.MatchString(line) && (phpScFilterValidateInt.MatchString(line) || phpScFilterSanitize.MatchString(line)) {
			return true
		}
		if phpScFilterVar.MatchString(line) && phpScFilterValidateIP.MatchString(line) {
			return true
		}
		if phpScPregMatch.MatchString(line) {
			return true
		}
	}
	return false
}

func phpScanHasAllowlist(lines []string, sinkLine int) bool {
	hasAllowlist := false
	hasCheck := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if phpScAllowlist.MatchString(line) {
			hasAllowlist = true
		}
		if phpScInArrayCheck.MatchString(line) {
			hasCheck = true
		}
	}
	return hasAllowlist && hasCheck
}

func phpScanHasNoUserInput(lines []string, sinkLine int) bool {
	// Check if any line in the vicinity references user input superglobals
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.Contains(line, "$_GET") || strings.Contains(line, "$_POST") ||
			strings.Contains(line, "$_REQUEST") || strings.Contains(line, "$_COOKIE") ||
			strings.Contains(line, "$_SERVER") || strings.Contains(line, "php://input") {
			return false
		}
	}
	return true
}
