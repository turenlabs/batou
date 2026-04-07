package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// csharpFilterAllFindings applies C#-specific false-positive suppression to ALL
// findings (regex + taint + AST). This runs at the scanner level after dedup,
// so it can suppress regex rule findings that the taint-level filter cannot reach.
func csharpFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
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
			suppressed = csScanHasSQLGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = csScanHasXSSGuard(lines, lineIdx)
		case "78": // Command Injection
			suppressed = csScanHasCmdiGuard(lines, lineIdx)
		case "22": // Path Traversal
			suppressed = csScanHasPathGuard(lines, lineIdx)
		case "918": // SSRF
			suppressed = csScanHasSSRFGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = csScanHasRedirectGuard(lines, lineIdx)
		case "502": // Insecure Deserialization
			suppressed = csScanHasDeserGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// --- Regex patterns for C# FP filtering ---

// SQL injection safety
var csScSqlParameter = regexp.MustCompile(`(?i)(?:SqlParameter|\.Parameters\.Add|\.Parameters\.AddWithValue|FromSqlInterpolated|ExecuteSqlInterpolated)`)
var csScLinqMethod = regexp.MustCompile(`(?i)\.(?:FirstOrDefault|Where|Select|Any|Count|Find|SaveChanges)\s*\(`)
var csScIntParse = regexp.MustCompile(`int\.Parse|long\.Parse|Int32\.Parse|Int64\.Parse`)
var csScAllowlist = regexp.MustCompile(`(?i)(?:Allowed|Valid|Safe|Whitelist|permitted)\w*\s*[\[.]`)
var csScContainsCheck = regexp.MustCompile(`\.Contains\s*\(`)

// XSS safety
var csScHtmlEncode = regexp.MustCompile(`(?i)(?:HttpUtility\.HtmlEncode|WebUtility\.HtmlEncode|HtmlEncoder\.Encode|_encoder\.Encode|Server\.HtmlEncode|AntiXssEncoder)`)
var csScJsonResult = regexp.MustCompile(`(?i)(?:return\s+Json\s*\(|JsonResult|return\s+Ok\s*\()`)
var csScRazorView = regexp.MustCompile(`(?i)return\s+View\s*\(`)
var csScIntParseXSS = regexp.MustCompile(`int\.Parse|long\.Parse|\.ToString\s*\(\s*\)`)

// Command injection safety
var csScRegexValidate = regexp.MustCompile(`Regex\.IsMatch\s*\(`)
var csScAllowedTools = regexp.MustCompile(`(?i)(?:AllowedTools|AllowedCommands|permitted)\w*\s*[\[.]`)
var csScIntParseCmd = regexp.MustCompile(`(?:int|long|Int32|Int64)\.Parse`)
var csScDnsReplace = regexp.MustCompile(`Dns\.GetHostAddresses`)
var csScNoUserInput = regexp.MustCompile(`Request\.(Query|Form|Body)|HttpContext\.Request|FromBody|FromQuery|FromForm`)

// Path traversal safety
var csScGetFullPath = regexp.MustCompile(`Path\.GetFullPath\s*\(`)
var csScStartsWith = regexp.MustCompile(`\.StartsWith\s*\(`)
var csScGetFileName = regexp.MustCompile(`Path\.GetFileName\s*\(`)
var csScAllowedFiles = regexp.MustCompile(`(?i)(?:AllowedFiles|AllowedPaths|permitted)\w*\s*[\[.]`)
var csScIntParsePath = regexp.MustCompile(`int\.Parse`)

// SSRF safety
var csScUriParse = regexp.MustCompile(`new\s+Uri\s*\(`)
var csScHostCheck = regexp.MustCompile(`(?i)(?:\.Host\b|\.IsLoopback|uri\.Scheme|AllowedHosts|AllowedDomains|ServiceMap)`)
var csScEscapeData = regexp.MustCompile(`Uri\.EscapeDataString`)
var csScIntParseSSRF = regexp.MustCompile(`int\.Parse`)
var csScHardcodedURL = regexp.MustCompile(`(?:GetAsync|PostAsync|GetStringAsync|GetByteArrayAsync|SendAsync)\s*\(\s*(?:\$"https?://[^{]*\{(?:userId|imageId|safeCity|id)\}|"https?://)`)
var csScTryGetValue = regexp.MustCompile(`\.TryGetValue\s*\(`)

// Redirect safety
var csScIsLocalUrl = regexp.MustCompile(`(?i)(?:Url\.IsLocalUrl|IsLocalUrl|LocalRedirect)`)
var csScRedirectToAction = regexp.MustCompile(`RedirectToAction\s*\(\s*"`)
var csScHostValidation = regexp.MustCompile(`(?i)(?:uri\.Host|\.Host\s*[!=]=|AllowedDomains|\.EndsWith)`)
var csScStartsWithSlash = regexp.MustCompile(`\.StartsWith\s*\(\s*"/"`)
var csScRejectsDouble = regexp.MustCompile(`(?:StartsWith\s*\(\s*"//"|"//"|\.\s*StartsWith\s*\(\s*"//")`)
var csScStringEquals = regexp.MustCompile(`(?:==\s*"|lang\s*==)`)

// Deserialization safety
// Typed deserialization patterns (safe when deserializing to a concrete type).
var csScTypedDeser = regexp.MustCompile(`(?:Deserialize<\w|DeserializeObject<\w|DeserializeAsync<\w)`)
// Unsafe "typed" deser with object/dynamic is not really typed.
var csScUnsafeTypedDeser = regexp.MustCompile(`(?:Deserialize<object>|DeserializeObject<object>|DeserializeAsync<object>|Deserialize<dynamic>|DeserializeObject<dynamic>)`)
var csScSerializationBinder = regexp.MustCompile(`(?i)SerializationBinder|ISerializationBinder`)
var csScSystemTextJson = regexp.MustCompile(`System\.Text\.Json`)
var csScFromBody = regexp.MustCompile(`\[FromBody\]`)
var csScTypeofFixed = regexp.MustCompile(`typeof\s*\(\s*[A-Z]\w+\s*\)`)
var csScJsonDocument = regexp.MustCompile(`JsonDocument\.Parse`)
var csScXDocument = regexp.MustCompile(`XDocument\.Load`)

// --- Per-CWE guard checks ---

func csScanHasSQLGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScSqlParameter.MatchString(line) {
			return true
		}
		if csScLinqMethod.MatchString(line) {
			return true
		}
	}
	// Check for allowlist + Contains combo
	hasAllowlist := false
	hasContains := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScAllowlist.MatchString(line) {
			hasAllowlist = true
		}
		if csScContainsCheck.MatchString(line) {
			hasContains = true
		}
		if csScIntParse.MatchString(line) {
			return true
		}
	}
	return hasAllowlist && hasContains
}

func csScanHasXSSGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScHtmlEncode.MatchString(line) {
			return true
		}
		if csScJsonResult.MatchString(line) {
			return true
		}
		if csScIntParseXSS.MatchString(line) {
			return true
		}
	}
	// Razor View return without Html.Raw is safe (auto-encodes)
	hasView := false
	hasHtmlRaw := false
	for i := max(0, sinkLine-15); i <= min(sinkLine+5, len(lines)-1); i++ {
		line := lines[i]
		if csScRazorView.MatchString(line) {
			hasView = true
		}
		if strings.Contains(line, "Html.Raw") {
			hasHtmlRaw = true
		}
	}
	if hasView && !hasHtmlRaw {
		return true
	}
	return false
}

func csScanHasCmdiGuard(lines []string, sinkLine int) bool {
	// Check if any user input source is present in the file at all
	hasUserInputNearby := false
	for i := max(0, sinkLine-20); i <= min(sinkLine+5, len(lines)-1); i++ {
		if csScNoUserInput.MatchString(lines[i]) {
			hasUserInputNearby = true
			break
		}
	}

	// If no user input near the sink, it's likely a hardcoded command
	if !hasUserInputNearby {
		return true
	}

	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScRegexValidate.MatchString(line) {
			return true
		}
		if csScAllowedTools.MatchString(line) || csScAllowlist.MatchString(line) {
			return true
		}
		if csScIntParseCmd.MatchString(line) {
			return true
		}
		if csScDnsReplace.MatchString(line) {
			return true
		}
	}

	// Check for allowlist + Contains combo (indicating allowlist validation)
	hasAllowlist := false
	hasContains := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScAllowedTools.MatchString(line) || csScAllowlist.MatchString(line) {
			hasAllowlist = true
		}
		if csScContainsCheck.MatchString(line) {
			hasContains = true
		}
	}
	if hasAllowlist && hasContains {
		return true
	}

	return false
}

func csScanHasPathGuard(lines []string, sinkLine int) bool {
	hasGetFullPath := false
	hasStartsWith := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScGetFullPath.MatchString(line) {
			hasGetFullPath = true
		}
		if csScStartsWith.MatchString(line) {
			hasStartsWith = true
		}
		if csScGetFileName.MatchString(line) {
			return true
		}
		if csScAllowedFiles.MatchString(line) || csScAllowlist.MatchString(line) {
			return true
		}
		if csScIntParsePath.MatchString(line) {
			return true
		}
		if csScRegexValidate.MatchString(line) {
			return true
		}
	}
	return hasGetFullPath && hasStartsWith
}

func csScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasUriParse := false
	hasHostCheck := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScUriParse.MatchString(line) {
			hasUriParse = true
		}
		if csScHostCheck.MatchString(line) {
			hasHostCheck = true
		}
		if csScEscapeData.MatchString(line) {
			return true
		}
		if csScIntParseSSRF.MatchString(line) {
			return true
		}
		if csScHardcodedURL.MatchString(line) {
			return true
		}
		if csScTryGetValue.MatchString(line) {
			return true
		}
	}
	return hasUriParse && hasHostCheck
}

func csScanHasRedirectGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScIsLocalUrl.MatchString(line) {
			return true
		}
		if csScRedirectToAction.MatchString(line) {
			return true
		}
	}

	// Check for URI host validation
	hasUriParse := false
	hasHostCheck := false
	hasPrefixSlash := false
	hasRejectDouble := false
	hasStringEquals := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if csScUriParse.MatchString(line) {
			hasUriParse = true
		}
		if csScHostValidation.MatchString(line) {
			hasHostCheck = true
		}
		if csScStartsWithSlash.MatchString(line) {
			hasPrefixSlash = true
		}
		if csScRejectsDouble.MatchString(line) {
			hasRejectDouble = true
		}
		if csScStringEquals.MatchString(line) {
			hasStringEquals = true
		}
		if csScTryGetValue.MatchString(line) {
			return true
		}
		if csScIntParsePath.MatchString(line) {
			return true
		}
	}
	if hasUriParse && hasHostCheck {
		return true
	}
	if hasPrefixSlash && hasRejectDouble {
		return true
	}
	if hasStringEquals {
		return true
	}
	return false
}

func csScanHasDeserGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= min(sinkLine+5, len(lines)-1); i++ {
		line := lines[i]
		if csScTypedDeser.MatchString(line) && !csScUnsafeTypedDeser.MatchString(line) {
			return true
		}
		if csScSerializationBinder.MatchString(line) {
			return true
		}
		if csScFromBody.MatchString(line) {
			return true
		}
		if csScTypeofFixed.MatchString(line) {
			return true
		}
		if csScJsonDocument.MatchString(line) {
			return true
		}
		if csScXDocument.MatchString(line) {
			return true
		}
	}
	// Check if file uses System.Text.Json (safe by default)
	for _, line := range lines {
		if csScSystemTextJson.MatchString(line) {
			return true
		}
	}
	return false
}
