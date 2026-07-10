package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// goFilterAllFindings applies Go-specific false-positive suppression to ALL
// findings (regex + taint + AST). This runs at the scanner level after dedup,
// so it can suppress regex rule findings that the taint-level filter cannot
// reach.
func goFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
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
			suppressed = goScanHasPathGuard(lines, lineIdx)
		case "89": // SQL Injection
			suppressed = goScanHasSQLGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = goScanHasXSSGuard(lines, lineIdx)
		case "918": // SSRF
			suppressed = goScanHasSSRFGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = goScanHasRedirectGuard(lines, lineIdx)
		case "117": // Log Injection
			suppressed = goScanHasLogGuard(lines, lineIdx)
		case "1336": // SSTI
			suppressed = goScanHasSSTIGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// --- Regex patterns for scanner-level Go FP filtering ---

// Path traversal safety
var goScFilepathClean = regexp.MustCompile(`filepath\.(?:Clean|Base)\s*\(`)
var goScFilepathAbs = regexp.MustCompile(`filepath\.Abs\s*\(`)
var goScHasPrefix = regexp.MustCompile(`strings\.HasPrefix\s*\(`)

// SQL safety
var goScStrconvAtoi = regexp.MustCompile(`strconv\.(?:Atoi|ParseInt|ParseFloat)\s*\(`)
var goScFmtIntVerb = regexp.MustCompile(`%d|%v`)
var goScParamQuery = regexp.MustCompile(`\?\s*[,)]`)

// XSS safety
//
// Genuine output-escaping sanitizers only. html.EscapeString /
// template.HTMLEscapeString / template.JSEscapeString actually neutralize a
// tainted value. We deliberately do NOT treat the presence of an
// `html/template` import or a `template.HTML(...)` call as a safety signal:
// `template.HTML`/`template.JS`/`template.CSS`/`template.HTMLAttr` are the
// escaping-BYPASS conversions — they are the XSS sink, not protection — and a
// bare `html/template` import does not sanitize a raw `w.Write`/`fmt.Fprintf`
// write or an explicit-bypass conversion. The genuine auto-escaping path
// (`tmpl.Execute(w, data)` on an html/template) is already suppressed soundly
// at the astflow layer by isHTMLTemplateExecute, so this window does not need
// to (and must not) re-approve it via an import-presence heuristic.
var goScHTMLEscape = regexp.MustCompile(`(?:html\.EscapeString|template\.(?:HTMLEscapeString|JSEscapeString))\s*\(`)
var goScStrconvFormat = regexp.MustCompile(`strconv\.(?:Itoa|FormatInt|FormatFloat)\s*\(`)
var goScFmtSprintf = regexp.MustCompile(`fmt\.Sprintf\s*\(`)

// SSRF safety
var goScURLParse = regexp.MustCompile(`url\.Parse\s*\(`)
var goScHostCheck = regexp.MustCompile(`\.(?:Host|Hostname)\b`)
var goScPathEscape = regexp.MustCompile(`url\.(?:PathEscape|QueryEscape)\s*\(`)
var goScNetParseIP = regexp.MustCompile(`net\.ParseIP\s*\(`)
var goScIPCheck = regexp.MustCompile(`\.(?:IsLoopback|IsPrivate|IsGlobalUnicast)\s*\(`)

// Redirect safety
var goScParsedHost = regexp.MustCompile(`(?:parsed|u|uri|url)\w*\.(?:Host|IsAbs)`)
var goScHasPrefixSlash = regexp.MustCompile(`strings\.HasPrefix\s*\([^,]+,\s*"/"`)
var goScRejectDoubleSlash = regexp.MustCompile(`"//"|strings\.HasPrefix\s*\([^,]+,\s*"//"`)

// Log injection safety
var goScQuotedFormat = regexp.MustCompile(`%q`)
var goScStructuredLog = regexp.MustCompile(`(?:slog|zerolog|zap|logrus)\.\w+\s*\(`)

// SSTI safety
var goScConstTemplate = regexp.MustCompile(`(?:const|var)\s+\w+\s*=\s*` + "`")
var goScTemplateParse = regexp.MustCompile(`\.Parse\s*\(\s*\w+\s*\)`)

// Shared patterns
var goScAllowlistMap = regexp.MustCompile(`(?:allowed|valid|safe|whitelist)\w*\[`)
var goScMapLookup = regexp.MustCompile(`[A-Z_]{2,}\[\w+\]`)
var goScTypeCoerce = regexp.MustCompile(`strconv\.(?:Atoi|ParseInt|ParseFloat|ParseBool)\s*\(`)

// --- Per-CWE guard checks ---

func goScanHasPathGuard(lines []string, sinkLine int) bool {
	hasClean := false
	hasPrefix := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScFilepathClean.MatchString(line) {
			return true
		}
		if goScFilepathAbs.MatchString(line) {
			hasClean = true
		}
		if goScHasPrefix.MatchString(line) {
			hasPrefix = true
		}
	}
	if hasClean && hasPrefix {
		return true
	}
	return goScanHasTypeCoercion(lines, sinkLine) || goScanHasAllowlist(lines, sinkLine)
}

func goScanHasSQLGuard(lines []string, sinkLine int) bool {
	hasAtoi := false
	hasFmtInt := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScParamQuery.MatchString(line) {
			return true
		}
		if goScStrconvAtoi.MatchString(line) {
			hasAtoi = true
		}
		if goScFmtIntVerb.MatchString(line) {
			hasFmtInt = true
		}
	}
	if hasAtoi && hasFmtInt {
		return true
	}
	return goScanHasTypeCoercion(lines, sinkLine) || goScanHasAllowlist(lines, sinkLine)
}

func goScanHasXSSGuard(lines []string, sinkLine int) bool {
	hasAtoi := false
	hasFmtInt := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScHTMLEscape.MatchString(line) {
			return true
		}
		if goScStrconvAtoi.MatchString(line) || goScStrconvFormat.MatchString(line) {
			hasAtoi = true
		}
		if goScFmtSprintf.MatchString(line) && goScFmtIntVerb.MatchString(line) {
			hasFmtInt = true
		}
	}
	if hasAtoi && hasFmtInt {
		return true
	}
	return goScanHasTypeCoercion(lines, sinkLine) || goScanHasAllowlist(lines, sinkLine)
}

func goScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasURLParse := false
	hasHostCheck := false
	hasIPParse := false
	hasIPCheck := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScPathEscape.MatchString(line) {
			return true
		}
		if goScURLParse.MatchString(line) {
			hasURLParse = true
		}
		if goScHostCheck.MatchString(line) {
			hasHostCheck = true
		}
		if goScNetParseIP.MatchString(line) {
			hasIPParse = true
		}
		if goScIPCheck.MatchString(line) {
			hasIPCheck = true
		}
	}
	if hasURLParse && hasHostCheck {
		return true
	}
	if hasIPParse && hasIPCheck {
		return true
	}
	return goScanHasTypeCoercion(lines, sinkLine) || goScanHasAllowlist(lines, sinkLine)
}

func goScanHasRedirectGuard(lines []string, sinkLine int) bool {
	hasURLParse := false
	hasHostCheck := false
	hasPrefixSlash := false
	hasRejectDouble := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScURLParse.MatchString(line) {
			hasURLParse = true
		}
		if goScParsedHost.MatchString(line) {
			hasHostCheck = true
		}
		if goScHasPrefixSlash.MatchString(line) {
			hasPrefixSlash = true
		}
		if goScRejectDoubleSlash.MatchString(line) {
			hasRejectDouble = true
		}
	}
	if hasURLParse && hasHostCheck {
		return true
	}
	if hasPrefixSlash && hasRejectDouble {
		return true
	}
	return goScanHasTypeCoercion(lines, sinkLine) || goScanHasAllowlist(lines, sinkLine)
}

func goScanHasLogGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScQuotedFormat.MatchString(line) || goScStructuredLog.MatchString(line) {
			return true
		}
	}
	return false
}

func goScanHasSSTIGuard(lines []string, sinkLine int) bool {
	hasConst := false
	hasConstParse := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScConstTemplate.MatchString(line) {
			hasConst = true
		}
		if goScTemplateParse.MatchString(line) {
			hasConstParse = true
		}
	}
	if hasConst && hasConstParse {
		return true
	}
	return goScanHasAllowlist(lines, sinkLine)
}

// --- Shared helpers ---

func goScanHasTypeCoercion(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if goScTypeCoerce.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func goScanHasAllowlist(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if goScAllowlistMap.MatchString(line) || goScMapLookup.MatchString(line) {
			return true
		}
	}
	return false
}
