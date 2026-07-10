package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// rubyFilterAllFindings applies Ruby-specific false-positive suppression to ALL
// findings (regex + taint + AST). This runs at the scanner level after dedup,
// so it can suppress regex rule findings that the taint-level filter cannot reach.
func rubyFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")
	kept := make([]rules.Finding, 0, len(findings))

	// Pre-compute file-level Ruby signals for rule-specific suppression.
	isRailsController := rbIsRailsController.MatchString(content)
	hasSQLFragment := rbHasSQLFragment.MatchString(content)

	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			kept = append(kept, f)
			continue
		}

		// Rule-specific suppressions for Ruby language mismatches.
		// These rules fire on patterns that are dangerous in other languages
		// but benign or standard practice in Ruby/Rails.
		switch f.RuleID {
		case "BATOU-TRV-002":
			// Ruby `require`/`load` loads from the Ruby load path ($LOAD_PATH),
			// NOT from user-controlled filesystem paths. This is fundamentally
			// different from PHP's include/require which opens files by path.
			// Suppress entirely for Ruby — file inclusion from user input would
			// be caught by BATOU-TRV-001 (path traversal) or taint analysis.
			continue

		case "BATOU-RACE-002":
			// Ruby web frameworks (Rails/Sinatra/Hanami) handle each HTTP request
			// in a single thread within a forked process (Puma/Unicorn). Check-
			// then-act patterns are safe in this model. The regex fires on any
			// if-nil-check, producing hundreds of FPs on idiomatic Ruby code.
			continue

		case "BATOU-VAL-001":
			// In Rails, `params[]` is THE standard way to read request data.
			// Every controller accesses params. The finding is "you read user
			// input" which is not a vulnerability — the vulnerability is what
			// you DO with it. Taint analysis (Layer 3) tracks the downstream
			// usage. Suppress the params-access finding in Rails controllers.
			if isRailsController {
				continue
			}

		case "BATOU-INJ-027":
			// SQL fragment injection regex fires on string interpolation near
			// SQL keywords. In Rails/Discourse, DB.sql_fragment() and
			// sanitize_sql() parameterize these safely. Suppress when the
			// file uses known parameterization helpers.
			if hasSQLFragment {
				continue
			}
		}

		cwe := strings.TrimPrefix(f.CWEID, "CWE-")

		suppressed := false
		switch cwe {
		case "22": // Path Traversal
			suppressed = rubyScanHasPathGuard(lines, lineIdx)
		case "89": // SQL Injection
			suppressed = rubyScanHasSQLGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = rubyScanHasXSSGuard(lines, lineIdx)
		case "78": // Command Injection
			// The cmdi guard is a COARSE line-proximity regex heuristic
			// (`.to_i` / array-form `system("x", …)` / Open3 / Shellwords within
			// ~15 lines). It exists to suppress regex-TIER false positives where
			// no dataflow is available. A data-flow-confirmed finding
			// (BATOU-TAINT-*) has already had precise, segment-aware sanitizer
			// analysis applied by the taint engine — a `.to_i` on a SIBLING
			// interpolation (`system("cp #{file.original_filename} #{Time.now
			// .to_i}")`) no longer suppresses the tainted segment there — so
			// re-applying this proximity guard would wrongly drop the genuine
			// flow (the railsgoat CWE-78 miss). Skip the guard for taint-tier
			// findings; keep it for regex-tier findings.
			if !strings.HasPrefix(f.RuleID, "BATOU-TAINT-") {
				suppressed = rubyScanHasCmdiGuard(lines, lineIdx)
			}
		case "918": // SSRF
			suppressed = rubyScanHasSSRFGuard(lines, lineIdx)
		case "502": // Deserialization
			suppressed = rubyScanHasDeserGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = rubyScanHasRedirectGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// --- File-level signals for rule-specific suppression ---
var rbIsRailsController = regexp.MustCompile(`(?:class\s+\w+Controller\s*<|ApplicationController|ActionController::Base|Sinatra::Base)`)
var rbHasSQLFragment = regexp.MustCompile(`DB\.sql_fragment\s*\(|sanitize_sql\s*\(|sanitize_sql_array\s*\(|connection\.quote\s*\(`)

// --- Regex patterns for scanner-level Ruby FP filtering ---

// Path traversal safety
var rbScBasename = regexp.MustCompile(`File\.basename\s*\(`)
var rbScExpandPath = regexp.MustCompile(`File\.expand_path\s*\(`)
var rbScStartWith = regexp.MustCompile(`\.start_with\?\s*\(`)
var rbScRealpath = regexp.MustCompile(`File\.realpath\s*\(`)
var rbScIncludeDotDot = regexp.MustCompile(`\.include\?\s*\(\s*["']\.\.["']`)
var rbScContainsDotDot = regexp.MustCompile(`\.contains\?\s*\(\s*["']\.\.["']`)

// SQL safety
var rbScWhereHash = regexp.MustCompile(`\.where\s*\(\s*[a-z_]+\s*:`)
var rbScWherePlaceholder = regexp.MustCompile(`\.where\s*\(\s*["'][^"']*\?[^"']*["']\s*,`)
var rbScFindBy = regexp.MustCompile(`\.find_by\s*\(\s*[a-z_]+\s*:`)
var rbScFind = regexp.MustCompile(`\.find\s*\(\s*[a-z_]\w*\s*\)`)
var rbScToI = regexp.MustCompile(`\.to_i\b`)
var rbScPermit = regexp.MustCompile(`\.permit\s*\(`)

// XSS safety
var rbScSanitize = regexp.MustCompile(`\bsanitize\s*\(`)
var rbScHtmlEscape = regexp.MustCompile(`(?:ERB::Util\.html_escape|CGI\.escapeHTML|h\s*\()`)
var rbScContentTag = regexp.MustCompile(`\bcontent_tag\s*\(`)
var rbScRenderJSON = regexp.MustCompile(`render\s+json\s*:`)
var rbScRenderPlain = regexp.MustCompile(`render\s+plain\s*:`)
var rbScEscapeUtils = regexp.MustCompile(`Rack::Utils\.escape_html`)

// Command injection safety
var rbScSystemArray = regexp.MustCompile(`\bsystem\s*\(\s*["'][^"']*["']\s*,\s*`)
var rbScShellwordsEscape = regexp.MustCompile(`Shellwords\.escape\s*\(`)
var rbScOpen3 = regexp.MustCompile(`Open3\.capture[23]?\s*\(`)
var rbScAllowedInclude = regexp.MustCompile(`(?i)(?:allowed|valid|safe|whitelist)\w*\.include\?\s*\(`)

// SSRF safety
var rbScHostCheck = regexp.MustCompile(`(?i)(?:ALLOWED_HOSTS|ALLOWED_DOMAINS|allowed_hosts|allowed_domains)\w*\.include\?`)
var rbScFixedURL = regexp.MustCompile(`URI\.parse\s*\(\s*["']https?://`)

// Deserialization safety
var rbScSafeLoad = regexp.MustCompile(`YAML\.safe_load`)
var rbScJSONParse = regexp.MustCompile(`JSON\.parse\s*\(`)
var rbScSafeLoadFile = regexp.MustCompile(`YAML\.safe_load_file`)

// Redirect safety
var rbScRelativePath = regexp.MustCompile(`\.start_with\?\s*\(\s*["']/["']\s*\)`)
var rbScNamedRoute = regexp.MustCompile(`redirect_to\s+\w+_path\b`)
var rbScRootPath = regexp.MustCompile(`redirect_to\s+root_path`)
var rbScHostValidation = regexp.MustCompile(`\.host\s*==\s*["']`)

// Shared: allowlist patterns
var rbScAllowlist = regexp.MustCompile(`(?i)(?:ALLOWED|VALID|SAFE|WHITELIST|PERMITTED)\w*\s*(?:=\s*%w|\.\s*include\?)`)
var rbScAllowlistCheck = regexp.MustCompile(`(?i)(?:allowed|valid|safe|whitelist|permitted)\w*\.include\?\s*\(`)

// --- Per-CWE guard checks ---

func rubyScanHasPathGuard(lines []string, sinkLine int) bool {
	hasBasename := false
	hasExpandPath := false
	hasStartWith := false
	hasRealpath := false
	hasContainsDotDot := false
	hasAllowlist := false

	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScBasename.MatchString(line) {
			hasBasename = true
		}
		if rbScExpandPath.MatchString(line) {
			hasExpandPath = true
		}
		if rbScStartWith.MatchString(line) {
			hasStartWith = true
		}
		if rbScRealpath.MatchString(line) {
			hasRealpath = true
		}
		if rbScIncludeDotDot.MatchString(line) || rbScContainsDotDot.MatchString(line) {
			hasContainsDotDot = true
		}
		if rbScAllowlist.MatchString(line) || rbScAllowlistCheck.MatchString(line) {
			hasAllowlist = true
		}
	}

	// File.basename strips directory components entirely
	if hasBasename {
		return true
	}
	// expand_path + start_with? = gold standard path validation
	if hasExpandPath && hasStartWith {
		return true
	}
	// realpath resolves symlinks and canonicalizes
	if hasRealpath && hasStartWith {
		return true
	}
	// Rejecting ".." in path
	if hasContainsDotDot {
		return true
	}
	// Allowlist of permitted file names
	if hasAllowlist {
		return true
	}
	return false
}

func rubyScanHasSQLGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScWhereHash.MatchString(line) || rbScWherePlaceholder.MatchString(line) {
			return true
		}
		if rbScFindBy.MatchString(line) || rbScFind.MatchString(line) {
			return true
		}
		if rbScPermit.MatchString(line) {
			return true
		}
	}
	return rubyScanHasTypeCoercion(lines, sinkLine) ||
		rubyScanHasAllowlist(lines, sinkLine)
}

func rubyScanHasXSSGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScSanitize.MatchString(line) || rbScHtmlEscape.MatchString(line) {
			return true
		}
		if rbScContentTag.MatchString(line) {
			return true
		}
		if rbScRenderJSON.MatchString(line) || rbScRenderPlain.MatchString(line) {
			return true
		}
		if rbScEscapeUtils.MatchString(line) {
			return true
		}
	}
	return rubyScanHasAllowlist(lines, sinkLine)
}

func rubyScanHasCmdiGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScSystemArray.MatchString(line) {
			return true
		}
		if rbScShellwordsEscape.MatchString(line) {
			return true
		}
		if rbScOpen3.MatchString(line) {
			return true
		}
	}
	return rubyScanHasTypeCoercion(lines, sinkLine) ||
		rubyScanHasAllowlist(lines, sinkLine)
}

func rubyScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasHostCheck := false
	hasAllowlist := false
	hasFixedURL := false

	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScHostCheck.MatchString(line) {
			hasHostCheck = true
		}
		if rbScFixedURL.MatchString(line) {
			hasFixedURL = true
		}
		if rbScAllowlist.MatchString(line) || rbScAllowlistCheck.MatchString(line) {
			hasAllowlist = true
		}
	}

	if hasHostCheck {
		return true
	}
	if hasFixedURL {
		return true
	}
	if hasAllowlist {
		return true
	}
	return false
}

func rubyScanHasDeserGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScSafeLoad.MatchString(line) || rbScSafeLoadFile.MatchString(line) {
			return true
		}
		if rbScJSONParse.MatchString(line) {
			return true
		}
	}
	return false
}

func rubyScanHasRedirectGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScRelativePath.MatchString(line) {
			return true
		}
		if rbScNamedRoute.MatchString(line) || rbScRootPath.MatchString(line) {
			return true
		}
		if rbScHostValidation.MatchString(line) {
			return true
		}
	}
	return rubyScanHasAllowlist(lines, sinkLine)
}

// --- Shared helpers ---

func rubyScanHasTypeCoercion(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if rbScToI.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func rubyScanHasAllowlist(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if rbScAllowlist.MatchString(line) || rbScAllowlistCheck.MatchString(line) {
			return true
		}
		if rbScAllowedInclude.MatchString(line) {
			return true
		}
	}
	return false
}
