package cors

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-CORS-001: Wildcard origin with credentials
var (
	// Generic: Access-Control-Allow-Origin: *
	headerAllowOriginStar = regexp.MustCompile(`(?i)Access-Control-Allow-Origin['":\s]+\*`)
	// Generic: Access-Control-Allow-Credentials: true
	headerAllowCreds = regexp.MustCompile(`(?i)Access-Control-Allow-Credentials['":\s]+true`)

	// Express/Node.js: cors({ origin: '*', credentials: true }) or cors({ origin: true, credentials: true })
	jsCorsOriginStar = regexp.MustCompile(`(?:origin\s*:\s*(?:['"]\*['"]|true|\[?\s*['"]\*['"]\s*\]?))`)
	jsCorsCredentials = regexp.MustCompile(`credentials\s*:\s*true`)

	// Spring: @CrossOrigin(origins = "*") or allowedOrigins("*")
	springCrossOriginStar = regexp.MustCompile(`@CrossOrigin\s*\(\s*(?:origins?\s*=\s*)?['"]\*['"]`)
	springAllowedOriginStar = regexp.MustCompile(`allowedOrigins?\s*\(\s*['"]\*['"]`)
	springAllowCredentials = regexp.MustCompile(`allowCredentials\s*(?:=\s*['"]\s*true\s*['"]|\(\s*['"]\s*true\s*['"])`)

	// Django: CORS_ALLOW_ALL_ORIGINS = True / CORS_ORIGIN_ALLOW_ALL = True
	djangoCorsAllowAll = regexp.MustCompile(`CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True`)
	djangoCorsAllowCreds = regexp.MustCompile(`CORS_ALLOW_CREDENTIALS\s*=\s*True`)

	// Flask-CORS: CORS(app, supports_credentials=True, origins="*")
	flaskCorsWildcard = regexp.MustCompile(`CORS\s*\([^)]*(?:origins?\s*=\s*['"]\*['"]|resources\s*=\s*['"]\*['"])`)
	flaskCorsCreds = regexp.MustCompile(`supports_credentials\s*=\s*True`)

	// Go: w.Header().Set("Access-Control-Allow-Origin", "*")
	goHeaderSetOriginStar = regexp.MustCompile(`\.(?:Set|Add)\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']`)
	goHeaderSetCreds      = regexp.MustCompile(`\.(?:Set|Add)\s*\(\s*["']Access-Control-Allow-Credentials["']\s*,\s*["']true["']`)
)

// GTSS-CORS-002: Reflected origin without validation
var (
	// Express: res.header("Access-Control-Allow-Origin", req.headers.origin)
	jsReflectedOrigin = regexp.MustCompile(`(?:\.header|\.set|\.setHeader)\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*(?:req\.headers\.origin|req\.header\(['"]origin['"]\)|origin|requestOrigin)`)
	// Go: w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	goReflectedOrigin = regexp.MustCompile(`\.Set\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*(?:r\.Header\.Get\s*\(\s*["']Origin["']\)|origin|reqOrigin)`)
	// Python: response["Access-Control-Allow-Origin"] = request.META.get("HTTP_ORIGIN")
	pyReflectedOrigin = regexp.MustCompile(`['"]Access-Control-Allow-Origin['"]\s*\]?\s*=\s*(?:request\.META\.get\s*\(\s*['"]HTTP_ORIGIN['"]|request\.headers\.get\s*\(\s*['"]origin['"]|origin|request_origin)`)
	// PHP: header("Access-Control-Allow-Origin: " . $_SERVER["HTTP_ORIGIN"])
	phpReflectedOrigin = regexp.MustCompile(`header\s*\(\s*['"]Access-Control-Allow-Origin:\s*['"]\s*\.\s*\$_SERVER\s*\[\s*['"]HTTP_ORIGIN['"]`)
)

func init() {
	rules.Register(&CORSWildcardCredentials{})
	rules.Register(&CORSReflectedOrigin{})
}

// --- GTSS-CORS-001: Wildcard Origin with Credentials ---

type CORSWildcardCredentials struct{}

func (r *CORSWildcardCredentials) ID() string                        { return "GTSS-CORS-001" }
func (r *CORSWildcardCredentials) Name() string                      { return "CORSWildcardCredentials" }
func (r *CORSWildcardCredentials) DefaultSeverity() rules.Severity   { return rules.Medium }
func (r *CORSWildcardCredentials) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo, rules.LangPHP, rules.LangRuby}
}

func (r *CORSWildcardCredentials) Description() string {
	return "Detects CORS configurations that use wildcard origin (*) with credentials enabled, which browsers block but indicates a misconfiguration that may lead to reflected origin patterns."
}

func (r *CORSWildcardCredentials) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Strategy: check if the file has BOTH wildcard origin AND credentials enabled.
	// Also flag specific framework patterns that combine both in one config.

	hasWildcardOrigin := false
	hasCredentials := false
	wildcardLine := 0
	wildcardMatch := ""

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		// Check per-language patterns for wildcard origin
		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if jsCorsOriginStar.MatchString(line) || headerAllowOriginStar.MatchString(line) || goHeaderSetOriginStar.MatchString(line) {
				hasWildcardOrigin = true
				if wildcardLine == 0 {
					wildcardLine = lineNum
					wildcardMatch = trimmed
				}
			}
			if jsCorsCredentials.MatchString(line) || headerAllowCreds.MatchString(line) {
				hasCredentials = true
			}
		case rules.LangJava:
			if springCrossOriginStar.MatchString(line) || springAllowedOriginStar.MatchString(line) {
				hasWildcardOrigin = true
				if wildcardLine == 0 {
					wildcardLine = lineNum
					wildcardMatch = trimmed
				}
			}
			if springAllowCredentials.MatchString(line) {
				hasCredentials = true
			}
		case rules.LangPython:
			if djangoCorsAllowAll.MatchString(line) {
				hasWildcardOrigin = true
				if wildcardLine == 0 {
					wildcardLine = lineNum
					wildcardMatch = trimmed
				}
			}
			if djangoCorsAllowCreds.MatchString(line) {
				hasCredentials = true
			}
			if flaskCorsWildcard.MatchString(line) {
				hasWildcardOrigin = true
				if wildcardLine == 0 {
					wildcardLine = lineNum
					wildcardMatch = trimmed
				}
			}
			if flaskCorsCreds.MatchString(line) {
				hasCredentials = true
			}
		case rules.LangGo:
			if goHeaderSetOriginStar.MatchString(line) || headerAllowOriginStar.MatchString(line) {
				hasWildcardOrigin = true
				if wildcardLine == 0 {
					wildcardLine = lineNum
					wildcardMatch = trimmed
				}
			}
			if goHeaderSetCreds.MatchString(line) || headerAllowCreds.MatchString(line) {
				hasCredentials = true
			}
		default:
			if headerAllowOriginStar.MatchString(line) {
				hasWildcardOrigin = true
				if wildcardLine == 0 {
					wildcardLine = lineNum
					wildcardMatch = trimmed
				}
			}
			if headerAllowCreds.MatchString(line) {
				hasCredentials = true
			}
		}
	}

	if hasWildcardOrigin && hasCredentials {
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "CORS wildcard origin (*) with credentials enabled",
			Description:   "The CORS configuration allows all origins (*) and also enables credentials. While browsers will block this combination, it indicates a misconfiguration that developers often 'fix' by reflecting the Origin header, creating a more serious vulnerability.",
			FilePath:      ctx.FilePath,
			LineNumber:    wildcardLine,
			MatchedText:   truncate(wildcardMatch, 120),
			Suggestion:    "Use an explicit allowlist of trusted origins instead of '*'. If credentials are needed, specify exact origins. Consider using a validation function that checks origins against a whitelist.",
			CWEID:         "CWE-942",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"cors", "wildcard-origin", "credentials", "misconfiguration"},
		})
	} else if hasWildcardOrigin {
		// Wildcard without credentials is lower severity but still worth noting
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      rules.Low,
			SeverityLabel: rules.Low.String(),
			Title:         "CORS wildcard origin (*) configured",
			Description:   "The CORS configuration allows all origins (*). While this is acceptable for truly public APIs, it may expose endpoints to unintended cross-origin access.",
			FilePath:      ctx.FilePath,
			LineNumber:    wildcardLine,
			MatchedText:   truncate(wildcardMatch, 120),
			Suggestion:    "If this API is not intended to be fully public, restrict origins to a specific allowlist of trusted domains.",
			CWEID:         "CWE-942",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "low",
			Tags:          []string{"cors", "wildcard-origin"},
		})
	}

	return findings
}

// --- GTSS-CORS-002: Reflected Origin ---

type CORSReflectedOrigin struct{}

func (r *CORSReflectedOrigin) ID() string                        { return "GTSS-CORS-002" }
func (r *CORSReflectedOrigin) Name() string                      { return "CORSReflectedOrigin" }
func (r *CORSReflectedOrigin) DefaultSeverity() rules.Severity   { return rules.High }
func (r *CORSReflectedOrigin) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangPHP, rules.LangJava}
}

func (r *CORSReflectedOrigin) Description() string {
	return "Detects CORS configurations that reflect the request Origin header without validation, allowing any site to make credentialed cross-origin requests."
}

func (r *CORSReflectedOrigin) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		confidence := "high"

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := jsReflectedOrigin.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangGo:
			if loc := goReflectedOrigin.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangPython:
			if loc := pyReflectedOrigin.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangPHP:
			if loc := phpReflectedOrigin.FindString(line); loc != "" {
				matched = loc
			}
		}

		if matched != "" {
			// Check if there's origin validation nearby
			if hasOriginValidation(lines, i) {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CORS origin reflected without validation",
				Description:   "The request Origin header is reflected directly in the Access-Control-Allow-Origin response header without validation. Any website can make cross-origin requests with credentials to this endpoint, enabling CSRF-like attacks and data theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate the Origin header against an allowlist of trusted domains before reflecting it. Never blindly reflect the origin. Use a framework CORS middleware with explicit origin configuration.",
				CWEID:         "CWE-942",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"cors", "reflected-origin", "credential-theft"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func hasOriginValidation(lines []string, idx int) bool {
	start := idx - 8
	if start < 0 {
		start = 0
	}
	end := idx + 3
	if end > len(lines) {
		end = len(lines)
	}

	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "allowedorigins") || strings.Contains(lower, "allowed_origins") ||
			strings.Contains(lower, "originwhitelist") || strings.Contains(lower, "origin_whitelist") ||
			strings.Contains(lower, "originallowlist") || strings.Contains(lower, "origin_allowlist") ||
			strings.Contains(lower, "isallowedorigin") || strings.Contains(lower, "is_allowed_origin") ||
			strings.Contains(lower, "validateorigin") || strings.Contains(lower, "validate_origin") ||
			strings.Contains(lower, ".includes(origin)") || strings.Contains(lower, ".has(origin)") ||
			strings.Contains(lower, "origin in ") || strings.Contains(lower, "origin ==") {
			return true
		}
	}
	return false
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
