package swift

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Vapor/Swift benchmark rules (BATOU-SWIFT-019..023)
// ---------------------------------------------------------------------------

// SWIFT-019: Vapor open redirect (CWE-601)
var (
	reVaporRedirect    = regexp.MustCompile(`\.redirect\s*\(\s*to\s*:`)
	reVaporRedirectVar = regexp.MustCompile(`\.redirect\s*\(\s*to\s*:\s*([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)`)
	reLocationHeader   = regexp.MustCompile(`\.replaceOrAdd\s*\(\s*name\s*:\s*\.location\s*,\s*value\s*:`)

	// Safe redirect targets
	reRedirectLiteral    = regexp.MustCompile(`\.redirect\s*\(\s*to\s*:\s*"`)
	reRedirectAllowCheck = regexp.MustCompile(`allowedHosts\.contains|allowlist\.contains|\.host\s*==`)
	reRedirectPathCheck  = regexp.MustCompile(`hasPrefix\s*\(\s*"/"\s*\).*!.*hasPrefix\s*\(\s*"//"|starts\s*\(\s*with\s*:\s*"/"\s*\).*!.*starts\s*\(\s*with\s*:\s*"//"`)
)

// SWIFT-020: Vapor XSS via HTML response (CWE-79)
var (
	reHTMLInterp    = regexp.MustCompile(`"<[a-zA-Z][^"]*\\?\([^)]*\)[^"]*>|"<[a-zA-Z][^"]*"\s*\+`)
	reHTMLResponse  = regexp.MustCompile(`Response\s*\(\s*status\s*:.*body\s*:|text/html`)
	reHTMLTag       = regexp.MustCompile(`<(?:html|body|div|span|p|h[1-6]|table|tr|td|a|img|script|form|input|head|title)\b`)
	reStringInterp  = regexp.MustCompile(`\\\(`)
	reLeafRenderer  = regexp.MustCompile(`req\.view\.render|LeafRenderer|\.leaf\s*\(`)
	reHTMLEscape    = regexp.MustCompile(`replacingOccurrences\s*\(\s*of\s*:\s*"<"`)
	reJSONResponse  = regexp.MustCompile(`JSONEncoder|application/json|\.encodeResponse`)
	reStringFormat  = regexp.MustCompile(`String\s*\(\s*format\s*:`)
)

// SWIFT-021: Swift Process/command injection (CWE-78)
var (
	reProcessCreate    = regexp.MustCompile(`Process\s*\(\s*\)|NSTask\s*\(\s*\)`)
	reProcessExec      = regexp.MustCompile(`\.executableURL\s*=|\.launchPath\s*=`)
	reProcessArgs      = regexp.MustCompile(`\.arguments\s*=`)
	reProcessRun       = regexp.MustCompile(`\.run\s*\(\s*\)|\.launch\s*\(\s*\)`)
	reVaporSource      = regexp.MustCompile(`req\.(?:parameters|query|content|body|headers|cookies)|request\.(?:parameters|query|content|body|headers|cookies)`)
	reAllowedCmd       = regexp.MustCompile(`allowedCommands\.contains|allowed\.contains|allowlist\.contains`)
)

// Shared FP suppression patterns
var (
	reIntGuard      = regexp.MustCompile(`guard\s+let\s+\w+\s*=\s*Int\s*\(|if\s+let\s+\w+\s*=\s*Int\s*\(`)
	reEnumDecode    = regexp.MustCompile(`enum\s+\w+\s*:\s*String\s*,\s*(?:Content|Codable|RawRepresentable)`)
	reRegexGuard    = regexp.MustCompile(`NSRegularExpression|NSPredicate\s*\(\s*format\s*:\s*"SELF MATCHES`)
	reUUIDGuard     = regexp.MustCompile(`UUID\s*\(\s*uuidString\s*:`)
	rePercentEncode = regexp.MustCompile(`addingPercentEncoding\s*\(`)
)

// SWIFT-022: Swift path traversal via FileManager/Data (CWE-22)
var (
	reFileManagerOp  = regexp.MustCompile(`FileManager\.default\.(?:contents\s*\(\s*atPath|createFile\s*\(\s*atPath|moveItem|copyItem|contentsOfDirectory|createSymbolicLink|removeItem)`)
	reDataContentsOf = regexp.MustCompile(`Data\s*\(\s*contentsOf\s*:`)
	reStringContents = regexp.MustCompile(`String\s*\(\s*contentsOfFile\s*:|String\s*\(\s*contentsOf\s*:`)
	reDataWrite      = regexp.MustCompile(`\.write\s*\(\s*to\s*:`)
	rePathSafe       = regexp.MustCompile(`standardizedFileURL|resolvingSymlinksInPath|lastPathComponent|hasPrefix\s*\(|\.contains\s*\(\s*"\.\."`)
)

// SWIFT-023: Swift insecure deserialization (CWE-502)
var (
	reNSUnarchive     = regexp.MustCompile(`NSKeyedUnarchiver\.unarchiveObject\s*\(`)
	reJSONSerDeser    = regexp.MustCompile(`JSONSerialization\.jsonObject\s*\(`)
	rePListSerDeser   = regexp.MustCompile(`PropertyListSerialization\.propertyList\s*\(`)
	rePListDecDeser   = regexp.MustCompile(`PropertyListDecoder\s*\(\s*\)\.decode\s*\(`)
	reDecodeObjForKey = regexp.MustCompile(`\.decodeObject\s*\(\s*forKey\s*:`)
	reNSClassFromStr  = regexp.MustCompile(`NSClassFromString\s*\(`)
	reSecureCoding    = regexp.MustCompile(`NSSecureCoding|requiresSecureCoding\s*=\s*true|unarchivedObject\s*\(\s*ofClass`)
	reCodableDecode   = regexp.MustCompile(`JSONDecoder\s*\(\s*\)\.decode\s*\(|\.content\.decode\s*\(|Codable|Decodable`)
)

func init() {
	rules.Register(&SwiftVaporRedirect{})
	rules.Register(&SwiftVaporXSS{})
	rules.Register(&SwiftProcessInjection{})
	rules.Register(&SwiftPathTraversal{})
	rules.Register(&SwiftInsecureDeser{})
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-019: Vapor open redirect
// ---------------------------------------------------------------------------

type SwiftVaporRedirect struct{}

func (r *SwiftVaporRedirect) ID() string                      { return "BATOU-SWIFT-019" }
func (r *SwiftVaporRedirect) Name() string                    { return "SwiftVaporRedirect" }
func (r *SwiftVaporRedirect) Description() string             { return "Detects Vapor redirect(to:) with user-controlled URL, enabling open redirect attacks." }
func (r *SwiftVaporRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftVaporRedirect) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftVaporRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reVaporRedirect.MatchString(ctx.Content) && !reLocationHeader.MatchString(ctx.Content) {
		return nil
	}

	// Skip if URL validation is present
	if reRedirectAllowCheck.MatchString(ctx.Content) || reRedirectPathCheck.MatchString(ctx.Content) {
		return nil
	}

	// Skip if input is restricted to enum values or integer-validated
	if reEnumDecode.MatchString(ctx.Content) {
		return nil
	}
	if reIntGuard.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if there are Vapor request sources in the file
	hasVaporSource := reVaporSource.MatchString(ctx.Content)
	if !hasVaporSource {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if reVaporRedirect.MatchString(line) && !reRedirectLiteral.MatchString(line) {
			m := reVaporRedirectVar.FindStringSubmatch(line)
			if len(m) > 1 {
				matched = strings.TrimSpace(line)
				desc = "Vapor redirect(to:) uses a variable that may contain user input. An attacker can craft a URL that redirects users to a phishing site."
			}
		} else if reLocationHeader.MatchString(line) {
			matched = strings.TrimSpace(line)
			desc = "HTTP Location header set with potentially user-controlled value, enabling open redirect."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Vapor open redirect with user-controlled URL",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate the redirect URL against an allowlist of trusted domains. Use relative paths only, or verify the URL host matches your domain. Reject absolute URLs to external domains.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "vapor", "redirect", "open-redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-020: Vapor XSS via HTML response
// ---------------------------------------------------------------------------

type SwiftVaporXSS struct{}

func (r *SwiftVaporXSS) ID() string                      { return "BATOU-SWIFT-020" }
func (r *SwiftVaporXSS) Name() string                    { return "SwiftVaporXSS" }
func (r *SwiftVaporXSS) Description() string             { return "Detects unescaped user input embedded in HTML responses in Vapor applications." }
func (r *SwiftVaporXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftVaporXSS) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftVaporXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Must have HTML tags in the file
	if !reHTMLTag.MatchString(ctx.Content) {
		return nil
	}

	// Skip if using Leaf template renderer (auto-escapes) or HTML escaping
	if reLeafRenderer.MatchString(ctx.Content) {
		return nil
	}
	if reHTMLEscape.MatchString(ctx.Content) {
		return nil
	}
	if rePercentEncode.MatchString(ctx.Content) {
		return nil
	}
	// Skip if all user input is integer-validated (output is numeric only)
	if reIntGuard.MatchString(ctx.Content) && !strings.Contains(ctx.Content, "req.query.get") {
		return nil
	}
	// Skip if returning JSON (not HTML)
	if reJSONResponse.MatchString(ctx.Content) && !reHTMLResponse.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		// Look for lines with HTML tags and string interpolation or concatenation
		if !reHTMLTag.MatchString(line) {
			continue
		}

		hasInterp := reStringInterp.MatchString(line)
		hasConcat := strings.Contains(line, "+") && strings.Contains(line, "\"")
		hasFormat := reStringFormat.MatchString(line)

		if hasInterp || hasConcat || hasFormat {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unescaped user input in Vapor HTML response",
				Description:   "User input is interpolated or concatenated directly into HTML markup without escaping. An attacker can inject JavaScript to steal session tokens, redirect users, or modify page content.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Leaf templates for HTML rendering (auto-escapes by default). If building HTML manually, escape user input by replacing <, >, &, \", and ' with their HTML entity equivalents.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "vapor", "xss", "html-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-021: Swift Process/command injection
// ---------------------------------------------------------------------------

type SwiftProcessInjection struct{}

func (r *SwiftProcessInjection) ID() string                      { return "BATOU-SWIFT-021" }
func (r *SwiftProcessInjection) Name() string                    { return "SwiftProcessInjection" }
func (r *SwiftProcessInjection) Description() string             { return "Detects Swift Process() execution with user-controlled arguments or launch path." }
func (r *SwiftProcessInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SwiftProcessInjection) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftProcessInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Must have Process creation and a run/launch call
	if !reProcessCreate.MatchString(ctx.Content) && !reProcessExec.MatchString(ctx.Content) {
		return nil
	}
	if !reProcessRun.MatchString(ctx.Content) {
		return nil
	}

	// Must have user input sources
	if !reVaporSource.MatchString(ctx.Content) {
		return nil
	}

	// Skip if command is validated against allowlist
	if reAllowedCmd.MatchString(ctx.Content) {
		return nil
	}

	// Skip if input is restricted via Int guard, enum decode, or regex validation
	if reIntGuard.MatchString(ctx.Content) {
		return nil
	}
	if reEnumDecode.MatchString(ctx.Content) {
		return nil
	}
	if reRegexGuard.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if reProcessArgs.MatchString(line) {
			matched = strings.TrimSpace(line)
			desc = "Process arguments are set with potentially user-controlled values. An attacker could inject additional arguments or modify command behavior."
		} else if reProcessExec.MatchString(line) && (reStringInterp.MatchString(line) || strings.Contains(line, "+")) {
			matched = strings.TrimSpace(line)
			desc = "Process executable path contains user input via interpolation or concatenation, enabling arbitrary command execution."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift Process execution with user-controlled input",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate command arguments against an allowlist. Never pass user input directly to Process arguments or launchPath. Use enum-based command selection or integer-validated parameters.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "command-injection", "process"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-022: Swift path traversal via FileManager/Data
// ---------------------------------------------------------------------------

type SwiftPathTraversal struct{}

func (r *SwiftPathTraversal) ID() string                      { return "BATOU-SWIFT-022" }
func (r *SwiftPathTraversal) Name() string                    { return "SwiftPathTraversal" }
func (r *SwiftPathTraversal) Description() string             { return "Detects file operations with user-controlled paths in Swift/Vapor applications." }
func (r *SwiftPathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftPathTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftPathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasFileOp := reFileManagerOp.MatchString(ctx.Content) ||
		reDataContentsOf.MatchString(ctx.Content) ||
		reStringContents.MatchString(ctx.Content) ||
		reDataWrite.MatchString(ctx.Content)

	if !hasFileOp {
		return nil
	}

	// Must have user input sources
	if !reVaporSource.MatchString(ctx.Content) {
		return nil
	}

	// Skip if path sanitization is present
	if rePathSafe.MatchString(ctx.Content) {
		return nil
	}

	// Skip if input is integer-validated, UUID-validated, or allowlisted
	if reIntGuard.MatchString(ctx.Content) {
		return nil
	}
	if reUUIDGuard.MatchString(ctx.Content) {
		return nil
	}
	if reAllowedCmd.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool

		if reFileManagerOp.MatchString(line) {
			matched = true
		} else if reDataContentsOf.MatchString(line) {
			matched = true
		} else if reStringContents.MatchString(line) {
			matched = true
		} else if reDataWrite.MatchString(line) {
			matched = true
		}

		if matched {
			text := strings.TrimSpace(line)
			if len(text) > 120 {
				text = text[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift file operation with user-controlled path",
				Description:   "A file system operation uses a path derived from user input without proper validation. An attacker can use directory traversal sequences (../) to access or modify files outside the intended directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   text,
				Suggestion:    "Canonicalize the path using URL.standardizedFileURL or (path as NSString).resolvingSymlinksInPath, then verify it starts with the expected base directory. Alternatively, use (filename as NSString).lastPathComponent to strip directory components.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "path-traversal", "file-access"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-023: Swift insecure deserialization
// ---------------------------------------------------------------------------

type SwiftInsecureDeser struct{}

func (r *SwiftInsecureDeser) ID() string                      { return "BATOU-SWIFT-023" }
func (r *SwiftInsecureDeser) Name() string                    { return "SwiftInsecureDeser" }
func (r *SwiftInsecureDeser) Description() string             { return "Detects insecure deserialization patterns in Swift (NSKeyedUnarchiver, JSONSerialization, PropertyListSerialization) without type-safe alternatives." }
func (r *SwiftInsecureDeser) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftInsecureDeser) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftInsecureDeser) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if using NSSecureCoding
	if reSecureCoding.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if reNSUnarchive.MatchString(line) {
			matched = reNSUnarchive.FindString(line)
			desc = "NSKeyedUnarchiver.unarchiveObject is deprecated and does not validate deserialized types. An attacker can craft archive data to instantiate arbitrary classes."
		} else if reJSONSerDeser.MatchString(line) {
			matched = reJSONSerDeser.FindString(line)
			desc = "JSONSerialization.jsonObject returns untyped Any objects. Combined with dynamic type casting, this enables type confusion and potential code execution via deserialized data."
		} else if rePListSerDeser.MatchString(line) {
			matched = rePListSerDeser.FindString(line)
			desc = "PropertyListSerialization.propertyList returns untyped Any objects from untrusted data, enabling type confusion attacks."
		} else if reNSClassFromStr.MatchString(line) {
			matched = reNSClassFromStr.FindString(line)
			desc = "NSClassFromString dynamically resolves a class name from user input, enabling arbitrary class instantiation."
		} else if reDecodeObjForKey.MatchString(line) {
			matched = reDecodeObjForKey.FindString(line)
			desc = "NSCoder.decodeObject(forKey:) without class restriction can deserialize arbitrary types from untrusted archives."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift insecure deserialization",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Codable (JSONDecoder/PropertyListDecoder) with typed structs instead of untyped serialization. For NSCoding, adopt NSSecureCoding with requiresSecureCoding = true and use unarchivedObject(ofClass:from:).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "deserialization", "insecure-deser"},
			})
		}
	}
	return findings
}
