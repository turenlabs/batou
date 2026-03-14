package ruby

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for BATOU-RB-021 .. BATOU-RB-030
// ---------------------------------------------------------------------------

// RB-021: ERB template injection via render inline
var (
	reRenderInline     = regexp.MustCompile(`\brender\s+inline\s*:`)
	reRenderInlineUser = regexp.MustCompile(`\brender\s+inline\s*:.*(?:params|request|#\{)`)
)

// RB-022: constantize with user input
var (
	reConstantizeUserGen = regexp.MustCompile(`(?:params|request|session|cookies)\s*\[.*\]\s*\.\s*(?:constantize|safe_constantize)`)
	reConstantizeInterpGen = regexp.MustCompile(`(?:constantize|safe_constantize)`)
)

// RB-023: Rails where interpolation
var (
	reWhereInterpolation = regexp.MustCompile(`\.where\s*\(\s*["'][^"']*#\{`)
)

// RB-024: instance_eval/class_eval injection
var (
	reEvalInjection     = regexp.MustCompile(`\b(?:instance_eval|class_eval|module_eval)\s*\(?\s*["']`)
	reEvalInjectionUser = regexp.MustCompile(`\b(?:instance_eval|class_eval|module_eval)\s*[({]?\s*(?:params|request)`)
	reEvalInjectionInterp = regexp.MustCompile(`\b(?:instance_eval|class_eval|module_eval)\s*\(?\s*["'][^"']*#\{`)
)

// RB-025: render file traversal
var (
	reRenderFile     = regexp.MustCompile(`\brender\s+file\s*:`)
	reRenderFileUser = regexp.MustCompile(`\brender\s+file\s*:.*(?:params|request|#\{)`)
)

// RB-026: Active Storage unsafe variant
var (
	reVariantUnsafe = regexp.MustCompile(`\.variant\s*\([^)]*(?:convert|define|process)`)
)

// RB-027: Log injection
var (
	reLoggerParams = regexp.MustCompile(`Rails\.logger\.(?:info|warn|error|debug|fatal)\s*(?:\(|\s).*(?:params|request)\s*\[`)
)

// RB-028: Rack::Directory in production
var (
	reRackDirectory = regexp.MustCompile(`Rack::Directory\.new`)
)

// RB-029: Mass assignment without permit
var (
	reMassAssignNoPermit = regexp.MustCompile(`\.(?:new|create|create!|update|update!)\s*\(\s*params\s*(?:\)|$)`)
	rePermitNearby       = regexp.MustCompile(`\.permit\s*\(`)
)

// RB-030: URI credential leakage
var (
	reURICredential = regexp.MustCompile(`\bURI\s*(?:\.\s*(?:join|parse)\s*\(|\.new\s*\()`)
	reURIUserInfo   = regexp.MustCompile(`(?i)(?:password|secret|token|api_key|credential)`)
)

// ---------------------------------------------------------------------------
// BATOU-RB-021: ERB Template Injection via render inline
// ---------------------------------------------------------------------------

type ERBTemplateInjection struct{}

func (r *ERBTemplateInjection) ID() string                      { return "BATOU-RB-021" }
func (r *ERBTemplateInjection) Name() string                    { return "RubyERBTemplateInjection" }
func (r *ERBTemplateInjection) Description() string             { return "Detects render inline: with user input interpolation, enabling server-side template injection." }
func (r *ERBTemplateInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ERBTemplateInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *ERBTemplateInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		confidence := "high"

		if reRenderInlineUser.MatchString(line) {
			matched = true
		} else if reRenderInline.MatchString(line) && hasNearbyPattern(lines, i, reUserInputSource) {
			matched = true
			confidence = "medium"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ERB template injection via render inline: with user input",
				Description:   "render inline: with user-controlled content creates a server-side template injection (SSTI) vulnerability. An attacker can inject ERB tags (<%= system('id') %>) to execute arbitrary Ruby code on the server, read files, or access the database.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass user input to render inline:. Use render with a template file and pass data as local variables: render template: 'view', locals: { data: params[:data] }. The template engine will auto-escape the variables.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "rails", "ssti", "template-injection", "render"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-022: constantize With User Input
// ---------------------------------------------------------------------------

type ConstantizeInjection struct{}

func (r *ConstantizeInjection) ID() string                      { return "BATOU-RB-022" }
func (r *ConstantizeInjection) Name() string                    { return "RubyConstantizeInjection" }
func (r *ConstantizeInjection) Description() string             { return "Detects constantize/safe_constantize with user input, enabling arbitrary class instantiation." }
func (r *ConstantizeInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ConstantizeInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *ConstantizeInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		confidence := "high"

		if reConstantizeUserGen.MatchString(line) {
			matched = true
		} else if reConstantizeInterpGen.MatchString(line) && hasNearbyPattern(lines, i, reUserInputSource) {
			matched = true
			confidence = "medium"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "constantize/safe_constantize with user input enables arbitrary class access",
				Description:   "constantize converts a string to a Ruby constant/class. With user input, an attacker can reference any loaded class (e.g., 'Kernel', 'File', 'IO') and call methods on it. Even safe_constantize only prevents errors on missing constants but does not restrict which classes can be resolved.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use an allowlist of permitted class names: ALLOWED_TYPES = {'post' => Post, 'comment' => Comment}; klass = ALLOWED_TYPES[params[:type]] or return. Never pass user input directly to constantize.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "rails", "constantize", "class-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-023: Rails .where Interpolation
// ---------------------------------------------------------------------------

type WhereInterpolation struct{}

func (r *WhereInterpolation) ID() string                      { return "BATOU-RB-023" }
func (r *WhereInterpolation) Name() string                    { return "RubyWhereInterpolation" }
func (r *WhereInterpolation) Description() string             { return "Detects Rails .where() with string interpolation, enabling SQL injection." }
func (r *WhereInterpolation) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *WhereInterpolation) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *WhereInterpolation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reWhereInterpolation.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails .where() with string interpolation (SQL injection)",
			Description:   "Using string interpolation (#{}) inside .where() injects values directly into the SQL query string without escaping. An attacker can manipulate the query to bypass authentication, extract data, or modify/delete records.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use parameterized queries: .where('column = ?', value) or hash syntax: .where(column: value). For complex conditions, use .where('column = :val', val: value). Never interpolate variables into SQL strings.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "rails", "sql-injection", "where", "activerecord"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-024: instance_eval/class_eval Injection
// ---------------------------------------------------------------------------

type EvalMethodInjection struct{}

func (r *EvalMethodInjection) ID() string                      { return "BATOU-RB-024" }
func (r *EvalMethodInjection) Name() string                    { return "RubyEvalMethodInjection" }
func (r *EvalMethodInjection) Description() string             { return "Detects instance_eval/class_eval with user input or string interpolation, enabling code injection." }
func (r *EvalMethodInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *EvalMethodInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *EvalMethodInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		confidence := "high"

		if reEvalInjectionUser.MatchString(line) {
			matched = true
		} else if reEvalInjectionInterp.MatchString(line) {
			matched = true
		} else if reEvalInjection.MatchString(line) && hasNearbyPattern(lines, i, reUserInputSource) {
			matched = true
			confidence = "medium"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "instance_eval/class_eval with user input (code injection)",
				Description:   "instance_eval, class_eval, and module_eval execute a string as Ruby code in the context of the receiver object. If user input flows into the evaluated string, an attacker can execute arbitrary Ruby code including file operations, shell commands, and database access.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use block form instead of string form: obj.instance_eval { method_call } instead of obj.instance_eval('method_call'). If dynamic behavior is needed, use define_method with an allowlist of permitted method names.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "eval", "code-injection", "instance-eval"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-025: render file: Traversal
// ---------------------------------------------------------------------------

type RenderFileTraversal struct{}

func (r *RenderFileTraversal) ID() string                      { return "BATOU-RB-025" }
func (r *RenderFileTraversal) Name() string                    { return "RubyRenderFileTraversal" }
func (r *RenderFileTraversal) Description() string             { return "Detects render file: with user input, enabling path traversal to read arbitrary files." }
func (r *RenderFileTraversal) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RenderFileTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RenderFileTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		confidence := "high"

		if reRenderFileUser.MatchString(line) {
			matched = true
		} else if reRenderFile.MatchString(line) && hasNearbyPattern(lines, i, reUserInputSource) {
			matched = true
			confidence = "medium"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "render file: with user input (path traversal)",
				Description:   "render file: with user-controlled path allows an attacker to read arbitrary files from the server using path traversal (../../etc/passwd). This exposes sensitive files including configuration files, database credentials, source code, and system files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass user input to render file:. Use render template: with a predefined template directory. If dynamic file rendering is needed, validate against an allowlist of permitted file paths and use File.realpath() to resolve symlinks and prevent traversal.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "rails", "path-traversal", "render-file", "lfi"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-026: Active Storage Unsafe Variant
// ---------------------------------------------------------------------------

type ActiveStorageUnsafeVariant struct{}

func (r *ActiveStorageUnsafeVariant) ID() string                      { return "BATOU-RB-026" }
func (r *ActiveStorageUnsafeVariant) Name() string                    { return "RubyActiveStorageUnsafeVariant" }
func (r *ActiveStorageUnsafeVariant) Description() string             { return "Detects Active Storage .variant() with convert/define/process operations that may allow ImageMagick exploitation." }
func (r *ActiveStorageUnsafeVariant) DefaultSeverity() rules.Severity { return rules.High }
func (r *ActiveStorageUnsafeVariant) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *ActiveStorageUnsafeVariant) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reVariantUnsafe.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Active Storage .variant() with unsafe transformation operations",
			Description:   "Using .variant() with convert, define, or process operations passes arguments to ImageMagick/libvips command-line tools. If user input controls these parameters, attackers can exploit ImageMagick vulnerabilities (ImageTragick) to execute shell commands, read files, or perform SSRF.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use only safe transformation operations (resize_to_limit, resize_to_fit). Never pass user input to variant() parameters. Configure ImageMagick policy.xml to restrict dangerous operations (disable MVG, MSL, ephemeral, URL coders).",
			CWEID:         "CWE-94",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"ruby", "rails", "active-storage", "imagemagick", "variant"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-027: Log Injection
// ---------------------------------------------------------------------------

type LogInjection struct{}

func (r *LogInjection) ID() string                      { return "BATOU-RB-027" }
func (r *LogInjection) Name() string                    { return "RubyLogInjection" }
func (r *LogInjection) Description() string             { return "Detects Rails.logger with unsanitized params/request data, enabling log injection." }
func (r *LogInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LogInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *LogInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reLoggerParams.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails.logger with unsanitized user input (log injection)",
			Description:   "Logging unsanitized params or request data allows log injection. An attacker can inject newlines to forge log entries, inject ANSI escape codes to exploit log viewers, or fill logs with misleading entries to hide malicious activity or trigger false alerts.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Sanitize user input before logging by removing newlines and control characters: value.to_s.gsub(/[\\r\\n\\t]/, ' '). Use structured logging (lograge, semantic_logger) which properly escapes values in JSON format.",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"ruby", "rails", "logging", "log-injection"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-028: Rack::Directory in Production
// ---------------------------------------------------------------------------

type RackDirectoryExposure struct{}

func (r *RackDirectoryExposure) ID() string                      { return "BATOU-RB-028" }
func (r *RackDirectoryExposure) Name() string                    { return "RubyRackDirectoryExposure" }
func (r *RackDirectoryExposure) Description() string             { return "Detects Rack::Directory.new which serves directory listings and enables path traversal." }
func (r *RackDirectoryExposure) DefaultSeverity() rules.Severity { return rules.High }
func (r *RackDirectoryExposure) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RackDirectoryExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reRackDirectory.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rack::Directory.new exposes directory listings",
			Description:   "Rack::Directory serves directory listings and file contents for a given root directory. In production, this exposes the application's file structure and potentially source code, configuration files, and sensitive data. Historical vulnerabilities (CVE-2020-8161) allowed path traversal beyond the root.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Remove Rack::Directory from production configurations. Use Rack::Static for serving specific static files with a restricted root. If directory listing is needed, implement a custom handler with access controls and path validation.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "rack", "directory-listing", "path-traversal"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-029: Mass Assignment Without permit
// ---------------------------------------------------------------------------

type MassAssignNoPermit struct{}

func (r *MassAssignNoPermit) ID() string                      { return "BATOU-RB-029" }
func (r *MassAssignNoPermit) Name() string                    { return "RubyMassAssignNoPermit" }
func (r *MassAssignNoPermit) Description() string             { return "Detects .new(params), .create(params), or .update(params) without .permit() for strong parameters." }
func (r *MassAssignNoPermit) DefaultSeverity() rules.Severity { return rules.High }
func (r *MassAssignNoPermit) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *MassAssignNoPermit) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reMassAssignNoPermit.MatchString(line) {
			continue
		}
		// Skip if .permit( is used on the same line
		if rePermitNearby.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Mass assignment without .permit() (strong parameters bypass)",
			Description:   "Passing raw params directly to .new(), .create(), or .update() without calling .permit() bypasses Rails strong parameters protection. An attacker can set any model attribute including admin flags, roles, passwords, or foreign keys by adding extra fields to the request.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use strong parameters: Model.new(params.require(:model).permit(:field1, :field2)). Define a private method in the controller: def model_params; params.require(:model).permit(:allowed_fields); end.",
			CWEID:         "CWE-915",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "rails", "mass-assignment", "strong-parameters"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-030: URI Credential Leakage
// ---------------------------------------------------------------------------

type URICredentialLeak struct{}

func (r *URICredentialLeak) ID() string                      { return "BATOU-RB-030" }
func (r *URICredentialLeak) Name() string                    { return "RubyURICredentialLeak" }
func (r *URICredentialLeak) Description() string             { return "Detects URI.join/URI.parse with potential credential data that may leak in logs or referer headers." }
func (r *URICredentialLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *URICredentialLeak) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *URICredentialLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reURICredential.MatchString(line) {
			continue
		}
		// Only flag if credentials/secrets are nearby
		if !reURIUserInfo.MatchString(line) && !hasNearbyPattern(lines, i, reURIUserInfo) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "URI construction with credentials may leak sensitive data",
			Description:   "Building URIs with embedded credentials (passwords, tokens, API keys) risks leaking them via server logs, Referer headers, browser history, or error messages. The userinfo component of URIs (user:password@host) is particularly dangerous as it appears in the string representation of the URI.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Pass credentials via HTTP headers (Authorization, X-API-Key) instead of embedding in URIs. If URI authentication is required, use a separate connection object that handles credentials without exposing them in the URI string.",
			CWEID:         "CWE-200",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"ruby", "uri", "credentials", "information-disclosure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&ERBTemplateInjection{})
	rules.Register(&ConstantizeInjection{})
	rules.Register(&WhereInterpolation{})
	rules.Register(&EvalMethodInjection{})
	rules.Register(&RenderFileTraversal{})
	rules.Register(&ActiveStorageUnsafeVariant{})
	rules.Register(&LogInjection{})
	rules.Register(&RackDirectoryExposure{})
	rules.Register(&MassAssignNoPermit{})
	rules.Register(&URICredentialLeak{})
}
