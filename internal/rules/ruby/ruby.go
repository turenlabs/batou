package ruby

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Ruby-specific security rules
// ---------------------------------------------------------------------------

// RB-001: ERB output without escaping
var (
	reERBRawCall     = regexp.MustCompile(`\braw\s*\(\s*(?:params|request|session|cookies|@\w+)`)
	reERBRawMethod   = regexp.MustCompile(`\braw\s+(?:params|request|session|cookies)`)
	reHTMLSafeUser   = regexp.MustCompile(`(?:params|request|session|cookies|@\w+)\s*(?:\[.*\])?\s*\.html_safe`)
	reHTMLSafeInterp = regexp.MustCompile(`"[^"]*#\{[^}]*\}[^"]*"\s*\.html_safe`)
)

// RB-002: system/exec/backtick with user input
var (
	reRubySystemUser = regexp.MustCompile(`\b(?:system|exec)\s*\(\s*["'][^"']*#\{\s*(?:params|request|session|cookies)`)
	reRubySystemVar  = regexp.MustCompile(`\b(?:system|exec)\s*\(\s*(?:params|request|ARGV)`)
	reRubyBacktickUser = regexp.MustCompile("`[^`]*#\\{\\s*(?:params|request|session|ARGV)")
	reRubySpawnUser  = regexp.MustCompile(`\b(?:spawn|IO\.popen|Open3\.capture[23]?|Open3\.popen[23]?)\s*\(\s*(?:["'][^"']*#\{|params|request)`)
)

// RB-003: YAML.load (use YAML.safe_load)
var (
	reYAMLLoad     = regexp.MustCompile(`\bYAML\.load\s*\(`)
	reYAMLSafeLoad = regexp.MustCompile(`\bYAML\.safe_load\b`)
	reYAMLLoadFile = regexp.MustCompile(`\bYAML\.load_file\s*\(`)
	// safe_load_file is fine
	reYAMLSafeLoadFile = regexp.MustCompile(`\bYAML\.safe_load_file\b`)
)

// RB-004: Sinatra params in SQL/shell
var (
	reSinatraSQL   = regexp.MustCompile(`(?:execute|query|where|find_by_sql|select|from|order|group|having)\s*\(\s*["'].*#\{\s*params\s*\[`)
	reSinatraShell = regexp.MustCompile(`\b(?:system|exec)\s*\(\s*["'].*#\{\s*params\s*\[`)
	reSinatraDB    = regexp.MustCompile(`\bDB\s*\[\s*["'][^"']*#\{\s*params`)
)

// RB-005: open() with pipe (Kernel#open)
var (
	reKernelOpen     = regexp.MustCompile(`\bopen\s*\(\s*(?:params|request|ARGV|gets|readline)`)
	reKernelOpenVar  = regexp.MustCompile(`\bopen\s*\(\s*["'][^"']*#\{`)
	reKernelOpenPipe = regexp.MustCompile(`\bopen\s*\(\s*["']\|`)
	reURIOpen        = regexp.MustCompile(`\bURI\.open\s*\(\s*(?:params|request|ARGV|gets|\$\w+)`)
)

// RB-006: send/public_send with user-controlled method name
var (
	reSendUser    = regexp.MustCompile(`\b(?:send|public_send|__send__)\s*\(\s*(?:params|request|session|cookies)\s*\[`)
	reSendDynamic = regexp.MustCompile(`\b(?:send|public_send|__send__)\s*\(\s*[a-z_]\w*\s*[,)]`)
)

// RB-007: Regex injection (Regexp.new with user input)
var (
	reRegexpNewUser = regexp.MustCompile(`\bRegexp\.new\s*\(\s*(?:params|request|session|cookies|gets|readline)`)
	reRegexpNewVar  = regexp.MustCompile(`\bRegexp\.new\s*\(\s*[a-z_]\w*\s*[,)]`)
	reRegexpCompile = regexp.MustCompile(`\bRegexp\.compile\s*\(\s*(?:params|request|gets)`)
	reUserInputSource = regexp.MustCompile(`\b(?:params|request|session|cookies)\s*\[`)
)

// RB-008: Insecure SSL (verify_mode = VERIFY_NONE)
var (
	reSSLVerifyNone  = regexp.MustCompile(`verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE`)
	reSSLVerifyNone2 = regexp.MustCompile(`ssl_verify_mode\s*=?\s*(?:OpenSSL::SSL::VERIFY_NONE|0)`)
	reSSLNoPeerVerify = regexp.MustCompile(`verify_peer\s*[:=]\s*false`)
)

// RB-009: Marshal.load from untrusted source
var (
	reMarshalLoad     = regexp.MustCompile(`\bMarshal\.(?:load|restore)\s*\(`)
	reMarshalSafe     = regexp.MustCompile(`\bMarshal\.(?:load|restore)\s*\(\s*(?:File\.read|IO\.read|File\.open)`)
)

// RB-010: Mass assignment (legacy patterns)
var (
	reAttrAccessible = regexp.MustCompile(`\battr_accessible\b`)
	reAttrProtected  = regexp.MustCompile(`\battr_protected\b`)
	reUpdateAttrs    = regexp.MustCompile(`\.update_attributes?\s*\(\s*params`)
	reNewParams      = regexp.MustCompile(`\.new\s*\(\s*params\s*(?:\[|\))`)
	reCreateParams   = regexp.MustCompile(`\.create\s*\(\s*params\s*(?:\[|\))`)
)

// RB-011: Open redirect
var (
	reRedirectParams = regexp.MustCompile(`\bredirect_to\s+(?:params|request\.referer|URI\s*\()`)
	reRedirectInterp = regexp.MustCompile(`\bredirect_to\s+["'][^"']*#\{\s*params`)
)

// RB-012: Insecure cookie settings
var (
	reCookieNoHTTPOnly = regexp.MustCompile(`cookies\s*\[.*\]\s*=\s*\{[^}]*\}`)
	reCookieDirect     = regexp.MustCompile(`cookies\s*\[\s*:[a-z_]+\s*\]\s*=\s*(?:params|request|session)`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "=begin")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func hasNearbyPattern(lines []string, idx int, pat *regexp.Regexp) bool {
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if pat.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-RB-001: ERB Output Without Escaping
// ---------------------------------------------------------------------------

type ERBUnescapedOutput struct{}

func (r *ERBUnescapedOutput) ID() string                      { return "GTSS-RB-001" }
func (r *ERBUnescapedOutput) Name() string                    { return "RubyERBUnescapedOutput" }
func (r *ERBUnescapedOutput) Description() string             { return "Detects raw() and .html_safe on user input in Ruby/Rails, bypassing XSS auto-escaping." }
func (r *ERBUnescapedOutput) DefaultSeverity() rules.Severity { return rules.High }
func (r *ERBUnescapedOutput) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *ERBUnescapedOutput) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		var title, desc string

		if reERBRawCall.MatchString(line) || reERBRawMethod.MatchString(line) {
			matched = true
			title = "raw() with user input disables XSS escaping"
			desc = "raw() marks content as safe HTML, bypassing Rails auto-escaping. When applied to user input (params, request, session), it creates an XSS vulnerability."
		} else if reHTMLSafeUser.MatchString(line) {
			matched = true
			title = ".html_safe on user-controlled input"
			desc = "Calling .html_safe on data derived from params, request, session, or instance variables bypasses Rails auto-escaping, creating an XSS vulnerability."
		} else if reHTMLSafeInterp.MatchString(line) {
			matched = true
			title = ".html_safe on interpolated string"
			desc = "Calling .html_safe on a string with interpolation bypasses Rails auto-escaping. If any interpolated value contains user input, this creates an XSS vulnerability."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove raw()/html_safe and let Rails auto-escape. If raw HTML is needed, use sanitize() helper or the sanitize gem to whitelist safe tags.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "rails", "xss", "raw", "html_safe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-002: Command Injection via system/exec/backtick
// ---------------------------------------------------------------------------

type RubyCommandInjection struct{}

func (r *RubyCommandInjection) ID() string                      { return "GTSS-RB-002" }
func (r *RubyCommandInjection) Name() string                    { return "RubyCommandInjection" }
func (r *RubyCommandInjection) Description() string             { return "Detects Ruby system/exec/backtick/spawn with user input, enabling command injection." }
func (r *RubyCommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyCommandInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyCommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
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

		if m := reRubySystemUser.FindString(line); m != "" {
			matched = m
			desc = "system/exec with user input interpolation"
		} else if m := reRubySystemVar.FindString(line); m != "" {
			matched = m
			desc = "system/exec with params/request/ARGV"
		} else if m := reRubyBacktickUser.FindString(line); m != "" {
			matched = m
			desc = "backtick with user input interpolation"
		} else if m := reRubySpawnUser.FindString(line); m != "" {
			matched = m
			desc = "spawn/IO.popen/Open3 with user input"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby command injection: " + desc,
				Description:   "Ruby shell execution (system, exec, backticks, spawn, IO.popen, Open3) with user-controlled input allows arbitrary OS command execution. An attacker can chain commands using ;, |, &&, or inject shell metacharacters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use the array form of system/exec to avoid shell interpretation: system('cmd', arg1, arg2). Use Shellwords.escape() for individual arguments if shell invocation is unavoidable.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "command-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-003: YAML.load (Unsafe Deserialization)
// ---------------------------------------------------------------------------

type YAMLUnsafeLoad struct{}

func (r *YAMLUnsafeLoad) ID() string                      { return "GTSS-RB-003" }
func (r *YAMLUnsafeLoad) Name() string                    { return "RubyYAMLUnsafeLoad" }
func (r *YAMLUnsafeLoad) Description() string             { return "Detects Ruby YAML.load which deserializes arbitrary objects, enabling RCE." }
func (r *YAMLUnsafeLoad) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *YAMLUnsafeLoad) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *YAMLUnsafeLoad) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	// Skip files that use safe_load (likely aware of the issue)
	if reYAMLSafeLoad.MatchString(ctx.Content) && !reYAMLLoad.MatchString(ctx.Content) {
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
		sev := r.DefaultSeverity()

		if m := reYAMLLoad.FindString(line); m != "" {
			// Skip if it's safe_load
			if reYAMLSafeLoad.MatchString(line) || reYAMLSafeLoadFile.MatchString(line) {
				continue
			}
			matched = m
			desc = "YAML.load() deserializes arbitrary Ruby objects. An attacker can craft YAML payloads that instantiate arbitrary classes and execute code via gadget chains (e.g., ERB, Gem::Requirement)."
		} else if m := reYAMLLoadFile.FindString(line); m != "" {
			if reYAMLSafeLoadFile.MatchString(line) {
				continue
			}
			matched = m
			desc = "YAML.load_file() deserializes arbitrary Ruby objects from a file. If the file path or content is user-controlled, this leads to RCE."
			sev = rules.High
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title:         "Ruby unsafe YAML deserialization",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use YAML.safe_load() or YAML.safe_load_file() instead of YAML.load(). If specific types are needed, use the permitted_classes option: YAML.safe_load(data, permitted_classes: [Symbol, Date]).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "yaml", "deserialization", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-004: Sinatra Params in SQL/Shell
// ---------------------------------------------------------------------------

type SinatraParamsInjection struct{}

func (r *SinatraParamsInjection) ID() string                      { return "GTSS-RB-004" }
func (r *SinatraParamsInjection) Name() string                    { return "RubySinatraParamsInjection" }
func (r *SinatraParamsInjection) Description() string             { return "Detects Sinatra params interpolated directly into SQL or shell commands." }
func (r *SinatraParamsInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SinatraParamsInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *SinatraParamsInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var title, desc string

		if m := reSinatraSQL.FindString(line); m != "" {
			matched = m
			title = "Sinatra params interpolated into SQL query"
			desc = "Sinatra params are interpolated directly into a SQL query string, allowing SQL injection. An attacker can modify query logic, extract data, or execute administrative operations."
		} else if m := reSinatraShell.FindString(line); m != "" {
			matched = m
			title = "Sinatra params interpolated into shell command"
			desc = "Sinatra params are interpolated directly into a shell command, allowing OS command injection."
		} else if m := reSinatraDB.FindString(line); m != "" {
			matched = m
			title = "Sinatra params in Sequel/DB query"
			desc = "Sinatra params are interpolated into a Sequel database query, allowing SQL injection."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use parameterized queries: DB[:users].where(name: params[:name]) for Sequel, or Model.where('name = ?', params[:name]) for ActiveRecord. For shell commands, use the array form of system().",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "sinatra", "injection", "params"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-005: Kernel#open with Pipe
// ---------------------------------------------------------------------------

type KernelOpenPipe struct{}

func (r *KernelOpenPipe) ID() string                      { return "GTSS-RB-005" }
func (r *KernelOpenPipe) Name() string                    { return "RubyKernelOpenPipe" }
func (r *KernelOpenPipe) Description() string             { return "Detects Ruby Kernel#open / URI.open with user input, which allows command injection via pipe prefix." }
func (r *KernelOpenPipe) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KernelOpenPipe) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *KernelOpenPipe) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
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
		confidence := "high"

		if m := reKernelOpenPipe.FindString(line); m != "" {
			matched = m
			desc = "Kernel#open with explicit pipe prefix executes shell commands. This is always dangerous."
		} else if m := reKernelOpen.FindString(line); m != "" {
			matched = m
			desc = "Kernel#open with user input (params, request, ARGV) allows command injection. If the input starts with |, Ruby executes it as a shell command."
		} else if m := reURIOpen.FindString(line); m != "" {
			matched = m
			desc = "URI.open with user input allows SSRF and (in older Ruby versions) command injection via pipe prefix."
		} else if m := reKernelOpenVar.FindString(line); m != "" {
			// Only flag if user input sources are nearby
			if hasNearbyPattern(lines, i, reUserInputSource) {
				matched = m
				desc = "Kernel#open with string interpolation near user input. If the string starts with |, Ruby executes it as a shell command."
				confidence = "medium"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby Kernel#open command injection via pipe",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use File.open() for file access and URI.parse(url).open for URL fetching. Never pass user input to Kernel#open. If dynamic file opening is needed, validate the path does not start with |.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "open", "command-injection", "pipe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-006: send/public_send with User-Controlled Method Name
// ---------------------------------------------------------------------------

type SendMethodInjection struct{}

func (r *SendMethodInjection) ID() string                      { return "GTSS-RB-006" }
func (r *SendMethodInjection) Name() string                    { return "RubySendMethodInjection" }
func (r *SendMethodInjection) Description() string             { return "Detects Ruby send/public_send with user-controlled method name, enabling arbitrary method invocation." }
func (r *SendMethodInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *SendMethodInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *SendMethodInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		confidence := "high"

		if m := reSendUser.FindString(line); m != "" {
			matched = m
		} else if m := reSendDynamic.FindString(line); m != "" {
			// Only flag if user input is nearby
			if hasNearbyPattern(lines, i, reUserInputSource) {
				matched = m
				confidence = "medium"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby send/public_send with user-controlled method name",
				Description:   "send()/public_send() with a user-controlled method name allows an attacker to call arbitrary methods on the object, including dangerous methods like system(), eval(), exec(), or exit. This can lead to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use an allowlist of permitted method names: ALLOWED_METHODS.include?(method_name) && obj.public_send(method_name). Never pass params directly to send/public_send.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "send", "method-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-007: Regex Injection (Regexp.new with user input)
// ---------------------------------------------------------------------------

type RegexpInjection struct{}

func (r *RegexpInjection) ID() string                      { return "GTSS-RB-007" }
func (r *RegexpInjection) Name() string                    { return "RubyRegexpInjection" }
func (r *RegexpInjection) Description() string             { return "Detects Regexp.new/compile with user input, enabling ReDoS or regex injection." }
func (r *RegexpInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RegexpInjection) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RegexpInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		confidence := "high"

		if m := reRegexpNewUser.FindString(line); m != "" {
			matched = m
		} else if m := reRegexpCompile.FindString(line); m != "" {
			matched = m
		} else if m := reRegexpNewVar.FindString(line); m != "" {
			if hasNearbyPattern(lines, i, reUserInputSource) {
				matched = m
				confidence = "medium"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby regex injection via Regexp.new with user input",
				Description:   "Regexp.new()/Regexp.compile() with user-controlled input allows an attacker to craft malicious regular expressions causing ReDoS (catastrophic backtracking) or bypass pattern-based security filters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use Regexp.escape() to sanitize user input before passing to Regexp.new(): Regexp.new(Regexp.escape(user_input)). Or use string matching (include?) instead of regex for simple searches.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "regex", "redos", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-008: Insecure SSL (VERIFY_NONE)
// ---------------------------------------------------------------------------

type InsecureSSL struct{}

func (r *InsecureSSL) ID() string                      { return "GTSS-RB-008" }
func (r *InsecureSSL) Name() string                    { return "RubyInsecureSSL" }
func (r *InsecureSSL) Description() string             { return "Detects Ruby SSL verification disabled (VERIFY_NONE), enabling MITM attacks." }
func (r *InsecureSSL) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureSSL) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *InsecureSSL) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		var desc string

		if reSSLVerifyNone.MatchString(line) {
			matched = true
			desc = "Setting verify_mode to OpenSSL::SSL::VERIFY_NONE disables SSL certificate verification, allowing man-in-the-middle attacks. Network traffic can be intercepted and modified."
		} else if reSSLVerifyNone2.MatchString(line) {
			matched = true
			desc = "SSL verification is disabled, allowing man-in-the-middle attacks. All certificate errors will be silently ignored."
		} else if reSSLNoPeerVerify.MatchString(line) {
			matched = true
			desc = "Peer SSL verification is disabled (verify_peer: false), allowing man-in-the-middle attacks."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby SSL verification disabled (MITM risk)",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use OpenSSL::SSL::VERIFY_PEER (the default) to verify server certificates. If using custom CAs, configure ca_file or ca_path instead of disabling verification.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "ssl", "tls", "mitm", "certificate"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-009: Marshal.load from Untrusted Source
// ---------------------------------------------------------------------------

type MarshalUnsafeLoad struct{}

func (r *MarshalUnsafeLoad) ID() string                      { return "GTSS-RB-009" }
func (r *MarshalUnsafeLoad) Name() string                    { return "RubyMarshalUnsafeLoad" }
func (r *MarshalUnsafeLoad) Description() string             { return "Detects Ruby Marshal.load which deserializes arbitrary objects, enabling RCE." }
func (r *MarshalUnsafeLoad) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *MarshalUnsafeLoad) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *MarshalUnsafeLoad) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if !reMarshalLoad.MatchString(line) {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Ruby Marshal.load unsafe deserialization",
			Description:   "Marshal.load()/Marshal.restore() deserializes arbitrary Ruby objects. An attacker can craft malicious payloads that execute arbitrary code via gadget chains. Marshal is fundamentally unsafe for untrusted data and cannot be made safe.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use JSON.parse() or YAML.safe_load() instead of Marshal.load(). If object serialization is needed, use a format with a strict schema like MessagePack or Protobuf. Never deserialize untrusted data with Marshal.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "marshal", "deserialization", "rce"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-010: Mass Assignment (Legacy Patterns)
// ---------------------------------------------------------------------------

type MassAssignment struct{}

func (r *MassAssignment) ID() string                      { return "GTSS-RB-010" }
func (r *MassAssignment) Name() string                    { return "RubyMassAssignment" }
func (r *MassAssignment) Description() string             { return "Detects Ruby/Rails mass assignment vulnerabilities via update_attributes(params) or legacy attr_accessible/attr_protected." }
func (r *MassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r *MassAssignment) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *MassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		var title, desc string

		if reUpdateAttrs.MatchString(line) {
			matched = true
			title = "Rails update_attributes with raw params (mass assignment)"
			desc = "update_attributes/update_attribute with raw params allows an attacker to set any model attribute, including admin flags, roles, or foreign keys."
		} else if reNewParams.MatchString(line) {
			matched = true
			title = "Rails Model.new with raw params (mass assignment)"
			desc = "Creating a model with raw params allows an attacker to set any model attribute."
		} else if reCreateParams.MatchString(line) {
			matched = true
			title = "Rails Model.create with raw params (mass assignment)"
			desc = "Creating a model with raw params allows an attacker to set any model attribute."
		} else if reAttrAccessible.MatchString(line) {
			matched = true
			title = "Legacy attr_accessible (mass assignment allowlist)"
			desc = "attr_accessible is a legacy Rails 3 pattern. It was replaced by strong parameters in Rails 4. Using attr_accessible may indicate the application relies on deprecated mass assignment protection."
		} else if reAttrProtected.MatchString(line) {
			matched = true
			title = "Legacy attr_protected (mass assignment blocklist)"
			desc = "attr_protected is a legacy Rails 3 pattern that uses a blocklist approach to mass assignment protection. Blocklists are inherently weaker than allowlists as new attributes are unprotected by default."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use Rails strong parameters: params.require(:model).permit(:field1, :field2). Avoid passing raw params to model create/update methods.",
				CWEID:         "CWE-915",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "rails", "mass-assignment"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-011: Open Redirect
// ---------------------------------------------------------------------------

type OpenRedirect struct{}

func (r *OpenRedirect) ID() string                      { return "GTSS-RB-011" }
func (r *OpenRedirect) Name() string                    { return "RubyOpenRedirect" }
func (r *OpenRedirect) Description() string             { return "Detects Rails redirect_to with user-controlled URLs, enabling open redirect attacks." }
func (r *OpenRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OpenRedirect) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *OpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		var desc string

		if reRedirectParams.MatchString(line) {
			matched = true
			desc = "redirect_to with params or request.referer allows an attacker to redirect users to malicious sites for phishing or credential theft."
		} else if reRedirectInterp.MatchString(line) {
			matched = true
			desc = "redirect_to with interpolated params allows an attacker to control the redirect URL."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails open redirect via redirect_to with user input",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate redirect URLs against an allowlist of permitted paths or hosts. Use redirect_to with only relative paths or named routes (redirect_to root_path). If user URL is needed, validate it starts with / (no protocol).",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "rails", "open-redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-RB-012: Cookie Security
// ---------------------------------------------------------------------------

type CookieSecurity struct{}

func (r *CookieSecurity) ID() string                      { return "GTSS-RB-012" }
func (r *CookieSecurity) Name() string                    { return "RubyCookieSecurity" }
func (r *CookieSecurity) Description() string             { return "Detects Rails cookies set directly from user input without security flags." }
func (r *CookieSecurity) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CookieSecurity) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *CookieSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reCookieDirect.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails cookie set directly from user input",
				Description:   "Setting cookies directly from params/request data without sanitization can allow cookie injection. The value should be validated and the cookie should include httponly, secure, and samesite flags.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate cookie values before setting. Use cookies.signed or cookies.encrypted for sensitive data. Set httponly, secure, and samesite flags: cookies[:key] = { value: val, httponly: true, secure: true, same_site: :lax }.",
				CWEID:         "CWE-614",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"ruby", "rails", "cookie", "session"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&ERBUnescapedOutput{})
	rules.Register(&RubyCommandInjection{})
	rules.Register(&YAMLUnsafeLoad{})
	rules.Register(&SinatraParamsInjection{})
	rules.Register(&KernelOpenPipe{})
	rules.Register(&SendMethodInjection{})
	rules.Register(&RegexpInjection{})
	rules.Register(&InsecureSSL{})
	rules.Register(&MarshalUnsafeLoad{})
	rules.Register(&MassAssignment{})
	rules.Register(&OpenRedirect{})
	rules.Register(&CookieSecurity{})
}
