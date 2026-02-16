package ruby

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Ruby extension rules (BATOU-RB-013 .. BATOU-RB-020)
// ---------------------------------------------------------------------------

// RB-013: send() with user-controlled method name (broader than RB-006)
var (
	reSendInterp      = regexp.MustCompile(`\b(?:send|public_send|__send__)\s*\(\s*["'][^"']*#\{`)
	reSendParamsIndex = regexp.MustCompile(`\b(?:send|public_send|__send__)\s*\(\s*params\s*\[`)
)

// RB-014: constantize/classify with user input
var (
	reConstantize       = regexp.MustCompile(`\b(?:constantize|safe_constantize|classify)\b`)
	reConstantizeUser   = regexp.MustCompile(`(?:params|request|session|cookies)\s*\[.*\]\s*\.\s*(?:constantize|classify)`)
	reConstantizeInterp = regexp.MustCompile(`(?:to_s|strip|downcase|upcase)\s*\.\s*(?:constantize|safe_constantize)`)
)

// RB-015: open() with user-controlled path (command injection via pipe)
var (
	reOpenUserPath = regexp.MustCompile(`\bopen\s*\(\s*(?:params|request|session|cookies)\s*\[`)
	reOpenInterp   = regexp.MustCompile(`\bopen\s*\(\s*"[^"]*#\{\s*(?:params|request|session|cookies)`)
)

// RB-016: Kernel.system with string interpolation
var (
	reKernelSystemInterp = regexp.MustCompile(`\bKernel\.system\s*\(\s*"[^"]*#\{`)
	reSystemInterpGeneric = regexp.MustCompile(`\bsystem\s*\(\s*"[^"]*#\{`)
)

// RB-017: YAML.load with untrusted input
var (
	reYAMLLoadUser   = regexp.MustCompile(`\bYAML\.load\s*\(\s*(?:params|request|body|data|input|payload)`)
	reYAMLLoadIO     = regexp.MustCompile(`\bYAML\.load\s*\(\s*(?:File\.read|IO\.read|open|Net::HTTP)`)
)

// RB-018: Regexp with user input (ReDoS)
var (
	reRegexpSlashInterp = regexp.MustCompile(`/[^/]*#\{\s*(?:params|request|session|cookies)`)
	reRegexpNewDynamic  = regexp.MustCompile(`\bRegexp\.new\s*\(\s*["'][^"']*#\{`)
)

// RB-019: ERB.new with user data
var (
	reERBNew       = regexp.MustCompile(`\bERB\.new\s*\(`)
	reERBNewUser   = regexp.MustCompile(`\bERB\.new\s*\(\s*(?:params|request|session|cookies|body|data|input)`)
	reERBNewVar    = regexp.MustCompile(`\bERB\.new\s*\(\s*[a-z_]\w*\s*[,)]`)
)

// RB-020: File.read/write with user-controlled path
var (
	reFileReadUser  = regexp.MustCompile(`\bFile\.(?:read|readlines|write|open|binread|binwrite|delete|unlink|rename)\s*\(\s*(?:params|request|session|cookies)\s*\[`)
	reFileReadInterp = regexp.MustCompile(`\bFile\.(?:read|readlines|write|open|binread|binwrite|delete|unlink|rename)\s*\(\s*"[^"]*#\{\s*(?:params|request|session|cookies)`)
	reFileReadVar   = regexp.MustCompile(`\bFile\.(?:read|readlines|write|open|binread|binwrite|delete|unlink|rename)\s*\(\s*[a-z_]\w*\s*[,)]`)
)

func init() {
	rules.Register(&RubySendUserMethod{})
	rules.Register(&RubyConstantize{})
	rules.Register(&RubyOpenCmdPipe{})
	rules.Register(&RubyKernelSystemInterp{})
	rules.Register(&RubyYAMLLoadUntrusted{})
	rules.Register(&RubyRegexpReDoS{})
	rules.Register(&RubyERBNewUser{})
	rules.Register(&RubyFilePathTraversal{})
}

// ---------------------------------------------------------------------------
// BATOU-RB-013: Ruby send() with user-controlled method name
// ---------------------------------------------------------------------------

type RubySendUserMethod struct{}

func (r *RubySendUserMethod) ID() string                      { return "BATOU-RB-013" }
func (r *RubySendUserMethod) Name() string                    { return "RubySendUserMethod" }
func (r *RubySendUserMethod) Description() string             { return "Detects Ruby send/public_send/__send__ with user-controlled method name via interpolation or params, enabling arbitrary method invocation." }
func (r *RubySendUserMethod) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubySendUserMethod) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubySendUserMethod) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if m := reSendInterp.FindString(line); m != "" {
			matched = m
		} else if m := reSendParamsIndex.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby send() with user-controlled method name",
				Description:   "send()/public_send()/__send__() with a user-controlled method name enables invocation of arbitrary methods including system(), eval(), exec(), or private methods. This can lead to remote code execution or privilege escalation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use an explicit allowlist of permitted method names: ALLOWED = %w[show index edit].freeze; obj.public_send(name) if ALLOWED.include?(name). Never pass user input directly to send.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "send", "method-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-014: Ruby constantize/classify with user input
// ---------------------------------------------------------------------------

type RubyConstantize struct{}

func (r *RubyConstantize) ID() string                      { return "BATOU-RB-014" }
func (r *RubyConstantize) Name() string                    { return "RubyConstantize" }
func (r *RubyConstantize) Description() string             { return "Detects Ruby constantize/classify with user input, enabling arbitrary class instantiation." }
func (r *RubyConstantize) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyConstantize) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyConstantize) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: no constantize/classify in the file
	if !reConstantize.MatchString(ctx.Content) {
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

		if m := reConstantizeUser.FindString(line); m != "" {
			matched = m
		} else if m := reConstantizeInterp.FindString(line); m != "" {
			// Only flag if user input source nearby
			if hasNearbyPattern(lines, i, reUserInputSource) {
				matched = m
				confidence = "medium"
			}
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby constantize/classify with user input",
				Description:   "constantize converts a string to a Ruby class constant. With user-controlled input, an attacker can instantiate arbitrary classes (e.g., Kernel, File, IO) to achieve code execution, file access, or denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use an allowlist of permitted class names: ALLOWED_TYPES = %w[Post Comment User].freeze; klass = type.constantize if ALLOWED_TYPES.include?(type). Use safe_constantize for nil return on failure.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "constantize", "class-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-015: Ruby open() with user-controlled path (command injection via pipe)
// ---------------------------------------------------------------------------

type RubyOpenCmdPipe struct{}

func (r *RubyOpenCmdPipe) ID() string                      { return "BATOU-RB-015" }
func (r *RubyOpenCmdPipe) Name() string                    { return "RubyOpenCmdPipe" }
func (r *RubyOpenCmdPipe) Description() string             { return "Detects Ruby Kernel#open with user-controlled path, which allows command injection if input starts with pipe character." }
func (r *RubyOpenCmdPipe) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyOpenCmdPipe) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyOpenCmdPipe) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if m := reOpenUserPath.FindString(line); m != "" {
			matched = m
		} else if m := reOpenInterp.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby open() with user-controlled path (command injection via pipe)",
				Description:   "Ruby's Kernel#open interprets a leading | character as a shell command. If user input is passed to open(), an attacker can inject '|command' to execute arbitrary OS commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Replace open() with File.open() for file access or URI.parse(url).open for URLs. File.open does not interpret pipe characters. If open() must be used, validate that the argument does not start with |.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "open", "command-injection", "pipe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-016: Ruby Kernel.system with string interpolation
// ---------------------------------------------------------------------------

type RubyKernelSystemInterp struct{}

func (r *RubyKernelSystemInterp) ID() string                      { return "BATOU-RB-016" }
func (r *RubyKernelSystemInterp) Name() string                    { return "RubyKernelSystemInterp" }
func (r *RubyKernelSystemInterp) Description() string             { return "Detects Ruby Kernel.system or system() with string interpolation, enabling command injection." }
func (r *RubyKernelSystemInterp) DefaultSeverity() rules.Severity { return rules.High }
func (r *RubyKernelSystemInterp) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyKernelSystemInterp) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if m := reKernelSystemInterp.FindString(line); m != "" {
			matched = m
		} else if m := reSystemInterpGeneric.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby system() with string interpolation",
				Description:   "Calling system() with a single interpolated string passes the entire string to a shell for parsing. An attacker can inject shell metacharacters (;, |, &&, $()) to execute arbitrary commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use the array form of system() to bypass shell interpretation: system('cmd', arg1, arg2). Use Shellwords.escape() if you must build a command string.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "system", "command-injection", "interpolation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-017: Ruby YAML.load with untrusted input
// ---------------------------------------------------------------------------

type RubyYAMLLoadUntrusted struct{}

func (r *RubyYAMLLoadUntrusted) ID() string                      { return "BATOU-RB-017" }
func (r *RubyYAMLLoadUntrusted) Name() string                    { return "RubyYAMLLoadUntrusted" }
func (r *RubyYAMLLoadUntrusted) Description() string             { return "Detects Ruby YAML.load with untrusted input sources (params, request body, IO, network), enabling unsafe deserialization." }
func (r *RubyYAMLLoadUntrusted) DefaultSeverity() rules.Severity { return rules.High }
func (r *RubyYAMLLoadUntrusted) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyYAMLLoadUntrusted) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if m := reYAMLLoadUser.FindString(line); m != "" {
			matched = m
			desc = "YAML.load() is called with user-controlled data (params, request body, etc.). YAML.load deserializes arbitrary Ruby objects, allowing gadget chain attacks for remote code execution."
		} else if m := reYAMLLoadIO.FindString(line); m != "" {
			matched = m
			desc = "YAML.load() is called with data from a file or network source. If the source is user-controlled or untrusted, an attacker can inject malicious YAML to achieve code execution."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby YAML.load with untrusted input",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use YAML.safe_load() instead: YAML.safe_load(data, permitted_classes: [Symbol, Date]). For file loading, use YAML.safe_load_file(). Never use YAML.load with untrusted data.",
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
// BATOU-RB-018: Ruby Regexp with user input (ReDoS)
// ---------------------------------------------------------------------------

type RubyRegexpReDoS struct{}

func (r *RubyRegexpReDoS) ID() string                      { return "BATOU-RB-018" }
func (r *RubyRegexpReDoS) Name() string                    { return "RubyRegexpReDoS" }
func (r *RubyRegexpReDoS) Description() string             { return "Detects Ruby regex construction with user input via interpolation or Regexp.new, enabling ReDoS attacks." }
func (r *RubyRegexpReDoS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RubyRegexpReDoS) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyRegexpReDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if m := reRegexpSlashInterp.FindString(line); m != "" {
			matched = m
		} else if m := reRegexpNewDynamic.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby regex with user input (ReDoS risk)",
				Description:   "User-controlled input is interpolated into a regex pattern. An attacker can craft a malicious regex with catastrophic backtracking (ReDoS) to cause denial of service, or exploit regex features to bypass security filters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Regexp.escape() to sanitize user input: Regexp.new(Regexp.escape(user_input)). For simple substring matching, prefer String#include? instead of regex. Set a timeout with Regexp.timeout= (Ruby 3.2+).",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ruby", "regex", "redos", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-019: Ruby ERB.new with user data
// ---------------------------------------------------------------------------

type RubyERBNewUser struct{}

func (r *RubyERBNewUser) ID() string                      { return "BATOU-RB-019" }
func (r *RubyERBNewUser) Name() string                    { return "RubyERBNewUser" }
func (r *RubyERBNewUser) Description() string             { return "Detects Ruby ERB.new with user-controlled template data, enabling server-side template injection (SSTI)." }
func (r *RubyERBNewUser) DefaultSeverity() rules.Severity { return rules.High }
func (r *RubyERBNewUser) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyERBNewUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail
	if !reERBNew.MatchString(ctx.Content) {
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

		if m := reERBNewUser.FindString(line); m != "" {
			matched = m
		} else if m := reERBNewVar.FindString(line); m != "" {
			if hasNearbyPattern(lines, i, reUserInputSource) {
				matched = m
				confidence = "medium"
			}
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby ERB.new with user data (SSTI)",
				Description:   "ERB.new() compiles an ERB template that can execute arbitrary Ruby code via <%= %> tags. If the template string is user-controlled, an attacker can inject code like <%= system('cmd') %> to achieve remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never pass user-controlled data as an ERB template. Use ERB templates from trusted files only, and pass user data as variables via binding. Consider using a logic-less template engine (Mustache, Liquid) for user-customizable templates.",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "erb", "ssti", "template-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-020: Ruby File.read/write with user-controlled path
// ---------------------------------------------------------------------------

type RubyFilePathTraversal struct{}

func (r *RubyFilePathTraversal) ID() string                      { return "BATOU-RB-020" }
func (r *RubyFilePathTraversal) Name() string                    { return "RubyFilePathTraversal" }
func (r *RubyFilePathTraversal) Description() string             { return "Detects Ruby File.read/write/open/delete with user-controlled path, enabling path traversal attacks." }
func (r *RubyFilePathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *RubyFilePathTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }

func (r *RubyFilePathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		confidence := "high"

		if m := reFileReadUser.FindString(line); m != "" {
			matched = m
		} else if m := reFileReadInterp.FindString(line); m != "" {
			matched = m
		} else if m := reFileReadVar.FindString(line); m != "" {
			if hasNearbyPattern(lines, i, reUserInputSource) {
				matched = m
				confidence = "medium"
			}
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby File operation with user-controlled path",
				Description:   "File.read/write/open/delete with a user-controlled path allows directory traversal via ../ sequences. An attacker can read sensitive files (/etc/passwd, config/secrets.yml) or overwrite critical files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate and sanitize file paths: use File.expand_path and verify the result starts with an allowed base directory. Use ActiveStorage or CarrierWave for file uploads. Reject paths containing '..' or absolute paths.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"ruby", "path-traversal", "file-access", "lfi"},
			})
		}
	}
	return findings
}
