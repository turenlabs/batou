package python

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Generated patterns for PY-031 through PY-040
// ---------------------------------------------------------------------------

// PY-031: Pickle/torch.load deserialization
var (
	reGenPickleLoad    = regexp.MustCompile(`\b(?:pickle|cPickle|_pickle|shelve|dill)\.(?:loads?|Unpickler)\s*\(`)
	reGenTorchLoad     = regexp.MustCompile(`\btorch\.load\s*\(`)
	reGenWeightsOnly   = regexp.MustCompile(`weights_only\s*=\s*True`)
)

// PY-032: LLM prompt injection
var (
	reGenPyLLMCall     = regexp.MustCompile(`(?i)(?:openai|anthropic|langchain|llm|ChatOpenAI|ChatAnthropic|Anthropic|OpenAI)\s*[\.(]`)
	reGenPyLLMFString  = regexp.MustCompile(`(?:f["']|\.format\s*\(|%\s*[(\w]).*(?i)(?:prompt|message|content|system|user|instruction)`)
	reGenPyUserInput   = regexp.MustCompile(`(?:request\.(?:args|form|json|data|values|GET|POST)|flask\.request|input\s*\(|sys\.stdin)`)
)

// PY-033: AI model from untrusted source
var (
	reGenFromPretrained = regexp.MustCompile(`\.from_pretrained\s*\(\s*[a-zA-Z_]\w*`)
	reGenSafeModel      = regexp.MustCompile(`\.from_pretrained\s*\(\s*["']`)
)

// PY-034: asyncio subprocess shell injection
var (
	reGenAsyncSubprocess = regexp.MustCompile(`create_subprocess_shell\s*\(\s*f["']`)
)

// PY-035: PLY pickle loading
var (
	reGenPLYPickle = regexp.MustCompile(`yacc\s*\(\s*[^)]*picklefile\s*=`)
)

// PY-036: Unsafe eval/exec of LLM output
var (
	reGenEvalExec   = regexp.MustCompile(`\b(?:eval|exec)\s*\(`)
	reGenLLMOutput  = regexp.MustCompile(`(?i)(?:response|completion|generated|output|result|answer|reply)\s*[\[.]`)
	reGenLLMVar     = regexp.MustCompile(`(?i)(?:response|completion|generated|ai_output|llm_output|model_output)`)
)

// PY-037: tarfile.extractall traversal
var (
	reGenTarExtract = regexp.MustCompile(`\.extractall\s*\(`)
	reGenTarFilter  = regexp.MustCompile(`filter\s*=`)
	reGenTarImport  = regexp.MustCompile(`\btarfile\b`)
)

// PY-038: Bare except pass in auth
var (
	reGenBareExcept = regexp.MustCompile(`except\s*(?:Exception\s*)?(?:as\s+\w+\s*)?:\s*(?:pass|\.\.\.)\s*$`)
	reGenAuthFile   = regexp.MustCompile(`(?i)(?:auth|login|password|crypto|token|session|permission|credential|security|verify|validate)`)
)

// PY-039: Dependency confusion
var (
	reGenExtraIndex = regexp.MustCompile(`--extra-index-url\s`)
)

// PY-040: Hardcoded RSA key size
var (
	reGenPyRSAKeygen = regexp.MustCompile(`(?:generate_private_key|rsa\.generate_private_key)\s*\([^)]*(?:key_size|public_exponent)[^)]*(?:1024|2048)`)
	reGenPyRSASimple = regexp.MustCompile(`(?:RSA\.generate|rsa\.generate_private_key)\s*\(\s*(?:1024|2048)`)
)

func init() {
	rules.Register(&PickleDeserialization{})
	rules.Register(&PyLLMPromptInjection{})
	rules.Register(&UntrustedModelLoad{})
	rules.Register(&AsyncSubprocessShell{})
	rules.Register(&PLYPickleLoad{})
	rules.Register(&EvalExecLLMOutput{})
	rules.Register(&TarfileExtractall{})
	rules.Register(&BareExceptAuth{})
	rules.Register(&DependencyConfusion{})
	rules.Register(&PyRSAKeySize{})
}

// --- PY-031: Pickle/torch.load deserialization ---

type PickleDeserialization struct{}

func (r *PickleDeserialization) ID() string                      { return "BATOU-PY-031" }
func (r *PickleDeserialization) Name() string                    { return "PickleDeserialization" }
func (r *PickleDeserialization) Description() string             { return "Detects pickle.load/loads and torch.load without weights_only=True, enabling arbitrary code execution." }
func (r *PickleDeserialization) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PickleDeserialization) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *PickleDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}

		var matched bool
		var desc string

		if reGenPickleLoad.MatchString(line) {
			matched = true
			desc = "pickle deserialization"
		} else if reGenTorchLoad.MatchString(line) && !reGenWeightsOnly.MatchString(line) {
			matched = true
			desc = "torch.load without weights_only=True"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe deserialization: " + desc,
				Description:   "pickle.load/loads and torch.load can execute arbitrary code during deserialization. An attacker can craft a malicious pickle file to achieve remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "For torch: use torch.load(f, weights_only=True). For data: use json, msgpack, or protobuf. If pickle is required, use fickling to audit pickle files or restrict with RestrictedUnpickler.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "pickle", "deserialization", "rce"},
			})
		}
	}
	return findings
}

// --- PY-032: LLM prompt injection ---

type PyLLMPromptInjection struct{}

func (r *PyLLMPromptInjection) ID() string                      { return "BATOU-PY-032" }
func (r *PyLLMPromptInjection) Name() string                    { return "PyLLMPromptInjection" }
func (r *PyLLMPromptInjection) Description() string             { return "Detects f-string/format with user input concatenated into OpenAI/Anthropic/LangChain API calls." }
func (r *PyLLMPromptInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *PyLLMPromptInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *PyLLMPromptInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files that reference LLM/AI APIs
	if !reGenPyLLMCall.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenPyLLMFString.MatchString(line) {
			// Check for user input sources nearby
			context := surroundingContext(lines, i, 10)
			confidence := "medium"
			if reGenPyUserInput.MatchString(context) {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LLM prompt injection via string interpolation",
				Description:   "User input interpolated into LLM prompts via f-strings or .format() enables prompt injection. Attackers can override system instructions, exfiltrate data, or manipulate AI behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use the API's structured message format with separate system/user roles. Apply input validation, length limits, and consider using prompt injection detection libraries.",
				CWEID:         "CWE-77",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"python", "llm", "prompt-injection", "ai"},
			})
		}
	}
	return findings
}

// --- PY-033: AI model from untrusted source ---

type UntrustedModelLoad struct{}

func (r *UntrustedModelLoad) ID() string                      { return "BATOU-PY-033" }
func (r *UntrustedModelLoad) Name() string                    { return "UntrustedModelLoad" }
func (r *UntrustedModelLoad) Description() string             { return "Detects from_pretrained() with variable arguments that could load models from untrusted sources." }
func (r *UntrustedModelLoad) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *UntrustedModelLoad) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *UntrustedModelLoad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenFromPretrained.MatchString(line) && !reGenSafeModel.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "AI model loaded from potentially untrusted source",
				Description:   "from_pretrained() with a variable argument can load models from arbitrary HuggingFace repos or URLs. Malicious models can contain pickled payloads that execute arbitrary code on load.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Pin model sources to trusted repos with hardcoded strings. Use trust_remote_code=False (default). Verify model hashes and use safetensors format instead of pickle-based checkpoints.",
				CWEID:         "CWE-829",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "ml", "supply-chain", "model-loading"},
			})
		}
	}
	return findings
}

// --- PY-034: asyncio subprocess shell injection ---

type AsyncSubprocessShell struct{}

func (r *AsyncSubprocessShell) ID() string                      { return "BATOU-PY-034" }
func (r *AsyncSubprocessShell) Name() string                    { return "AsyncSubprocessShell" }
func (r *AsyncSubprocessShell) Description() string             { return "Detects asyncio.create_subprocess_shell with f-string interpolation, enabling shell injection." }
func (r *AsyncSubprocessShell) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *AsyncSubprocessShell) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *AsyncSubprocessShell) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenAsyncSubprocess.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Shell injection via asyncio create_subprocess_shell with f-string",
				Description:   "create_subprocess_shell with f-string interpolation passes user-controlled data to a shell interpreter, enabling command injection. This is the async equivalent of subprocess shell=True.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use asyncio.create_subprocess_exec() with a list of arguments instead of create_subprocess_shell(). Use shlex.quote() if shell invocation is unavoidable.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "asyncio", "shell-injection", "command-injection"},
			})
		}
	}
	return findings
}

// --- PY-035: PLY pickle loading ---

type PLYPickleLoad struct{}

func (r *PLYPickleLoad) ID() string                      { return "BATOU-PY-035" }
func (r *PLYPickleLoad) Name() string                    { return "PLYPickleLoad" }
func (r *PLYPickleLoad) Description() string             { return "Detects PLY yacc() with picklefile parameter, which deserializes parser tables via pickle." }
func (r *PLYPickleLoad) DefaultSeverity() rules.Severity { return rules.High }
func (r *PLYPickleLoad) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *PLYPickleLoad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenPLYPickle.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PLY yacc pickle deserialization",
				Description:   "PLY's yacc(picklefile=...) loads parser tables via pickle, which can execute arbitrary code if the pickle file is attacker-controlled or tampered with.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Avoid picklefile parameter in yacc(). Generate parser tables at build time and include them in source. If picklefile is needed, verify file integrity with a hash check.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "ply", "pickle", "deserialization"},
			})
		}
	}
	return findings
}

// --- PY-036: Unsafe eval/exec of LLM output ---

type EvalExecLLMOutput struct{}

func (r *EvalExecLLMOutput) ID() string                      { return "BATOU-PY-036" }
func (r *EvalExecLLMOutput) Name() string                    { return "EvalExecLLMOutput" }
func (r *EvalExecLLMOutput) Description() string             { return "Detects eval/exec called on LLM/AI response variables, enabling arbitrary code execution." }
func (r *EvalExecLLMOutput) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *EvalExecLLMOutput) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *EvalExecLLMOutput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenEvalExec.MatchString(line) {
			// Check if the argument references LLM output
			if reGenLLMOutput.MatchString(line) || reGenLLMVar.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Arbitrary code execution via eval/exec of AI output",
					Description:   "Passing LLM/AI-generated text to eval() or exec() enables arbitrary code execution. LLM outputs are not trustworthy and can be manipulated via prompt injection to produce malicious code.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Never eval/exec LLM output. Use a sandboxed code executor (e.g., RestrictedPython, subprocess with seccomp). Parse structured output with json.loads() instead of eval().",
					CWEID:         "CWE-94",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"python", "eval", "exec", "llm", "ai", "rce"},
				})
			}
		}
	}
	return findings
}

// --- PY-037: tarfile.extractall traversal ---

type TarfileExtractall struct{}

func (r *TarfileExtractall) ID() string                      { return "BATOU-PY-037" }
func (r *TarfileExtractall) Name() string                    { return "TarfileExtractall" }
func (r *TarfileExtractall) Description() string             { return "Detects tarfile.extractall() without filter= parameter, enabling path traversal (CVE-2007-4559)." }
func (r *TarfileExtractall) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *TarfileExtractall) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *TarfileExtractall) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files that use tarfile
	if !reGenTarImport.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenTarExtract.MatchString(line) && !reGenTarFilter.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Path traversal via tarfile.extractall without filter",
				Description:   "tarfile.extractall() without filter= is vulnerable to CVE-2007-4559 (path traversal). A malicious tar archive can write files outside the target directory using ../../../ entries.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use extractall(filter='data') (Python 3.12+) or extractall(filter='tar') for basic filtering. For older Python, validate each member's path before extraction.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "tarfile", "path-traversal", "cve-2007-4559"},
			})
		}
	}
	return findings
}

// --- PY-038: Bare except pass in auth ---

type BareExceptAuth struct{}

func (r *BareExceptAuth) ID() string                      { return "BATOU-PY-038" }
func (r *BareExceptAuth) Name() string                    { return "BareExceptAuth" }
func (r *BareExceptAuth) Description() string             { return "Detects except: pass or except Exception: pass in auth/crypto file contexts, creating fail-open conditions." }
func (r *BareExceptAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *BareExceptAuth) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *BareExceptAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag in security-relevant files
	if !reGenAuthFile.MatchString(ctx.FilePath) && !reGenAuthFile.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenBareExcept.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Bare except with pass in security context",
				Description:   "Silently catching and ignoring all exceptions in auth/crypto code creates fail-open vulnerabilities. Authentication failures, cryptographic errors, and permission checks are silently swallowed.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Catch specific exceptions and handle them explicitly. Log security-relevant errors. Never use bare except: pass in authentication or cryptographic code.",
				CWEID:         "CWE-755",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"python", "auth", "error-handling", "bare-except"},
			})
		}
	}
	return findings
}

// --- PY-039: Dependency confusion ---

type DependencyConfusion struct{}

func (r *DependencyConfusion) ID() string                      { return "BATOU-PY-039" }
func (r *DependencyConfusion) Name() string                    { return "DependencyConfusion" }
func (r *DependencyConfusion) Description() string             { return "Detects --extra-index-url in requirements/pyproject files, which enables dependency confusion attacks." }
func (r *DependencyConfusion) DefaultSeverity() rules.Severity { return rules.High }
func (r *DependencyConfusion) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *DependencyConfusion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan requirements and pyproject files
	fp := strings.ToLower(ctx.FilePath)
	if !strings.Contains(fp, "requirements") && !strings.Contains(fp, "pyproject") && !strings.Contains(fp, "pip.conf") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenExtraIndex.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Dependency confusion via --extra-index-url",
				Description:   "--extra-index-url adds a secondary package index alongside PyPI. An attacker can register a higher-versioned package on PyPI with the same name as your private package, which pip will prefer.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use --index-url (replaces PyPI) instead of --extra-index-url. Pin exact versions with hashes. Register your private package names on PyPI as placeholders.",
				CWEID:         "CWE-829",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "supply-chain", "dependency-confusion", "pip"},
			})
		}
	}
	return findings
}

// --- PY-040: Hardcoded RSA key size ---

type PyRSAKeySize struct{}

func (r *PyRSAKeySize) ID() string                      { return "BATOU-PY-040" }
func (r *PyRSAKeySize) Name() string                    { return "PyRSAKeySize" }
func (r *PyRSAKeySize) Description() string             { return "Detects RSA key generation with 1024 or 2048 bit sizes, which are deprecated or weak." }
func (r *PyRSAKeySize) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PyRSAKeySize) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }

func (r *PyRSAKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reGenPyRSAKeygen.MatchString(line) || reGenPyRSASimple.MatchString(line) {
			severity := "weak RSA key (2048-bit)"
			if strings.Contains(line, "1024") {
				severity = "broken RSA key (1024-bit)"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Deprecated RSA key size: " + severity,
				Description:   "RSA 1024-bit keys are broken and factorable. RSA 2048-bit keys are being deprecated by NIST (target 2030). Modern applications should use at least 3072-bit RSA or switch to ECC.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use rsa.generate_private_key(public_exponent=65537, key_size=4096) or switch to ec.generate_private_key(ec.SECP256R1()) for better performance and security.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"python", "crypto", "rsa", "key-size"},
			})
		}
	}
	return findings
}
