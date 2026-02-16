package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled patterns ---

// BATOU-FW-TAURI-001: Dangerous shell command allowlist
var (
	// Tauri v1: "shell": { "all": true } or shell.all = true
	shellAllTrue = regexp.MustCompile(`"shell"\s*:\s*\{[^}]*"all"\s*:\s*true`)
	// shell.execute or shell.open with broad scope in allowlist JSON
	shellExecuteAll = regexp.MustCompile(`"shell"\s*:\s*\{[^}]*"execute"\s*:\s*true`)
	// shell > open with wildcard or no restriction
	shellOpenBroad = regexp.MustCompile(`"shell"\s*:\s*\{[^}]*"open"\s*:\s*(?:true|"[^"]*\.\*[^"]*")`)
	// Tauri v2 TOML/JSON: "allow-execute" permission
	shellAllowExecute = regexp.MustCompile(`"?shell:allow-execute"?`)
	// Rust: Command::new with user input
	rustCommandNew = regexp.MustCompile(`Command::new\s*\(\s*(?:&?\s*)?[a-zA-Z_]\w*\s*\)`)
	// Rust: tauri::api::shell::open with variable
	rustShellOpen = regexp.MustCompile(`(?:tauri::api::shell::open|shell::open|api::shell::open)\s*\(`)
	// JS/TS: invoke("plugin:shell|execute"...) or Command.create
	jsShellInvoke = regexp.MustCompile(`invoke\s*\(\s*['"]plugin:shell\|execute['"]`)
	jsCommandCreate = regexp.MustCompile(`Command\s*\.\s*create\s*\(`)
)

// BATOU-FW-TAURI-002: Overly permissive filesystem scope
var (
	// fs scope with $HOME/**, $APPDATA/**, or ** wildcard
	fsScopeHomeStar  = regexp.MustCompile(`"(?:fs|allow)"\s*:\s*\{[^}]*"scope"\s*:\s*\[[^\]]*"\$HOME/\*\*"`)
	fsScopeAppData   = regexp.MustCompile(`"(?:fs|allow)"\s*:\s*\{[^}]*"scope"\s*:\s*\[[^\]]*"\$APPDATA/\*\*"`)
	fsScopeWildcard  = regexp.MustCompile(`"scope"\s*:\s*\[[^\]]*"\*\*"[^\]]*\]`)
	// Broad scope patterns in flat config
	fsScopeBroadPath = regexp.MustCompile(`"scope"\s*:\s*\[\s*"\*\*"\s*\]`)
	// Tauri v2 permissions
	fsAllowAll       = regexp.MustCompile(`"?fs:allow-read"?\s*,\s*"?fs:allow-write"?`)
	fsScopeRoot      = regexp.MustCompile(`"scope"\s*:\s*\[[^\]]*"(?:/\*\*|[A-Z]:\\\\\*\*)"`)
)

// BATOU-FW-TAURI-003: IPC command injection
var (
	// Rust: #[tauri::command] fn without input validation (basic indicator)
	tauriCommandAttr       = regexp.MustCompile(`#\[tauri::command\]`)
	tauriCommandUnsafe     = regexp.MustCompile(`(?:std::process::Command|tokio::process::Command)::new\s*\(\s*(?:&?\s*)?[a-zA-Z_]\w*`)
	// JS/TS: invoke() with variable command name
	jsInvokeVariable       = regexp.MustCompile(`invoke\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
	// JS: user input flows to invoke
	jsInvokeUserInput      = regexp.MustCompile(`invoke\s*\(\s*(?:document\s*\.\s*getElementById|querySelector|event\s*\.\s*target|input\s*\.\s*value|userInput|user_input|cmdName|commandName)`)
)

// BATOU-FW-TAURI-004: Dangerous protocol handler
var (
	// Custom protocol without origin check
	customProtocolRust     = regexp.MustCompile(`register_uri_scheme_protocol\s*\(`)
	tauriLocalhost         = regexp.MustCompile(`tauri://localhost`)
	// Custom protocol without origin validation
	protocolNoOriginCheck  = regexp.MustCompile(`register_uri_scheme_protocol\s*\(\s*"[^"]+"\s*,`)
	// Dangerous scheme allowlist
	dangerousScheme        = regexp.MustCompile(`"(?:open|scheme)"\s*:\s*(?:true|"(?:file|smb|nfs)://)`)
)

// BATOU-FW-TAURI-005: CSP bypass or missing CSP
var (
	// No CSP in security section: "security": {} with no "csp" key
	securityNoCSP   = regexp.MustCompile(`"security"\s*:\s*\{[^}]*\}`)
	securityCSP     = regexp.MustCompile(`"security"\s*:\s*\{[^}]*"csp"`)
	// unsafe-inline or unsafe-eval in CSP
	cspUnsafeInline = regexp.MustCompile(`"csp"\s*:\s*"[^"]*unsafe-inline[^"]*"`)
	cspUnsafeEval   = regexp.MustCompile(`"csp"\s*:\s*"[^"]*unsafe-eval[^"]*"`)
	cspWildcard     = regexp.MustCompile(`"csp"\s*:\s*"[^"]*\*[^"]*"`)
)

// BATOU-FW-TAURI-006: window.__TAURI__ exposure
var (
	// Direct reference to window.__TAURI__
	tauriWindowExpose  = regexp.MustCompile(`window\s*\.\s*__TAURI__`)
	// withGlobalTauri: true or similar config exposing APIs
	globalTauriConfig  = regexp.MustCompile(`"?withGlobalTauri"?\s*:\s*true`)
	// Accessing __TAURI__ and passing to untrusted context
	tauriAPILeak       = regexp.MustCompile(`(?:postMessage|send|emit|broadcast)\s*\([^)]*__TAURI__`)
)

// BATOU-FW-TAURI-007: Dangerous Tauri v2 permissions
var (
	// allow-execute in capability
	permAllowExecute = regexp.MustCompile(`"shell:allow-execute"`)
	// allow-open with broad scope
	permAllowOpen    = regexp.MustCompile(`"shell:allow-open"`)
	// default permission with shell
	permShellDefault = regexp.MustCompile(`"shell:default"`)
	// fs with write access to broad scope
	permFsWriteAll   = regexp.MustCompile(`"fs:allow-write"`)
	// Broad scope with no window restriction
	permAllWindows   = regexp.MustCompile(`"windows"\s*:\s*\[\s*"\*"\s*\]`)
)

// BATOU-FW-TAURI-008: Insecure updater config
var (
	// Updater endpoint using HTTP (not HTTPS)
	updaterHTTPEndpoint = regexp.MustCompile(`"(?:updater|endpoints?)"\s*:\s*(?:\[?\s*"http://[^"]+)`)
	// Updater active but no pubkey
	updaterActive       = regexp.MustCompile(`"updater"\s*:\s*\{[^}]*"active"\s*:\s*true`)
	updaterPubkey       = regexp.MustCompile(`"updater"\s*:\s*\{[^}]*"pubkey"`)
	// Rust: tauri::updater without signature check
	rustUpdaterNoSig    = regexp.MustCompile(`(?:tauri::updater|UpdateBuilder)`)
	rustDangerousAccept = regexp.MustCompile(`dangerous_insecure_transport_protocol\s*\(\s*true\s*\)`)
)

// isRustComment checks if a line is a comment in Rust.
// Unlike isComment, this does NOT treat #[...] (Rust attributes) as comments.
func isRustComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*")
}

// isTauriConfig checks if the file is a Tauri configuration file
func isTauriConfig(filePath string) bool {
	lower := strings.ToLower(filePath)
	return strings.Contains(lower, "tauri.conf") ||
		strings.Contains(lower, "tauri.config") ||
		strings.HasSuffix(lower, "/capabilities.json") ||
		strings.Contains(lower, "/capabilities/")
}

// isTauriProject heuristically checks if content has Tauri indicators
func isTauriProject(content, filePath string) bool {
	if isTauriConfig(filePath) {
		return true
	}
	return strings.Contains(content, "tauri::") ||
		strings.Contains(content, "@tauri-apps") ||
		strings.Contains(content, "window.__TAURI__") ||
		strings.Contains(content, "__TAURI__") ||
		strings.Contains(content, "tauri::command") ||
		strings.Contains(content, "invoke(") && strings.Contains(content, "tauri")
}

// --- BATOU-FW-TAURI-001: Dangerous Shell Command Allowlist ---

type TauriShellAllowlist struct{}

func (r *TauriShellAllowlist) ID() string                      { return "BATOU-FW-TAURI-001" }
func (r *TauriShellAllowlist) Name() string                    { return "TauriShellAllowlist" }
func (r *TauriShellAllowlist) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *TauriShellAllowlist) Languages() []rules.Language {
	return []rules.Language{rules.LangJSON, rules.LangJavaScript, rules.LangTypeScript, rules.LangRust}
}
func (r *TauriShellAllowlist) Description() string {
	return "Detects dangerous Tauri shell command allowlist configurations that enable arbitrary command execution from the webview."
}

func (r *TauriShellAllowlist) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriProject(ctx.Content, ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		matched := false
		title := ""
		desc := ""
		suggestion := ""

		if shellAllTrue.MatchString(ctx.Content) && strings.Contains(line, "\"all\"") && strings.Contains(line, "true") {
			matched = true
			title = "Tauri shell.all enabled - allows arbitrary command execution"
			desc = "The Tauri shell allowlist has 'all: true', which permits the webview to execute any system command. A compromised webview or XSS vulnerability can lead to full system compromise."
			suggestion = "Remove shell.all:true. Use a scoped sidecar with explicit allowed commands instead. Define specific commands in the shell.scope configuration."
		} else if shellExecuteAll.MatchString(ctx.Content) && strings.Contains(line, "execute") && strings.Contains(line, "true") {
			matched = true
			title = "Tauri shell.execute enabled - webview can execute commands"
			desc = "Shell execute is enabled in the Tauri allowlist, permitting the webview to run system commands. This grants OS-level access to any code running in the webview."
			suggestion = "Disable shell.execute and use scoped sidecars with predefined command names. Define allowed programs in shell.scope.allowedPrograms."
		} else if shellAllowExecute.MatchString(line) {
			matched = true
			title = "Tauri v2 shell:allow-execute permission grants command execution"
			desc = "The shell:allow-execute permission allows the frontend to execute arbitrary shell commands. This is one of the most dangerous Tauri permissions."
			suggestion = "Remove shell:allow-execute. Use scoped commands with specific allowed programs instead."
		} else if rustCommandNew.MatchString(line) && isTauriProject(ctx.Content, ctx.FilePath) && ctx.Language == rules.LangRust {
			matched = true
			title = "Tauri command handler spawns process with variable input"
			desc = "A Tauri command handler uses Command::new with a variable argument, which could allow command injection if the value originates from the frontend."
			suggestion = "Validate and sanitize the command argument. Use an allowlist of permitted programs. Never pass frontend input directly to Command::new."
		} else if jsShellInvoke.MatchString(line) {
			matched = true
			title = "Frontend invokes shell execute plugin directly"
			desc = "The frontend JavaScript/TypeScript code directly invokes the shell execute plugin, which can execute system commands from the webview context."
			suggestion = "Use scoped Tauri commands instead of direct shell plugin invocation. Implement validation in a Rust backend command."
		} else if jsCommandCreate.MatchString(line) && isTauriProject(ctx.Content, ctx.FilePath) {
			matched = true
			title = "Frontend creates shell Command object"
			desc = "The frontend creates a Tauri shell Command object, enabling system command execution from the webview."
			suggestion = "Move command execution to a Rust backend handler with input validation. Use scoped sidecars with predefined command names."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         title,
				Description:   desc,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    suggestion,
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "high",
				Tags:          []string{"tauri", "shell", "command-injection", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-002: Overly Permissive Filesystem Scope ---

type TauriFilesystemScope struct{}

func (r *TauriFilesystemScope) ID() string                      { return "BATOU-FW-TAURI-002" }
func (r *TauriFilesystemScope) Name() string                    { return "TauriFilesystemScope" }
func (r *TauriFilesystemScope) DefaultSeverity() rules.Severity { return rules.High }
func (r *TauriFilesystemScope) Languages() []rules.Language {
	return []rules.Language{rules.LangJSON}
}
func (r *TauriFilesystemScope) Description() string {
	return "Detects overly permissive Tauri filesystem scope configurations that grant the webview access to sensitive directories."
}

func (r *TauriFilesystemScope) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriConfig(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		matched := false
		title := ""
		desc := ""

		if strings.Contains(line, "$HOME/**") || fsScopeHomeStar.MatchString(ctx.Content) && strings.Contains(line, "$HOME") {
			matched = true
			title = "Tauri filesystem scope includes entire home directory"
			desc = "The filesystem scope grants access to $HOME/**, allowing the webview to read/write any file in the user's home directory including SSH keys, browser data, and credentials."
		} else if strings.Contains(line, "$APPDATA/**") || fsScopeAppData.MatchString(ctx.Content) && strings.Contains(line, "$APPDATA") {
			matched = true
			title = "Tauri filesystem scope includes entire appdata directory"
			desc = "The filesystem scope grants access to $APPDATA/**, allowing the webview to access data from other applications."
		} else if fsScopeBroadPath.MatchString(line) {
			matched = true
			title = "Tauri filesystem scope uses unrestricted wildcard"
			desc = "The filesystem scope uses '**' which grants the webview access to the entire filesystem. This allows reading/writing any file the process has permissions for."
		} else if fsScopeRoot.MatchString(line) {
			matched = true
			title = "Tauri filesystem scope includes root directory"
			desc = "The filesystem scope includes the root path wildcard, granting the webview access to the entire filesystem."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         title,
				Description:   desc,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Restrict filesystem scope to only the directories your app needs. Use $APPDATA/$APP/ for app-specific data. Never use $HOME/** or ** wildcards.",
				CWEID:         "CWE-732",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"tauri", "filesystem", "scope", "access-control", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-003: IPC Command Injection ---

type TauriIPCInjection struct{}

func (r *TauriIPCInjection) ID() string                      { return "BATOU-FW-TAURI-003" }
func (r *TauriIPCInjection) Name() string                    { return "TauriIPCInjection" }
func (r *TauriIPCInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *TauriIPCInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangRust, rules.LangJavaScript, rules.LangTypeScript}
}
func (r *TauriIPCInjection) Description() string {
	return "Detects Tauri IPC command handlers that pass unvalidated frontend input to dangerous operations, and frontend code that uses dynamic command names."
}

func (r *TauriIPCInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriProject(ctx.Content, ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	if ctx.Language == rules.LangRust {
		// Check for #[tauri::command] functions that use dangerous operations
		inTauriCommand := false
		commandStartLine := 0
		braceDepth := 0

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isRustComment(trimmed) {
				continue
			}

			if tauriCommandAttr.MatchString(line) {
				inTauriCommand = true
				commandStartLine = i
				braceDepth = 0
				continue
			}

			if inTauriCommand {
				braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

				if tauriCommandUnsafe.MatchString(line) {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						Title:         "Tauri command handler executes system process with frontend input",
						Description:   "A #[tauri::command] function uses Command::new with a parameter that may originate from the frontend. This allows the webview to execute arbitrary system commands.",
						LineNumber:    i + 1,
						MatchedText:   truncate(strings.TrimSpace(line), 120),
						Suggestion:    "Validate command arguments against an allowlist. Never pass frontend input directly to Command::new. Use a match statement to map allowed command names to fixed executables.",
						CWEID:         "CWE-78",
						OWASPCategory: "A03:2021-Injection",
						Confidence:    "high",
						Tags:          []string{"tauri", "ipc", "command-injection", "framework"},
					})
				}

				if braceDepth <= 0 && i > commandStartLine {
					inTauriCommand = false
				}
			}
		}
	} else {
		// JS/TS: Check for invoke with variable/user-controlled command names
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}

			if jsInvokeVariable.MatchString(line) {
				// Exclude invoke with string literal (that's normal usage)
				if strings.Contains(line, "invoke('") || strings.Contains(line, "invoke(\"") || strings.Contains(line, "invoke(`") {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "Tauri invoke() called with variable command name",
					Description:   "The invoke() function is called with a variable command name instead of a string literal. If this variable is user-controlled, an attacker could invoke arbitrary Tauri commands.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Always use string literal command names with invoke(). Use a switch/map to select from allowed command names: invoke('known_command', { param: value }).",
					CWEID:         "CWE-20",
					OWASPCategory: "A03:2021-Injection",
					Confidence:    "medium",
					Tags:          []string{"tauri", "ipc", "invoke", "framework"},
				})
			}

			if jsInvokeUserInput.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Critical,
					Title:         "Tauri invoke() with user-controlled input as command name",
					Description:   "User input (from DOM elements or variables) is used as the command name in invoke(). This allows an attacker to call any registered Tauri command.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Never use user input as the invoke() command name. Validate against a fixed allowlist of command names.",
					CWEID:         "CWE-20",
					OWASPCategory: "A03:2021-Injection",
					Confidence:    "high",
					Tags:          []string{"tauri", "ipc", "invoke", "command-injection", "framework"},
				})
			}
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-004: Dangerous Protocol Handler ---

type TauriProtocolHandler struct{}

func (r *TauriProtocolHandler) ID() string                      { return "BATOU-FW-TAURI-004" }
func (r *TauriProtocolHandler) Name() string                    { return "TauriProtocolHandler" }
func (r *TauriProtocolHandler) DefaultSeverity() rules.Severity { return rules.High }
func (r *TauriProtocolHandler) Languages() []rules.Language {
	return []rules.Language{rules.LangRust, rules.LangJavaScript, rules.LangTypeScript, rules.LangJSON}
}
func (r *TauriProtocolHandler) Description() string {
	return "Detects dangerous Tauri custom protocol handlers that lack origin validation, and dangerous URI scheme configurations that could enable code execution."
}

func (r *TauriProtocolHandler) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriProject(ctx.Content, ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		matched := false
		title := ""
		desc := ""
		suggestion := ""
		confidence := "medium"

		if customProtocolRust.MatchString(line) {
			// Check if there's an origin validation nearby
			hasOriginCheck := false
			start := i
			end := i + 20
			if end > len(lines) {
				end = len(lines)
			}
			for _, contextLine := range lines[start:end] {
				if strings.Contains(contextLine, "origin") || strings.Contains(contextLine, "Origin") ||
					strings.Contains(contextLine, "referer") || strings.Contains(contextLine, "Referer") {
					hasOriginCheck = true
					break
				}
			}
			if !hasOriginCheck {
				matched = true
				title = "Tauri custom protocol handler without origin validation"
				desc = "A custom URI scheme protocol handler is registered without checking the request origin. External websites or applications could invoke this protocol to access local resources."
				suggestion = "Validate the request origin in custom protocol handlers. Only accept requests from your application's origin (tauri://localhost or your custom protocol)."
				confidence = "medium"
			}
		} else if dangerousScheme.MatchString(line) {
			matched = true
			title = "Dangerous URI scheme enabled in Tauri configuration"
			desc = "A potentially dangerous URI scheme (file://, smb://, or nfs://) is allowed in the shell open configuration. This can be exploited to read local files or connect to network shares (CVE-2025-31477)."
			suggestion = "Restrict allowed URI schemes to https:// and mailto:// only. Remove file://, smb://, and nfs:// from the scheme allowlist."
			confidence = "high"
		} else if tauriLocalhost.MatchString(line) && ctx.Language != rules.LangRust {
			// tauri://localhost in non-Rust code could be protocol confusion
			if strings.Contains(line, "fetch") || strings.Contains(line, "XMLHttpRequest") || strings.Contains(line, "src=") {
				matched = true
				title = "Direct access to tauri://localhost protocol"
				desc = "Code directly references tauri://localhost protocol, which could be exploited if the content is controlled by an attacker to access local Tauri resources."
				suggestion = "Use Tauri's invoke() API instead of directly accessing the tauri:// protocol. Ensure all protocol access is through the official Tauri API."
				confidence = "medium"
			}
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         title,
				Description:   desc,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    suggestion,
				CWEID:         "CWE-939",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Confidence:    confidence,
				Tags:          []string{"tauri", "protocol", "handler", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-005: CSP Bypass or Missing CSP ---

type TauriCSPMissing struct{}

func (r *TauriCSPMissing) ID() string                      { return "BATOU-FW-TAURI-005" }
func (r *TauriCSPMissing) Name() string                    { return "TauriCSPMissing" }
func (r *TauriCSPMissing) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TauriCSPMissing) Languages() []rules.Language {
	return []rules.Language{rules.LangJSON}
}
func (r *TauriCSPMissing) Description() string {
	return "Detects missing or insecure Content Security Policy in Tauri configuration, which can allow XSS and code injection in the webview."
}

func (r *TauriCSPMissing) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriConfig(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for unsafe CSP directives
	for i, line := range lines {
		if cspUnsafeInline.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Tauri CSP contains unsafe-inline directive",
				Description:   "The Content Security Policy includes 'unsafe-inline', which allows inline script execution and defeats the purpose of CSP. An XSS vulnerability in the webview can execute arbitrary code.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove 'unsafe-inline' from the CSP. Use nonces or hashes for inline scripts. Set a strict CSP: \"default-src 'self'; script-src 'self'\".",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "high",
				Tags:          []string{"tauri", "csp", "xss", "framework"},
			})
		}

		if cspUnsafeEval.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				Title:         "Tauri CSP contains unsafe-eval directive",
				Description:   "The Content Security Policy includes 'unsafe-eval', which allows eval(), new Function(), and similar dynamic code execution. In a Tauri app with IPC access, this significantly increases the attack surface.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove 'unsafe-eval' from the CSP. Refactor code to avoid eval() and new Function(). Most modern frameworks do not require unsafe-eval.",
				CWEID:         "CWE-95",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "high",
				Tags:          []string{"tauri", "csp", "eval", "framework"},
			})
		}

		if cspWildcard.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Tauri CSP uses wildcard source",
				Description:   "The Content Security Policy uses a wildcard (*) source, which allows loading resources from any origin. This negates CSP protections.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Replace wildcard (*) with specific trusted origins. Use 'self' for local resources.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "high",
				Tags:          []string{"tauri", "csp", "wildcard", "framework"},
			})
		}
	}

	// Check for missing CSP in security block
	if securityNoCSP.MatchString(ctx.Content) && !securityCSP.MatchString(ctx.Content) {
		// Find the security block line
		for i, line := range lines {
			if strings.Contains(line, "\"security\"") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "Tauri security configuration missing CSP",
					Description:   "The Tauri security configuration block does not define a Content Security Policy. Without CSP, the webview has no restrictions on script execution, style loading, or resource fetching.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Add a CSP to the security configuration: \"csp\": \"default-src 'self'; script-src 'self'\". Make it as restrictive as possible.",
					CWEID:         "CWE-693",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Confidence:    "medium",
					Tags:          []string{"tauri", "csp", "missing", "framework"},
				})
				break
			}
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-006: window.__TAURI__ Exposure ---

type TauriWindowExposure struct{}

func (r *TauriWindowExposure) ID() string                      { return "BATOU-FW-TAURI-006" }
func (r *TauriWindowExposure) Name() string                    { return "TauriWindowExposure" }
func (r *TauriWindowExposure) DefaultSeverity() rules.Severity { return rules.High }
func (r *TauriWindowExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangJSON}
}
func (r *TauriWindowExposure) Description() string {
	return "Detects exposure of the window.__TAURI__ API to potentially untrusted contexts, which can allow XSS to escalate to full system access."
}

func (r *TauriWindowExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if globalTauriConfig.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Tauri global API exposure enabled (withGlobalTauri: true)",
				Description:   "withGlobalTauri is set to true, exposing all Tauri APIs on window.__TAURI__. Any XSS vulnerability can directly access filesystem, shell, and other system APIs through the global object.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set withGlobalTauri to false and use @tauri-apps/api imports instead. This enables tree-shaking and limits API exposure to only what is imported.",
				CWEID:         "CWE-749",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "high",
				Tags:          []string{"tauri", "api-exposure", "global", "framework"},
			})
		}

		if tauriAPILeak.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				Title:         "Tauri API object leaked via messaging",
				Description:   "The __TAURI__ API object is being sent through postMessage, send, or emit, potentially exposing system-level APIs to untrusted contexts like iframes or other windows.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass the __TAURI__ API object to other contexts. Expose only specific, validated functions through a controlled interface.",
				CWEID:         "CWE-749",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"tauri", "api-exposure", "leak", "framework"},
			})
		}

		if tauriWindowExpose.MatchString(line) && !tauriAPILeak.MatchString(line) && !globalTauriConfig.MatchString(line) {
			// Direct reference to window.__TAURI__ in JS/TS code
			if strings.Contains(line, "eval") || strings.Contains(line, "innerHTML") ||
				strings.Contains(line, "document.write") || strings.Contains(line, "postMessage") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Critical,
					Title:         "window.__TAURI__ used in unsafe context",
					Description:   "window.__TAURI__ is accessed alongside dangerous operations (eval, innerHTML, document.write, postMessage). This pattern can lead to system-level code execution.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Never use window.__TAURI__ with eval, innerHTML, or similar unsafe APIs. Use @tauri-apps/api imports with proper input validation.",
					CWEID:         "CWE-749",
					OWASPCategory: "A01:2021-Broken Access Control",
					Confidence:    "high",
					Tags:          []string{"tauri", "api-exposure", "unsafe-context", "framework"},
				})
			}
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-007: Dangerous Tauri v2 Permissions ---

type TauriDangerousPerms struct{}

func (r *TauriDangerousPerms) ID() string                      { return "BATOU-FW-TAURI-007" }
func (r *TauriDangerousPerms) Name() string                    { return "TauriDangerousPerms" }
func (r *TauriDangerousPerms) DefaultSeverity() rules.Severity { return rules.High }
func (r *TauriDangerousPerms) Languages() []rules.Language {
	return []rules.Language{rules.LangJSON}
}
func (r *TauriDangerousPerms) Description() string {
	return "Detects dangerous Tauri v2 permission configurations in capability files that grant excessive access to the frontend."
}

func (r *TauriDangerousPerms) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriConfig(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		matched := false
		title := ""
		desc := ""
		severity := r.DefaultSeverity()

		if permAllowExecute.MatchString(line) {
			matched = true
			title = "Tauri v2 shell:allow-execute permission is dangerous"
			desc = "The capability grants shell:allow-execute, which allows the frontend to execute arbitrary shell commands. This is one of the most dangerous permissions in Tauri v2."
			severity = rules.Critical
		} else if permAllowOpen.MatchString(line) {
			matched = true
			title = "Tauri v2 shell:allow-open grants URI scheme access"
			desc = "The capability grants shell:allow-open, which allows the frontend to open URIs. Without scope restrictions, this can be exploited with dangerous protocols like file://, smb://, or nfs:// (CVE-2025-31477)."
		} else if permFsWriteAll.MatchString(line) {
			// Check if there's a restrictive scope nearby
			hasScope := false
			start := i - 5
			if start < 0 {
				start = 0
			}
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			for _, contextLine := range lines[start:end] {
				if strings.Contains(contextLine, "scope") {
					hasScope = true
					break
				}
			}
			if !hasScope {
				matched = true
				title = "Tauri v2 fs:allow-write without scope restriction"
				desc = "The capability grants fs:allow-write without a visible scope restriction. Without scoping, the frontend can write to any file the process has access to."
			}
		} else if permAllWindows.MatchString(line) {
			// Broad window permission - check if combined with dangerous perms
			hasDangerousPerm := strings.Contains(ctx.Content, "shell:allow-execute") ||
				strings.Contains(ctx.Content, "shell:allow-open") ||
				strings.Contains(ctx.Content, "fs:allow-write")
			if hasDangerousPerm {
				matched = true
				title = "Dangerous permissions applied to all windows"
				desc = "Dangerous permissions (shell or filesystem access) are applied to all windows ('*'). This grants every window in the app, including potential attacker-controlled iframes, access to sensitive operations."
			}
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				Title:         title,
				Description:   desc,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Follow the principle of least privilege. Only grant permissions that are strictly necessary. Use scope restrictions to limit what each permission can access. Apply permissions to specific windows, not all.",
				CWEID:         "CWE-250",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"tauri", "permissions", "capabilities", "v2", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-TAURI-008: Insecure Updater Configuration ---

type TauriInsecureUpdater struct{}

func (r *TauriInsecureUpdater) ID() string                      { return "BATOU-FW-TAURI-008" }
func (r *TauriInsecureUpdater) Name() string                    { return "TauriInsecureUpdater" }
func (r *TauriInsecureUpdater) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *TauriInsecureUpdater) Languages() []rules.Language {
	return []rules.Language{rules.LangJSON, rules.LangRust}
}
func (r *TauriInsecureUpdater) Description() string {
	return "Detects insecure Tauri updater configurations including HTTP endpoints, missing signature verification, and dangerous transport settings."
}

func (r *TauriInsecureUpdater) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isTauriProject(ctx.Content, ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if updaterHTTPEndpoint.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Tauri updater uses HTTP endpoint (no TLS)",
				Description:   "The updater is configured with an HTTP endpoint instead of HTTPS. This allows man-in-the-middle attacks to serve malicious updates, leading to arbitrary code execution on user machines.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Always use HTTPS for updater endpoints. Configure: \"endpoints\": [\"https://your-update-server.com/updates/{{target}}/{{current_version}}\"].",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Confidence:    "high",
				Tags:          []string{"tauri", "updater", "http", "mitm", "framework"},
			})
		}

		if rustDangerousAccept.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Tauri updater configured to accept insecure transport",
				Description:   "dangerous_insecure_transport_protocol(true) disables TLS verification for the updater. This allows man-in-the-middle attacks to serve malicious updates.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove dangerous_insecure_transport_protocol(true). Always use HTTPS with valid certificates for update distribution.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Confidence:    "high",
				Tags:          []string{"tauri", "updater", "tls", "insecure", "framework"},
			})
		}
	}

	// Check for active updater without pubkey (JSON only)
	if ctx.Language == rules.LangJSON && isTauriConfig(ctx.FilePath) {
		if updaterActive.MatchString(ctx.Content) && !strings.Contains(ctx.Content, "\"pubkey\"") {
			for i, line := range lines {
				if strings.Contains(line, "\"updater\"") {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						Title:         "Tauri updater active without signature verification (no pubkey)",
						Description:   "The updater is enabled but no public key (pubkey) is configured for signature verification. Without signature checking, the app will accept any update binary, enabling supply chain attacks.",
						LineNumber:    i + 1,
						MatchedText:   truncate(strings.TrimSpace(line), 120),
						Suggestion:    "Add a pubkey to the updater configuration for signature verification: \"pubkey\": \"your-base64-encoded-public-key\". Generate a key pair with: tauri signer generate -w ~/.tauri/myapp.key.",
						CWEID:         "CWE-347",
						OWASPCategory: "A02:2021-Cryptographic Failures",
						Confidence:    "high",
						Tags:          []string{"tauri", "updater", "signature", "supply-chain", "framework"},
					})
					break
				}
			}
		}
	}

	return findings
}
