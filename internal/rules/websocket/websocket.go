package websocket

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-WS-001: WebSocket without origin validation
var (
	reWSUpgradeNoOrigin    = regexp.MustCompile(`(?i)(?:websocket\.(?:Upgrader|upgrade)|new\s+WebSocketServer|ws\.Server|Upgrade\s*\()`)
	reWSCheckOriginFalse   = regexp.MustCompile(`(?i)CheckOrigin\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true`)
	reWSOriginAllowed      = regexp.MustCompile(`(?i)(?:allowedOrigins?\s*[=:]\s*\[\s*["']\*["']\s*\]|origin\s*[=:]\s*["']\*["'])`)
	reWSOriginCheck        = regexp.MustCompile(`(?i)(?:CheckOrigin|check_origin|checkOrigin|verifyOrigin|verify_origin|origin_allowed|allowedOrigins|isOriginAllowed)`)
)

// BATOU-WS-002: WebSocket without authentication
var (
	reWSHandler         = regexp.MustCompile(`(?i)(?:\.on\s*\(\s*["']connection["']|def\s+websocket_connect|def\s+ws_connect|@(?:app\.)?websocket|ws\.on\s*\(\s*["']open["']|func.*websocket.*Handler|HandleFunc\s*\(\s*["']/ws)`)
	reWSAuth            = regexp.MustCompile(`(?i)(?:authenticate|authorization|auth_token|isAuthenticated|is_authenticated|verify_token|jwt\.verify|passport|session\.user|currentUser|current_user|req\.user|request\.user|@login_required|@authenticated|@requires_auth|middleware.*auth)`)
)

// BATOU-WS-003: WebSocket message used in eval/exec
var (
	reWSMessageEval     = regexp.MustCompile(`(?i)(?:message\.data|event\.data|msg\.data|data|payload)\s*.*\b(?:eval|exec|Function)\s*\(`)
	reWSOnMessage       = regexp.MustCompile(`(?i)\.on\s*\(\s*["']message["']\s*,\s*(?:function|async|\()`)
	reWSMsgToEval       = regexp.MustCompile(`(?i)(?:eval|exec|Function|compile)\s*\(\s*(?:message|msg|data|payload|event\.data|ws_data)`)
	reWSMsgToExecPy     = regexp.MustCompile(`(?i)(?:on_message|handle_message|receive)\s*\([^)]*\)\s*:.*(?:eval|exec|subprocess|os\.system|os\.popen)\s*\(`)
)

// BATOU-WS-004: WebSocket without rate limiting
var (
	reWSBroadcast       = regexp.MustCompile(`(?i)(?:broadcast|\.send\s*\(|\.emit\s*\(|clients\.forEach|for\s+.*\bclient\b.*\.send)`)
	reWSRateLimit       = regexp.MustCompile(`(?i)(?:rate.?limit|rateLimit|throttle|debounce|max_messages|message_count|flood|spam|cooldown|bucket)`)
)

// BATOU-WS-005: WebSocket broadcasting sensitive data
var (
	reWSSensitiveBroadcast = regexp.MustCompile(`(?i)(?:broadcast|\.send|\.emit)\s*\([^)]*(?:password|passwd|secret|token|api_key|apiKey|credit.?card|ssn|social_security|private_key|privateKey)`)
	reWSBroadcastAll       = regexp.MustCompile(`(?i)(?:broadcast|sendAll|emitAll|io\.emit|wss\.clients\.forEach)\s*\(`)
)

// BATOU-WS-006: WebSocket without TLS (ws:// not wss://)
var (
	reWSInsecureURL     = regexp.MustCompile(`(?i)["']ws://[^"']+["']`)
	reWSInsecureConnect = regexp.MustCompile(`(?i)(?:new\s+WebSocket|WebSocket\.connect|ws\.connect|websocket\.create_connection)\s*\(\s*["']ws://`)
	reWSSecureURL       = regexp.MustCompile(`(?i)["']wss://`)
)

// BATOU-WS-007: WebSocket CSWSH (Cross-Site WebSocket Hijacking)
var (
	reWSNoCORSCheck    = regexp.MustCompile(`(?i)(?:new\s+WebSocket|WebSocket\.connect)\s*\(\s*(?:["'][^"']+["']|url|wsUrl|endpoint)`)
	reWSCookieAuth     = regexp.MustCompile(`(?i)(?:cookie|session|withCredentials|credentials\s*[=:]\s*["']include)`)
)

// BATOU-WS-008: WebSocket message SQL/NoSQL injection
var (
	reWSMsgToSQL       = regexp.MustCompile(`(?i)(?:\.query|\.execute|\.exec|cursor\.execute|db\.query)\s*\(\s*(?:["'][^"']*["']\s*\+\s*(?:message|msg|data|payload)|f["'][^"']*\{(?:message|msg|data|payload)|["'][^"']*["']\s*%\s*(?:message|msg|data|payload))`)
	reWSMsgToMongo     = regexp.MustCompile(`(?i)(?:\.find|\.findOne|\.updateOne|\.deleteOne|\.aggregate)\s*\(\s*(?:JSON\.parse\s*\(\s*(?:message|msg|data|payload)|\{[^}]*:\s*(?:message|msg|data|payload))`)
	reWSMsgToQuery     = regexp.MustCompile(`(?i)(?:message|msg|data|payload|event\.data)\s*.*(?:\.query|\.execute|\.exec|db\.)\s*\(`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

func hasNearbyPattern(lines []string, idx, before, after int, re *regexp.Regexp) bool {
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := idx + after + 1
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-WS-001: WebSocket without origin validation
// ---------------------------------------------------------------------------

type WSNoOriginValidation struct{}

func (r *WSNoOriginValidation) ID() string                     { return "BATOU-WS-001" }
func (r *WSNoOriginValidation) Name() string                   { return "WSNoOriginValidation" }
func (r *WSNoOriginValidation) DefaultSeverity() rules.Severity { return rules.High }
func (r *WSNoOriginValidation) Description() string {
	return "Detects WebSocket server configurations that do not validate the Origin header, or explicitly accept all origins, enabling cross-site WebSocket hijacking."
}
func (r *WSNoOriginValidation) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangRuby, rules.LangPHP}
}

func (r *WSNoOriginValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		// Explicit "accept all origins" patterns
		for _, re := range []*regexp.Regexp{reWSCheckOriginFalse, reWSOriginAllowed} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket accepts all origins",
					Description:   "The WebSocket server is configured to accept connections from any origin. A malicious website can connect to this WebSocket endpoint and send/receive messages on behalf of an authenticated user (Cross-Site WebSocket Hijacking).",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Validate the Origin header against an allowlist of trusted domains. In Go gorilla/websocket, implement a proper CheckOrigin function. In Node.js ws, use the verifyClient option.",
					CWEID:         "CWE-346",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"websocket", "origin-validation", "cswsh"},
				})
				break
			}
		}
		// WebSocket setup without origin check
		if m := reWSUpgradeNoOrigin.FindString(line); m != "" {
			if !hasNearbyPattern(lines, i, 10, 10, reWSOriginCheck) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket server without origin validation",
					Description:   "WebSocket server is created without visible origin validation. Without checking the Origin header, any website can establish a WebSocket connection, potentially hijacking authenticated sessions.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Add origin validation to the WebSocket handshake. Check the Origin header against your domain allowlist before accepting the connection.",
					CWEID:         "CWE-346",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"websocket", "origin-validation", "cswsh"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-002: WebSocket without authentication
// ---------------------------------------------------------------------------

type WSNoAuthentication struct{}

func (r *WSNoAuthentication) ID() string                     { return "BATOU-WS-002" }
func (r *WSNoAuthentication) Name() string                   { return "WSNoAuthentication" }
func (r *WSNoAuthentication) DefaultSeverity() rules.Severity { return rules.High }
func (r *WSNoAuthentication) Description() string {
	return "Detects WebSocket connection handlers that do not verify authentication, allowing unauthenticated users to establish WebSocket connections."
}
func (r *WSNoAuthentication) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangRuby}
}

func (r *WSNoAuthentication) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reWSHandler.FindString(line); m != "" {
			if !hasNearbyPattern(lines, i, 5, 20, reWSAuth) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket connection without authentication",
					Description:   "WebSocket connection handler does not appear to verify user authentication. Unauthenticated users may be able to establish WebSocket connections and access functionality or data intended for authenticated users.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Authenticate WebSocket connections during the handshake (via cookie/session/token in the initial HTTP upgrade request) or immediately after connection with an auth message. Disconnect unauthenticated clients.",
					CWEID:         "CWE-306",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"websocket", "authentication", "access-control"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-003: WebSocket message used in eval/exec
// ---------------------------------------------------------------------------

type WSMessageEval struct{}

func (r *WSMessageEval) ID() string                     { return "BATOU-WS-003" }
func (r *WSMessageEval) Name() string                   { return "WSMessageEval" }
func (r *WSMessageEval) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *WSMessageEval) Description() string {
	return "Detects WebSocket message data passed to eval(), exec(), Function(), or similar code execution functions, enabling remote code execution."
}
func (r *WSMessageEval) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython}
}

func (r *WSMessageEval) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reWSMsgToEval, reWSMessageEval, reWSMsgToExecPy} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket message passed to eval/exec",
					Description:   "Data received from a WebSocket message is passed to eval(), exec(), or a code execution function. An attacker who can send WebSocket messages can execute arbitrary code on the server or client.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Never pass WebSocket message data to eval/exec. Parse messages as JSON with a strict schema. Use a message handler dispatch table (switch/case on message type) instead of dynamic code execution.",
					CWEID:         "CWE-94",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"websocket", "code-injection", "eval", "rce"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-004: WebSocket without rate limiting
// ---------------------------------------------------------------------------

type WSNoRateLimit struct{}

func (r *WSNoRateLimit) ID() string                     { return "BATOU-WS-004" }
func (r *WSNoRateLimit) Name() string                   { return "WSNoRateLimit" }
func (r *WSNoRateLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WSNoRateLimit) Description() string {
	return "Detects WebSocket message handlers without rate limiting, which can be abused for denial of service or resource exhaustion."
}
func (r *WSNoRateLimit) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangRuby}
}

func (r *WSNoRateLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reWSOnMessage.FindString(line); m != "" {
			if !hasNearbyPattern(lines, i, 10, 30, reWSRateLimit) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket handler without rate limiting",
					Description:   "WebSocket message handler does not implement rate limiting. An attacker can flood the WebSocket with messages to exhaust server resources (CPU, memory, database connections) causing denial of service.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Implement per-connection rate limiting for WebSocket messages. Track message count per time window and disconnect clients that exceed the limit. Consider using a token bucket or sliding window algorithm.",
					CWEID:         "CWE-799",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"websocket", "rate-limiting", "dos"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-005: WebSocket broadcasting sensitive data
// ---------------------------------------------------------------------------

type WSSensitiveBroadcast struct{}

func (r *WSSensitiveBroadcast) ID() string                     { return "BATOU-WS-005" }
func (r *WSSensitiveBroadcast) Name() string                   { return "WSSensitiveBroadcast" }
func (r *WSSensitiveBroadcast) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WSSensitiveBroadcast) Description() string {
	return "Detects WebSocket broadcast or send operations that include sensitive data fields like passwords, tokens, API keys, or financial data."
}
func (r *WSSensitiveBroadcast) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangRuby, rules.LangPHP}
}

func (r *WSSensitiveBroadcast) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reWSSensitiveBroadcast.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "WebSocket broadcasting sensitive data",
				Description:   "Sensitive data (password, token, API key, financial data) is being sent or broadcast over WebSocket. This data may be exposed to unintended recipients if broadcast to all connected clients.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Never broadcast sensitive data over WebSocket. Filter sensitive fields before sending. Use targeted sends to specific clients instead of broadcasting. Encrypt sensitive payloads if they must be sent.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"websocket", "sensitive-data", "broadcast"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-006: WebSocket without TLS (ws:// not wss://)
// ---------------------------------------------------------------------------

type WSInsecure struct{}

func (r *WSInsecure) ID() string                     { return "BATOU-WS-006" }
func (r *WSInsecure) Name() string                   { return "WSInsecure" }
func (r *WSInsecure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WSInsecure) Description() string {
	return "Detects WebSocket connections using the insecure ws:// protocol instead of wss://, exposing data to network-level interception."
}
func (r *WSInsecure) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangRuby, rules.LangPHP}
}

func (r *WSInsecure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		// Skip if the line also contains wss:// or is clearly a conditional/comparison
		if reWSSecureURL.MatchString(line) {
			continue
		}
		// Skip localhost/127.0.0.1 connections (development)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "ws://localhost") || strings.Contains(lower, "ws://127.0.0.1") || strings.Contains(lower, "ws://0.0.0.0") {
			continue
		}
		for _, re := range []*regexp.Regexp{reWSInsecureConnect, reWSInsecureURL} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket using insecure ws:// (no TLS)",
					Description:   "WebSocket connection uses the unencrypted ws:// protocol. All data transmitted over this connection can be intercepted and modified by network-level attackers (man-in-the-middle).",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use wss:// (WebSocket Secure) for all production WebSocket connections. This provides TLS encryption, the same as HTTPS for regular HTTP.",
					CWEID:         "CWE-319",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"websocket", "tls", "encryption", "cleartext"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-007: WebSocket CSWSH cross-site hijacking
// ---------------------------------------------------------------------------

type WSCSWSH struct{}

func (r *WSCSWSH) ID() string                     { return "BATOU-WS-007" }
func (r *WSCSWSH) Name() string                   { return "WSCSWSH" }
func (r *WSCSWSH) DefaultSeverity() rules.Severity { return rules.High }
func (r *WSCSWSH) Description() string {
	return "Detects WebSocket client connections that rely on cookie-based authentication without CSRF protection, making them vulnerable to Cross-Site WebSocket Hijacking."
}
func (r *WSCSWSH) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *WSCSWSH) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reWSNoCORSCheck.FindString(line); m != "" {
			// Check if cookie/session-based auth is used nearby
			if hasNearbyPattern(lines, i, 10, 10, reWSCookieAuth) {
				// Check if there's a CSRF token/origin check
				if !hasNearbyPattern(lines, i, 10, 20, reWSOriginCheck) {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "WebSocket CSWSH: cookie auth without origin validation",
						Description:   "WebSocket connection uses cookie-based authentication (withCredentials/session cookies) without origin validation. A malicious website can establish a WebSocket connection that automatically includes the victim's cookies, hijacking their session.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   truncate(m, 120),
						Suggestion:    "Validate the Origin header on the server during WebSocket handshake. Use token-based auth (pass token as query param or first message) instead of cookies. Add a CSRF token to the WebSocket URL.",
						CWEID:         "CWE-346",
						OWASPCategory: "A07:2021-Identification and Authentication Failures",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"websocket", "cswsh", "csrf", "session-hijacking"},
					})
				}
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-WS-008: WebSocket message SQL/NoSQL injection
// ---------------------------------------------------------------------------

type WSMessageInjection struct{}

func (r *WSMessageInjection) ID() string                     { return "BATOU-WS-008" }
func (r *WSMessageInjection) Name() string                   { return "WSMessageInjection" }
func (r *WSMessageInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *WSMessageInjection) Description() string {
	return "Detects WebSocket message data used directly in SQL or NoSQL queries without parameterization, enabling injection attacks."
}
func (r *WSMessageInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo, rules.LangPHP, rules.LangRuby}
}

func (r *WSMessageInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reWSMsgToSQL, reWSMsgToMongo, reWSMsgToQuery} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket message used in SQL/NoSQL query",
					Description:   "Data from a WebSocket message is used directly in a database query via string concatenation. WebSocket messages are fully attacker-controlled and must be treated as untrusted input.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use parameterized queries or prepared statements. Validate and sanitize WebSocket message data against an expected schema before using in database queries.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"websocket", "sql-injection", "nosql-injection"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&WSNoOriginValidation{})
	rules.Register(&WSNoAuthentication{})
	rules.Register(&WSMessageEval{})
	rules.Register(&WSNoRateLimit{})
	rules.Register(&WSSensitiveBroadcast{})
	rules.Register(&WSInsecure{})
	rules.Register(&WSCSWSH{})
	rules.Register(&WSMessageInjection{})
}
