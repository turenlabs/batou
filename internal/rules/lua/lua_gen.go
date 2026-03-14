package lua

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns (generated rules LUA-015 through LUA-024)
// ---------------------------------------------------------------------------

// LUA-015: OpenResty args in SQL
var (
	reGenNgxArgsSQL  = regexp.MustCompile(`(?i)(?:ngx\.req\.get_uri_args|ngx\.req\.get_post_args|get_uri_args|get_post_args)`)
	reGenSQLExec     = regexp.MustCompile(`(?i)(?:query|execute|prepare)\s*\(`)
)

// LUA-016: Redis injection
var (
	reGenRedisCall   = regexp.MustCompile(`redis[:\.](?:call|pcall|command)\s*\(|red:(?:get|set|del|hget|hset|lpush|rpush|sadd|zadd|eval)\s*\(`)
	reGenNgxVarArgs  = regexp.MustCompile(`ngx\.var\.|args\[|ngx\.req\.get_uri_args`)
)

// LUA-017: SSRF via ngx.location.capture
var (
	reGenNgxCapture     = regexp.MustCompile(`ngx\.location\.capture\s*\(`)
	reGenNgxCaptureUser = regexp.MustCompile(`ngx\.var\.|args\[|ngx\.req\.get_uri_args`)
)

// LUA-018: Redis Lua sandbox escape
var (
	reGenRedisCallFn  = regexp.MustCompile(`redis\.call\s*\(`)
	reGenLoadstringFn = regexp.MustCompile(`loadstring\s*\(|load\s*\(`)
)

// LUA-019: JWT validation bypass
var (
	reGenJWTVerify  = regexp.MustCompile(`jwt[:\.]verify_jwt_obj\s*\(|jwt[:\.]verify\s*\(`)
	reGenAlgCheck   = regexp.MustCompile(`(?i)(?:\.alg|algorithm|alg\s*==|alg\s*~=|check_alg|allowed_alg)`)
)

// LUA-020: LuaJIT FFI unsafe pointer
var reGenFFICast = regexp.MustCompile(`ffi\.cast\s*\(\s*["'][^"']*[*]`)

// LUA-021: LuaSocket without TLS
var (
	reGenSocketConnect = regexp.MustCompile(`socket\.connect\s*\(|socket\.tcp\s*\(`)
	reGenSSLWrap       = regexp.MustCompile(`ssl\.wrap\s*\(|ssl\.newcontext\s*\(`)
)

// LUA-022: string.dump code leak
var (
	reGenStringDump  = regexp.MustCompile(`string\.dump\s*\(`)
	reGenResponseCtx = regexp.MustCompile(`ngx\.say\s*\(|ngx\.print\s*\(|response|send|write`)
)

// LUA-023: Missing HTTPS redirect
var reGenNgxRedirectHTTP = regexp.MustCompile(`ngx\.redirect\s*\(\s*["']http://`)

// LUA-024: Insecure math.random
var (
	reGenMathRandom   = regexp.MustCompile(`math\.random\s*\(`)
	reGenSecurityCtx  = regexp.MustCompile(`(?i)(?:auth|token|session|secret|key|nonce|salt|csrf|otp|password)`)
)

// ---------------------------------------------------------------------------
// LUA-015: OpenResty Args in SQL
// ---------------------------------------------------------------------------

type OpenRestyArgsSQL struct{}

func (r OpenRestyArgsSQL) ID() string                      { return "BATOU-LUA-015" }
func (r OpenRestyArgsSQL) Name() string                    { return "OpenResty Args in SQL" }
func (r OpenRestyArgsSQL) DefaultSeverity() rules.Severity { return rules.Critical }
func (r OpenRestyArgsSQL) Description() string {
	return "Detects OpenResty request arguments (ngx.req.get_uri_args) used near SQL query/execute calls, indicating potential SQL injection."
}
func (r OpenRestyArgsSQL) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r OpenRestyArgsSQL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenNgxArgsSQL.MatchString(ctx.Content) || !reGenSQLExec.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenSQLExec.MatchString(line) {
			// Check nearby lines for ngx args usage
			start := i - 10
			if start < 0 {
				start = 0
			}
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			hasArgs := false
			for _, nearby := range lines[start:end] {
				if reGenNgxArgsSQL.MatchString(nearby) {
					hasArgs = true
					break
				}
			}
			if hasArgs {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OpenResty request args used in SQL query",
					Description:   "Request arguments from ngx.req.get_uri_args or ngx.req.get_post_args are used near a SQL query/execute call. This enables SQL injection if arguments are not parameterized.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use parameterized queries with ngx_postgres or lua-resty-mysql placeholders. Never concatenate request arguments into SQL strings.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"lua", "openresty", "sql-injection"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-016: Redis Injection
// ---------------------------------------------------------------------------

type RedisInjection struct{}

func (r RedisInjection) ID() string                      { return "BATOU-LUA-016" }
func (r RedisInjection) Name() string                    { return "Redis Injection" }
func (r RedisInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r RedisInjection) Description() string {
	return "Detects Redis commands with user-controlled input from ngx.var or request arguments, enabling Redis injection attacks."
}
func (r RedisInjection) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r RedisInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenNgxVarArgs.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenRedisCall.MatchString(line) && reGenNgxVarArgs.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Redis command with user-controlled input",
				Description:   "Redis commands using ngx.var or request arguments can be exploited to inject additional Redis commands or manipulate data if input is not validated.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Validate and sanitize user input before passing to Redis commands. Use specific Redis APIs rather than raw EVAL. Restrict Redis command access via ACLs.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "redis", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-017: SSRF via ngx.location.capture
// ---------------------------------------------------------------------------

type SSRFNgxCapture struct{}

func (r SSRFNgxCapture) ID() string                      { return "BATOU-LUA-017" }
func (r SSRFNgxCapture) Name() string                    { return "SSRF via ngx.location.capture" }
func (r SSRFNgxCapture) DefaultSeverity() rules.Severity { return rules.Critical }
func (r SSRFNgxCapture) Description() string {
	return "Detects ngx.location.capture with user-controlled arguments, enabling server-side request forgery (SSRF) to access internal services."
}
func (r SSRFNgxCapture) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r SSRFNgxCapture) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenNgxCapture.MatchString(line) {
			// Check if the line or nearby lines use user input
			hasUserInput := reGenNgxCaptureUser.MatchString(line)
			if !hasUserInput {
				start := i - 5
				if start < 0 {
					start = 0
				}
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				for _, nearby := range lines[start:end] {
					if reGenNgxCaptureUser.MatchString(nearby) {
						hasUserInput = true
						break
					}
				}
			}
			if hasUserInput {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SSRF via ngx.location.capture with user input",
					Description:   "ngx.location.capture makes internal subrequests. When the URL path includes user-controlled data (ngx.var, args), attackers can reach internal services and metadata endpoints.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Validate and whitelist allowed capture paths. Never pass raw user input as the capture URL. Use an allowlist of permitted internal locations.",
					CWEID:         "CWE-918",
					OWASPCategory: "A10:2021-Server-Side Request Forgery",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"lua", "openresty", "ssrf"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-018: Redis Lua Sandbox Escape
// ---------------------------------------------------------------------------

type RedisSandboxEscape struct{}

func (r RedisSandboxEscape) ID() string                      { return "BATOU-LUA-018" }
func (r RedisSandboxEscape) Name() string                    { return "Redis Lua Sandbox Escape" }
func (r RedisSandboxEscape) DefaultSeverity() rules.Severity { return rules.Critical }
func (r RedisSandboxEscape) Description() string {
	return "Detects redis.call combined with loadstring/load, which can break out of the Redis Lua sandbox and execute arbitrary code."
}
func (r RedisSandboxEscape) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r RedisSandboxEscape) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenRedisCallFn.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenLoadstringFn.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Redis Lua sandbox escape via loadstring/load",
				Description:   "Using loadstring or load within a Redis Lua script can bypass the Redis Lua sandbox restrictions, enabling arbitrary code execution on the Redis server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Remove loadstring/load from Redis Lua scripts. Use only redis.call/redis.pcall with static commands. Upgrade Redis to versions with stricter sandbox enforcement.",
				CWEID:         "CWE-416",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "redis", "sandbox-escape"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-019: JWT Validation Bypass
// ---------------------------------------------------------------------------

type JWTValidationBypass struct{}

func (r JWTValidationBypass) ID() string                      { return "BATOU-LUA-019" }
func (r JWTValidationBypass) Name() string                    { return "JWT Validation Bypass" }
func (r JWTValidationBypass) DefaultSeverity() rules.Severity { return rules.Critical }
func (r JWTValidationBypass) Description() string {
	return "Detects JWT verification without algorithm validation, which allows attackers to forge tokens using the 'none' algorithm or switch from RS256 to HS256."
}
func (r JWTValidationBypass) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r JWTValidationBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenJWTVerify.MatchString(line) {
			// Check surrounding context for algorithm validation
			hasAlgCheck := false
			start := i - 10
			if start < 0 {
				start = 0
			}
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			for _, nearby := range lines[start:end] {
				if reGenAlgCheck.MatchString(nearby) {
					hasAlgCheck = true
					break
				}
			}
			if !hasAlgCheck {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT verification without algorithm check",
					Description:   "JWT verification without explicit algorithm validation allows attackers to forge tokens by changing the algorithm to 'none' or switching from asymmetric (RS256) to symmetric (HS256) signing.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Always specify and verify the expected JWT algorithm. Check jwt_obj.header.alg against an allowlist before accepting the token.",
					CWEID:         "CWE-347",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"lua", "jwt", "authentication"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-020: LuaJIT FFI Unsafe Pointer
// ---------------------------------------------------------------------------

type FFIUnsafePointer struct{}

func (r FFIUnsafePointer) ID() string                      { return "BATOU-LUA-020" }
func (r FFIUnsafePointer) Name() string                    { return "LuaJIT FFI Unsafe Pointer" }
func (r FFIUnsafePointer) DefaultSeverity() rules.Severity { return rules.High }
func (r FFIUnsafePointer) Description() string {
	return "Detects LuaJIT FFI ffi.cast with pointer types, which can bypass Lua's memory safety guarantees and cause memory corruption."
}
func (r FFIUnsafePointer) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r FFIUnsafePointer) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenFFICast.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LuaJIT FFI cast with pointer type",
				Description:   "ffi.cast with pointer types bypasses Lua's memory safety. Incorrect pointer arithmetic, type mismatches, or dangling pointers can cause memory corruption and code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Minimize ffi.cast usage. Validate pointer arithmetic carefully. Use ffi.new for type-safe allocation and avoid casting between incompatible pointer types.",
				CWEID:         "CWE-119",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "ffi", "pointer-cast"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-021: LuaSocket Without TLS
// ---------------------------------------------------------------------------

type LuaSocketWithoutTLS struct{}

func (r LuaSocketWithoutTLS) ID() string                      { return "BATOU-LUA-021" }
func (r LuaSocketWithoutTLS) Name() string                    { return "LuaSocket Without TLS" }
func (r LuaSocketWithoutTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r LuaSocketWithoutTLS) Description() string {
	return "Detects LuaSocket connections (socket.connect/socket.tcp) without SSL/TLS wrapping, exposing data to eavesdropping."
}
func (r LuaSocketWithoutTLS) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r LuaSocketWithoutTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if reGenSSLWrap.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenSocketConnect.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LuaSocket connection without TLS",
				Description:   "socket.connect or socket.tcp creates a plaintext connection. Without ssl.wrap, all data transmitted is visible to network attackers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Wrap the socket with LuaSec: local ssl = require('ssl'); local conn = ssl.wrap(sock, params). Configure TLS with appropriate protocol versions and cipher suites.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "socket", "cleartext"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-022: string.dump Code Leak
// ---------------------------------------------------------------------------

type StringDumpCodeLeak struct{}

func (r StringDumpCodeLeak) ID() string                      { return "BATOU-LUA-022" }
func (r StringDumpCodeLeak) Name() string                    { return "string.dump Code Leak" }
func (r StringDumpCodeLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r StringDumpCodeLeak) Description() string {
	return "Detects string.dump usage in response context, which can leak bytecode containing function implementations and internal logic."
}
func (r StringDumpCodeLeak) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r StringDumpCodeLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenResponseCtx.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenStringDump.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "string.dump in response context",
				Description:   "string.dump serializes a function to bytecode. When included in HTTP responses, this leaks compiled code that can be reverse-engineered to extract business logic and secrets.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Remove string.dump from response paths. If bytecode serialization is needed for caching, ensure it is never exposed in client-facing responses.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "information-disclosure", "bytecode"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-023: Missing HTTPS Redirect
// ---------------------------------------------------------------------------

type MissingHTTPSRedirect struct{}

func (r MissingHTTPSRedirect) ID() string                      { return "BATOU-LUA-023" }
func (r MissingHTTPSRedirect) Name() string                    { return "Missing HTTPS Redirect" }
func (r MissingHTTPSRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r MissingHTTPSRedirect) Description() string {
	return "Detects ngx.redirect with an HTTP (non-HTTPS) URL, which sends users to an unencrypted endpoint."
}
func (r MissingHTTPSRedirect) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r MissingHTTPSRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenNgxRedirectHTTP.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ngx.redirect to HTTP URL",
				Description:   "ngx.redirect is sending users to an HTTP (plaintext) URL. This exposes session cookies, credentials, and data to network eavesdropping.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use HTTPS URLs in redirects: ngx.redirect(\"https://...\"). Configure nginx to redirect all HTTP traffic to HTTPS at the server block level.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "openresty", "cleartext"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-024: Insecure math.random
// ---------------------------------------------------------------------------

type InsecureMathRandom struct{}

func (r InsecureMathRandom) ID() string                      { return "BATOU-LUA-024" }
func (r InsecureMathRandom) Name() string                    { return "Insecure math.random" }
func (r InsecureMathRandom) DefaultSeverity() rules.Severity { return rules.High }
func (r InsecureMathRandom) Description() string {
	return "Detects math.random usage in security-sensitive contexts (auth, tokens, sessions). math.random is a weak PRNG not suitable for cryptographic purposes."
}
func (r InsecureMathRandom) Languages() []rules.Language { return []rules.Language{rules.LangLua} }

func (r InsecureMathRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenSecurityCtx.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenMathRandom.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "math.random in security-sensitive context",
				Description:   "math.random uses a weak PRNG (typically linear congruential) that is predictable and unsuitable for generating tokens, session IDs, or cryptographic keys.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use a cryptographically secure random source: read from /dev/urandom via io.open, or use OpenSSL bindings (resty.random or ffi-based).",
				CWEID:         "CWE-330",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "crypto", "weak-random"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(OpenRestyArgsSQL{})
	rules.Register(RedisInjection{})
	rules.Register(SSRFNgxCapture{})
	rules.Register(RedisSandboxEscape{})
	rules.Register(JWTValidationBypass{})
	rules.Register(FFIUnsafePointer{})
	rules.Register(LuaSocketWithoutTLS{})
	rules.Register(StringDumpCodeLeak{})
	rules.Register(MissingHTTPSRedirect{})
	rules.Register(InsecureMathRandom{})
}
