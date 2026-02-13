package golang

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// GO-001: GORM Raw SQL Injection
var (
	reGORMRawSprintf  = regexp.MustCompile(`\b(?:db|tx|gdb|gorm)\s*\.\s*(?:Raw|Exec)\s*\(\s*fmt\.Sprintf\s*\(`)
	reGORMRawConcat   = regexp.MustCompile(`\b(?:db|tx|gdb|gorm)\s*\.\s*(?:Raw|Exec)\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)`)
	reGORMWhereConcat = regexp.MustCompile(`\b(?:db|tx|gdb|gorm)\s*\.\s*Where\s*\(\s*fmt\.Sprintf\s*\(`)
)

// GO-002: template.HTML type conversion
var (
	reTemplateHTML   = regexp.MustCompile(`template\.HTML\s*\(`)
	reTemplateHTMLAttr = regexp.MustCompile(`template\.HTMLAttr\s*\(`)
	reTemplateJS     = regexp.MustCompile(`template\.JS\s*\(`)
	reTemplateCSS    = regexp.MustCompile(`template\.CSS\s*\(`)
	reTemplateURL    = regexp.MustCompile(`template\.URL\s*\(`)
	// Suppress if the argument is a string literal
	reTemplateTypeLiteral = regexp.MustCompile(`template\.(?:HTML|HTMLAttr|JS|CSS|URL)\s*\(\s*["` + "`]")
)

// GO-003: ListenAndServe without TLS
var (
	reListenAndServe    = regexp.MustCompile(`\bhttp\.ListenAndServe\s*\(`)
	reListenAndServeTLS = regexp.MustCompile(`\bhttp\.ListenAndServeTLS\b`)
	reTLSConfig         = regexp.MustCompile(`\btls\.Config\b`)
)

// GO-004: Gin/Echo bind without validation
var (
	reGinBind       = regexp.MustCompile(`\.(?:Bind|BindJSON|BindXML|BindQuery|BindYAML|BindHeader|BindUri|ShouldBind|ShouldBindJSON|ShouldBindXML|ShouldBindQuery|ShouldBindYAML|ShouldBindHeader|ShouldBindUri)\s*\(`)
	reGinValidate   = regexp.MustCompile(`(?i)(?:validate|validator|binding:"[^"]*required)`)
	reEchoBind      = regexp.MustCompile(`\.\s*Bind\s*\(\s*&`)
	reEchoValidate  = regexp.MustCompile(`(?i)(?:validate|validator|Validate\s*\()`)
)

// GO-005: filepath.Clean traversal
var (
	reFilepathJoin      = regexp.MustCompile(`filepath\.Join\s*\(`)
	reFilepathClean     = regexp.MustCompile(`filepath\.Clean\s*\(`)
	reHasPrefix         = regexp.MustCompile(`strings\.HasPrefix\s*\(`)
	reUserInputHTTP     = regexp.MustCompile(`r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get|PathValue)\s*\(|mux\.Vars|chi\.URLParam|c\.(?:Param|Query|DefaultQuery|PostForm)|ctx\.(?:Param|QueryParam|FormValue)`)
)

// GO-006: math/rand for crypto operations
var (
	reGoMathRandImport = regexp.MustCompile(`"math/rand"`)
	reGoRandCryptoUse  = regexp.MustCompile(`\brand\.(?:Read|Int|Intn|Int63|Int31|Float64|Float32|Uint32|Uint64|New|NewSource)\s*\(`)
	reGoCryptoContext  = regexp.MustCompile(`(?i)(token|key|secret|nonce|salt|password|session|otp|csrf|iv|encrypt|cipher|sign|hmac|auth|credential)`)
)

// GO-007: Goroutine leak in HTTP handler
var (
	reGoFuncInHandler   = regexp.MustCompile(`\bgo\s+func\s*\(`)
	reGoFuncNamed       = regexp.MustCompile(`\bgo\s+\w+\s*\(`)
	reContextDone       = regexp.MustCompile(`(?:ctx|context)\.Done\s*\(\)|<-\s*(?:ctx|context)\.Done\s*\(\)|context\.WithCancel|context\.WithTimeout|context\.WithDeadline|select\s*\{`)
	reHTTPHandlerSig    = regexp.MustCompile(`func\s+\w*\s*\(\s*w\s+http\.ResponseWriter|func\s*\(\s*w\s+http\.ResponseWriter|http\.Handler|http\.HandlerFunc|gin\.Context|echo\.Context|fiber\.Ctx`)
)

// GO-008: Race condition in HTTP handler
var (
	rePackageVarAssign = regexp.MustCompile(`^\s*var\s+\w+\s`)
	reGlobalMapAccess  = regexp.MustCompile(`\b(cache|store|counter|count|visitors|sessions|connections|state|data|registry|handlers|routes)\s*\[`)
	reMutexUsage       = regexp.MustCompile(`(?i)(?:sync\.(?:Mutex|RWMutex)|\.Lock\(\)|\.RLock\(\)|\.Unlock\(\)|\.RUnlock\(\)|sync\.Map|atomic\.)`)
)

// GO-009: Unvalidated redirect with user input (Go-specific patterns beyond GEN-004)
var (
	reHTTPRedirectReq    = regexp.MustCompile(`http\.Redirect\s*\(\s*\w+\s*,\s*\w+\s*,\s*r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|Header\.Get)\s*\(`)
	reGinRedirectReq     = regexp.MustCompile(`c\.Redirect\s*\(\s*\d+\s*,\s*c\.(?:Query|Param|PostForm|DefaultQuery|GetHeader)\s*\(`)
	reEchoRedirectReq    = regexp.MustCompile(`(?:c|ctx)\.Redirect\s*\(\s*\d+\s*,\s*(?:c|ctx)\.(?:QueryParam|Param|FormValue)\s*\(`)
)

// GO-010: Missing CSRF in form handler
var (
	reFormHandler    = regexp.MustCompile(`\.(?:POST|Put|Patch|Delete|HandleFunc)\s*\(\s*["']`)
	reCSRFMiddleware = regexp.MustCompile(`(?i)(?:csrf|nosurf|gorilla/csrf|CSRFProtect|CSRF\s*\(|csrfProtection)`)
	reFormParse      = regexp.MustCompile(`r\.ParseForm\(\)|r\.ParseMultipartForm|r\.PostForm|r\.FormValue`)
)

// GO-011: Hardcoded JWT secret
var (
	reJWTNewWithClaims = regexp.MustCompile(`jwt\.(?:NewWithClaims|New)\s*\(`)
	reJWTSigningKey    = regexp.MustCompile(`\.(?:SignedString|SigningKey)\s*\(\s*\[\]byte\s*\(\s*["']`)
	reJWTParseKey      = regexp.MustCompile(`jwt\.Parse\s*\([^,]+,\s*func`)
	reJWTKeyLiteral    = regexp.MustCompile(`\[\]byte\s*\(\s*["'][^"']{4,}["']\s*\)`)
	reJWTKeyVariable   = regexp.MustCompile(`(?i)(jwt_secret|jwt_key|signing_key|token_secret|jwtSecret|signingKey|tokenSecret)\s*[:=]\s*["'][^"']{4,}["']`)
)

// GO-012: os.MkdirAll with permissive mode
var (
	reMkdirAllPermissive = regexp.MustCompile(`os\.MkdirAll\s*\([^,]+,\s*0o?777\s*\)`)
	reMkdirPermissive    = regexp.MustCompile(`os\.Mkdir\s*\([^,]+,\s*0o?777\s*\)`)
	reWriteFilePermissive = regexp.MustCompile(`os\.WriteFile\s*\([^,]+,[^,]+,\s*0o?(?:777|766|776)\s*\)`)
	reOpenFilePermissive = regexp.MustCompile(`os\.OpenFile\s*\([^,]+,[^,]+,\s*0o?(?:777|766|776)\s*\)`)
)

// GO-013: Gin/Echo trusted proxy misconfiguration
var (
	reGinTrustAllProxies   = regexp.MustCompile(`\.TrustedPlatform\s*=\s*""`)
	reGinSetTrustedProxies = regexp.MustCompile(`\.SetTrustedProxies\s*\(\s*nil\s*\)`)
	reGinForwardedByClient = regexp.MustCompile(`\.ForwardedByClientIP\s*=\s*true`)
	reEchoIPExtractor      = regexp.MustCompile(`IPExtractor\s*=\s*echo\.ExtractIPFromXFFHeader`)
	reGinNoTrustedProxies  = regexp.MustCompile(`SetTrustedProxies`)
)

// GO-014: Unsafe HTTP response (writing user input without Content-Type)
var (
	reResponseWrite       = regexp.MustCompile(`w\.Write\s*\(\s*\[\]byte\s*\(\s*(?:r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)|(?:c|ctx)\.(?:Query|Param|QueryParam|FormValue))\s*\(`)
	reFprintfResponse     = regexp.MustCompile(`fmt\.Fprint(?:f|ln)?\s*\(\s*w\s*,\s*(?:r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)|(?:c|ctx)\.(?:Query|Param|QueryParam|FormValue))\s*\(`)
	reSetContentType      = regexp.MustCompile(`w\.Header\(\)\.Set\s*\(\s*["']Content-Type["']`)
)

func init() {
	rules.Register(&GORMSQLInjection{})
	rules.Register(&TemplateHTMLBypass{})
	rules.Register(&ListenAndServeNoTLS{})
	rules.Register(&BindWithoutValidation{})
	rules.Register(&FilepathTraversal{})
	rules.Register(&MathRandCrypto{})
	rules.Register(&GoroutineLeak{})
	rules.Register(&RaceConditionHandler{})
	rules.Register(&UnvalidatedRedirect{})
	rules.Register(&MissingCSRF{})
	rules.Register(&HardcodedJWTSecret{})
	rules.Register(&PermissiveFileMode{})
	rules.Register(&TrustedProxyMisconfig{})
	rules.Register(&UnsafeHTTPResponse{})
}

// --- Helpers ---

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func surroundingContext(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// hasNearbyUserInput checks if HTTP user input sources appear within a window of lines.
func hasNearbyUserInput(lines []string, idx, window int) bool {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if reUserInputHTTP.MatchString(l) {
			return true
		}
	}
	return false
}

// isInHTTPHandler checks if context suggests an HTTP handler function.
func isInHTTPHandler(content string) bool {
	return reHTTPHandlerSig.MatchString(content)
}

// --- GO-001: GORM Raw SQL Injection ---

type GORMSQLInjection struct{}

func (r *GORMSQLInjection) ID() string                      { return "GTSS-GO-001" }
func (r *GORMSQLInjection) Name() string                    { return "GORMSQLInjection" }
func (r *GORMSQLInjection) Description() string             { return "Detects GORM Raw/Exec/Where with fmt.Sprintf or string concatenation, enabling SQL injection via ORM bypass." }
func (r *GORMSQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *GORMSQLInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *GORMSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
	}

	patterns := []pattern{
		{reGORMRawSprintf, "db.Raw/Exec with fmt.Sprintf"},
		{reGORMRawConcat, "db.Raw/Exec with string concatenation"},
		{reGORMWhereConcat, "db.Where with fmt.Sprintf"},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "GORM SQL injection via " + p.desc,
					Description:   "GORM's Raw(), Exec(), and Where() accept parameterized queries. Using fmt.Sprintf or string concatenation bypasses GORM's built-in SQL injection protection.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use GORM's parameterized query syntax: db.Raw(\"SELECT * FROM users WHERE id = ?\", userID) or db.Where(\"name = ?\", name).",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"go", "gorm", "sql-injection"},
				})
				break
			}
		}
	}
	return findings
}

// --- GO-002: template.HTML type conversion ---

type TemplateHTMLBypass struct{}

func (r *TemplateHTMLBypass) ID() string                      { return "GTSS-GO-002" }
func (r *TemplateHTMLBypass) Name() string                    { return "TemplateHTMLBypass" }
func (r *TemplateHTMLBypass) Description() string             { return "Detects template.HTML() and similar type conversions that bypass html/template's auto-escaping." }
func (r *TemplateHTMLBypass) DefaultSeverity() rules.Severity { return rules.High }
func (r *TemplateHTMLBypass) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *TemplateHTMLBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
	}

	patterns := []pattern{
		{reTemplateHTML, "template.HTML()"},
		{reTemplateHTMLAttr, "template.HTMLAttr()"},
		{reTemplateJS, "template.JS()"},
		{reTemplateCSS, "template.CSS()"},
		{reTemplateURL, "template.URL()"},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				// Skip if the argument is a string literal (safe)
				if reTemplateTypeLiteral.MatchString(line) {
					continue
				}
				confidence := "medium"
				if hasNearbyUserInput(lines, i, 10) {
					confidence = "high"
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Template escaping bypass via " + p.desc,
					Description:   p.desc + " marks content as safe, bypassing html/template's automatic XSS escaping. If the input contains user-controlled data, this enables cross-site scripting.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Avoid template.HTML() with user-controlled input. If raw HTML is needed, sanitize with a library like bluemonday before converting.",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    confidence,
					Tags:          []string{"go", "template", "xss", "escaping-bypass"},
				})
				break
			}
		}
	}
	return findings
}

// --- GO-003: ListenAndServe without TLS ---

type ListenAndServeNoTLS struct{}

func (r *ListenAndServeNoTLS) ID() string                      { return "GTSS-GO-003" }
func (r *ListenAndServeNoTLS) Name() string                    { return "ListenAndServeNoTLS" }
func (r *ListenAndServeNoTLS) Description() string             { return "Detects net/http.ListenAndServe (plaintext HTTP) without a corresponding TLS configuration." }
func (r *ListenAndServeNoTLS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ListenAndServeNoTLS) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *ListenAndServeNoTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if TLS is configured elsewhere in the file
	if reListenAndServeTLS.MatchString(ctx.Content) || reTLSConfig.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if loc := reListenAndServe.FindStringIndex(line); loc != nil {
			// Skip if binding to localhost only
			if strings.Contains(line, `"localhost:`) || strings.Contains(line, `"127.0.0.1:`) || strings.Contains(line, `":0"`) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "HTTP server without TLS (plaintext)",
				Description:   "http.ListenAndServe starts a plaintext HTTP server. All data including credentials, tokens, and session cookies are transmitted unencrypted.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use http.ListenAndServeTLS() with a certificate, or place behind a TLS-terminating reverse proxy. For development, use localhost binding.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "tls", "plaintext", "transport"},
			})
		}
	}
	return findings
}

// --- GO-004: Bind without validation ---

type BindWithoutValidation struct{}

func (r *BindWithoutValidation) ID() string                      { return "GTSS-GO-004" }
func (r *BindWithoutValidation) Name() string                    { return "BindWithoutValidation" }
func (r *BindWithoutValidation) Description() string             { return "Detects Gin/Echo request binding without input validation, which may allow unexpected or malicious data." }
func (r *BindWithoutValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *BindWithoutValidation) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *BindWithoutValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if validation is used in the file
	if reGinValidate.MatchString(ctx.Content) || reEchoValidate.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if loc := reGinBind.FindStringIndex(line); loc != nil {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Request binding without input validation",
				Description:   "Gin/Echo request binding deserializes user input directly into structs without validation. Missing validation allows out-of-range values, SQL injection payloads, or XSS in bound fields.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add struct validation tags (binding:\"required,min=1,max=100\") and use ShouldBind* methods, or call a validator after binding.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"go", "gin", "echo", "validation", "binding"},
			})
		}
	}
	return findings
}

// --- GO-005: filepath traversal ---

type FilepathTraversal struct{}

func (r *FilepathTraversal) ID() string                      { return "GTSS-GO-005" }
func (r *FilepathTraversal) Name() string                    { return "FilepathTraversal" }
func (r *FilepathTraversal) Description() string             { return "Detects filepath.Join/Clean with user input but without a HasPrefix check, which allows path traversal even after cleaning." }
func (r *FilepathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *FilepathTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *FilepathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if HasPrefix check is present (proper mitigation)
	if reHasPrefix.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reFilepathJoin.MatchString(line) && hasNearbyUserInput(lines, i, 10) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Path traversal via filepath.Join with user input",
				Description:   "filepath.Join with user-controlled path segments does not prevent traversal. filepath.Clean normalizes but still allows escaping the intended directory (e.g., ../../etc/passwd resolves to a valid path).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "After filepath.Join/Clean, verify the result starts with the expected base directory: if !strings.HasPrefix(cleanPath, baseDir) { return error }.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "path-traversal", "filepath"},
			})
		}
	}
	return findings
}

// --- GO-006: math/rand for crypto ---

type MathRandCrypto struct{}

func (r *MathRandCrypto) ID() string                      { return "GTSS-GO-006" }
func (r *MathRandCrypto) Name() string                    { return "MathRandCrypto" }
func (r *MathRandCrypto) Description() string             { return "Detects math/rand usage in security-sensitive contexts where crypto/rand should be used." }
func (r *MathRandCrypto) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *MathRandCrypto) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *MathRandCrypto) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only applies if math/rand is imported
	if !reGoMathRandImport.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if loc := reGoRandCryptoUse.FindStringIndex(line); loc != nil {
			if reGoCryptoContext.MatchString(line) || reGoCryptoContext.MatchString(surroundingContext(lines, i, 5)) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "math/rand used in security-sensitive context",
					Description:   "math/rand uses a deterministic PRNG (even with auto-seeding in Go 1.20+). It is not suitable for generating tokens, keys, nonces, or any cryptographic material.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use crypto/rand.Read() or crypto/rand.Int() for cryptographically secure random values.",
					CWEID:         "CWE-330",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"go", "crypto", "random", "math-rand"},
				})
			}
		}
	}
	return findings
}

// --- GO-007: Goroutine leak in HTTP handler ---

type GoroutineLeak struct{}

func (r *GoroutineLeak) ID() string                      { return "GTSS-GO-007" }
func (r *GoroutineLeak) Name() string                    { return "GoroutineLeak" }
func (r *GoroutineLeak) Description() string             { return "Detects goroutines launched in HTTP handlers without context cancellation, which can leak goroutines." }
func (r *GoroutineLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GoroutineLeak) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *GoroutineLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag in HTTP handlers
	if !isInHTTPHandler(ctx.Content) {
		return nil
	}

	// Skip if context cancellation patterns are present
	if reContextDone.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if loc := reGoFuncInHandler.FindString(line); loc != "" {
			matched = loc
		} else if loc := reGoFuncNamed.FindString(line); loc != "" {
			// Avoid matching "go build", "go test", etc. in strings
			if !strings.Contains(line, `"go `) && !strings.Contains(line, "'go ") {
				matched = loc
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Goroutine in HTTP handler without context cancellation",
				Description:   "Launching goroutines in HTTP handlers without context-based cancellation can cause goroutine leaks. When the client disconnects, the goroutine continues running indefinitely, consuming memory and CPU.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Pass r.Context() to the goroutine and select on ctx.Done() to handle cancellation. Use context.WithTimeout() for background work with deadlines.",
				CWEID:         "CWE-400",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "goroutine", "leak", "context"},
			})
		}
	}
	return findings
}

// --- GO-008: Race condition in HTTP handler ---

type RaceConditionHandler struct{}

func (r *RaceConditionHandler) ID() string                      { return "GTSS-GO-008" }
func (r *RaceConditionHandler) Name() string                    { return "RaceConditionHandler" }
func (r *RaceConditionHandler) Description() string             { return "Detects shared mutable state accessed in HTTP handlers without synchronization (mutex, sync.Map, atomic)." }
func (r *RaceConditionHandler) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RaceConditionHandler) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *RaceConditionHandler) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag in HTTP handler contexts
	if !isInHTTPHandler(ctx.Content) {
		return nil
	}

	// Skip if synchronization primitives are used
	if reMutexUsage.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if loc := reGlobalMapAccess.FindStringIndex(line); loc != nil {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Potential race condition: shared map access without synchronization",
				Description:   "Accessing shared maps or variables in HTTP handlers without a mutex or sync.Map causes data races. Go's HTTP server handles requests concurrently, so shared state must be protected.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use sync.Mutex to protect shared state, sync.Map for concurrent map access, or atomic operations for counters. Run tests with -race to detect races.",
				CWEID:         "CWE-362",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "race-condition", "concurrency"},
			})
		}
	}
	return findings
}

// --- GO-009: Unvalidated redirect ---

type UnvalidatedRedirect struct{}

func (r *UnvalidatedRedirect) ID() string                      { return "GTSS-GO-009" }
func (r *UnvalidatedRedirect) Name() string                    { return "UnvalidatedRedirect" }
func (r *UnvalidatedRedirect) Description() string             { return "Detects HTTP redirects using user-controlled URL parameters in Go web frameworks (net/http, Gin, Echo)." }
func (r *UnvalidatedRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnvalidatedRedirect) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *UnvalidatedRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
	}

	patterns := []pattern{
		{reHTTPRedirectReq, "http.Redirect with request parameter"},
		{reGinRedirectReq, "Gin c.Redirect with user input"},
		{reEchoRedirectReq, "Echo ctx.Redirect with user input"},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Open redirect via " + p.desc,
					Description:   "Redirecting to a user-controlled URL without validation enables phishing attacks. An attacker can craft a URL that redirects victims to a malicious site after authentication.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Validate redirect URLs against an allowlist of trusted domains. Only allow relative paths or check url.Parse().Host against known hosts.",
					CWEID:         "CWE-601",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"go", "redirect", "open-redirect"},
				})
				break
			}
		}
	}
	return findings
}

// --- GO-010: Missing CSRF ---

type MissingCSRF struct{}

func (r *MissingCSRF) ID() string                      { return "GTSS-GO-010" }
func (r *MissingCSRF) Name() string                    { return "MissingCSRF" }
func (r *MissingCSRF) Description() string             { return "Detects POST/PUT/DELETE form handlers without CSRF protection middleware." }
func (r *MissingCSRF) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingCSRF) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *MissingCSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if CSRF middleware is present anywhere in the file
	if reCSRFMiddleware.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reFormHandler.MatchString(line) {
			// Check if the handler parses form data
			context := surroundingContext(lines, i, 15)
			if reFormParse.MatchString(context) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Form handler without CSRF protection",
					Description:   "POST/PUT/DELETE handlers processing form data without CSRF middleware are vulnerable to cross-site request forgery. An attacker's site can submit forms on behalf of authenticated users.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Add CSRF middleware: gorilla/csrf, nosurf, or your framework's CSRF protection. Include a CSRF token in forms and validate it on submission.",
					CWEID:         "CWE-352",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"go", "csrf", "form"},
				})
			}
		}
	}
	return findings
}

// --- GO-011: Hardcoded JWT Secret ---

type HardcodedJWTSecret struct{}

func (r *HardcodedJWTSecret) ID() string                      { return "GTSS-GO-011" }
func (r *HardcodedJWTSecret) Name() string                    { return "HardcodedJWTSecret" }
func (r *HardcodedJWTSecret) Description() string             { return "Detects hardcoded JWT signing keys in Go code." }
func (r *HardcodedJWTSecret) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedJWTSecret) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *HardcodedJWTSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files that reference JWT
	if !strings.Contains(ctx.Content, "jwt") && !strings.Contains(ctx.Content, "JWT") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		var desc string

		if reJWTSigningKey.MatchString(line) {
			matched = true
			desc = "JWT SignedString with hardcoded []byte key"
		} else if reJWTKeyVariable.MatchString(line) {
			matched = true
			desc = "JWT secret assigned as string literal"
		} else if reJWTKeyLiteral.MatchString(line) {
			// Only flag []byte("literal") near JWT context
			context := surroundingContext(lines, i, 5)
			if strings.Contains(context, "jwt") || strings.Contains(context, "JWT") || strings.Contains(context, "SignedString") || strings.Contains(context, "token") {
				matched = true
				desc = "Hardcoded []byte key in JWT context"
			}
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded JWT secret: " + desc,
				Description:   "JWT signing keys must not be hardcoded in source code. An attacker with access to the code can forge arbitrary JWT tokens, bypassing all authentication and authorization.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Load JWT signing keys from environment variables (os.Getenv(\"JWT_SECRET\")), a secrets manager (Vault, AWS Secrets Manager), or a key file with restricted permissions.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "jwt", "hardcoded-secret"},
			})
		}
	}
	return findings
}

// --- GO-012: Permissive file mode ---

type PermissiveFileMode struct{}

func (r *PermissiveFileMode) ID() string                      { return "GTSS-GO-012" }
func (r *PermissiveFileMode) Name() string                    { return "PermissiveFileMode" }
func (r *PermissiveFileMode) Description() string             { return "Detects os.MkdirAll, os.Mkdir, os.WriteFile, and os.OpenFile with world-writable permissions (0777)." }
func (r *PermissiveFileMode) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PermissiveFileMode) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *PermissiveFileMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
	}

	patterns := []pattern{
		{reMkdirAllPermissive, "os.MkdirAll with mode 0777"},
		{reMkdirPermissive, "os.Mkdir with mode 0777"},
		{reWriteFilePermissive, "os.WriteFile with world-writable mode"},
		{reOpenFilePermissive, "os.OpenFile with world-writable mode"},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Overly permissive file mode: " + p.desc,
					Description:   "World-writable file permissions (0777) allow any user on the system to read, write, and execute. This can lead to privilege escalation, data tampering, or arbitrary code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use restrictive permissions: 0750 for directories, 0600 for sensitive files, 0644 for public read-only files.",
					CWEID:         "CWE-732",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"go", "file-permissions", "world-writable"},
				})
				break
			}
		}
	}
	return findings
}

// --- GO-013: Trusted proxy misconfiguration ---

type TrustedProxyMisconfig struct{}

func (r *TrustedProxyMisconfig) ID() string                      { return "GTSS-GO-013" }
func (r *TrustedProxyMisconfig) Name() string                    { return "TrustedProxyMisconfig" }
func (r *TrustedProxyMisconfig) Description() string             { return "Detects Gin/Echo trusted proxy misconfiguration that allows IP spoofing via X-Forwarded-For headers." }
func (r *TrustedProxyMisconfig) DefaultSeverity() rules.Severity { return rules.High }
func (r *TrustedProxyMisconfig) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *TrustedProxyMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		var desc string

		if reGinSetTrustedProxies.MatchString(line) {
			matched = true
			desc = "Gin SetTrustedProxies(nil) trusts all proxies"
		} else if reEchoIPExtractor.MatchString(line) {
			// Echo: extracting IP from X-Forwarded-For without trusted proxy config
			matched = true
			desc = "Echo ExtractIPFromXFFHeader trusts all X-Forwarded-For values"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Trusted proxy misconfiguration: " + desc,
				Description:   "Trusting all proxies allows attackers to spoof their IP address via X-Forwarded-For headers. This bypasses IP-based rate limiting, access control, and audit logging.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Configure trusted proxies explicitly: router.SetTrustedProxies([]string{\"10.0.0.0/8\", \"172.16.0.0/12\"}). For Echo, use echo.ExtractIPFromRealIPHeader() or configure trusted proxy IPs.",
				CWEID:         "CWE-348",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "gin", "echo", "proxy", "ip-spoofing"},
			})
		}
	}
	return findings
}

// --- GO-014: Unsafe HTTP response ---

type UnsafeHTTPResponse struct{}

func (r *UnsafeHTTPResponse) ID() string                      { return "GTSS-GO-014" }
func (r *UnsafeHTTPResponse) Name() string                    { return "UnsafeHTTPResponse" }
func (r *UnsafeHTTPResponse) Description() string             { return "Detects writing user-controlled input directly to HTTP response without sanitization, enabling reflected XSS." }
func (r *UnsafeHTTPResponse) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeHTTPResponse) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *UnsafeHTTPResponse) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		var desc string

		if reResponseWrite.MatchString(line) {
			matched = true
			desc = "w.Write() with user input"
		} else if reFprintfResponse.MatchString(line) {
			matched = true
			desc = "fmt.Fprintf(w, ...) with user input"
		}

		if !matched {
			continue
		}

		// Suppress if Content-Type is set nearby (proper mitigation)
		context := surroundingContext(lines, i, 5)
		if reSetContentType.MatchString(context) {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Reflected XSS via " + desc,
			Description:   "Writing user-controlled input directly to the HTTP response body without HTML escaping or explicit Content-Type enables reflected XSS. Go's net/http defaults to text/html content sniffing.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Set an explicit Content-Type header (e.g., application/json, text/plain) or use html.EscapeString() before writing user input to the response.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"go", "xss", "reflected", "response"},
		})
	}
	return findings
}
