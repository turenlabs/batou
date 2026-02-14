package java

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "#")
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
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
// Compiled regex patterns
// ---------------------------------------------------------------------------

// JAVA-001: JNDI Injection
var (
	reJNDILookup       = regexp.MustCompile(`\.lookup\s*\(\s*[a-zA-Z_]\w*`)
	reJNDILookupConcat = regexp.MustCompile(`\.lookup\s*\(\s*"[^"]*"\s*\+`)
	reInitialContext    = regexp.MustCompile(`new\s+InitialContext\s*\(`)
	reDirContext        = regexp.MustCompile(`new\s+(?:InitialDirContext|InitialLdapContext)\s*\(`)
	reJNDIContext       = regexp.MustCompile(`(?:InitialContext|Context|DirContext|LdapContext)`)
)

// JAVA-002: Expression Language Injection
var (
	reELEval        = regexp.MustCompile(`\.eval\s*\(\s*[a-zA-Z_]\w*`)
	reELValueExpr   = regexp.MustCompile(`\.createValueExpression\s*\(\s*[^"'\s)]`)
	reELMethodExpr  = regexp.MustCompile(`\.createMethodExpression\s*\(\s*[^"'\s)]`)
	reELExprFactory = regexp.MustCompile(`ExpressionFactory\.newInstance`)
	reELConcat      = regexp.MustCompile(`\.createValueExpression\s*\([^)]*"[^"]*"\s*\+`)
)

// JAVA-003: Spring SpEL Injection
var (
	reSpELParser        = regexp.MustCompile(`SpelExpressionParser\s*\(\s*\)`)
	reSpELParseExpr     = regexp.MustCompile(`\.parseExpression\s*\(\s*[a-zA-Z_]\w*`)
	reSpELParseConcat   = regexp.MustCompile(`\.parseExpression\s*\(\s*"[^"]*"\s*\+`)
	reSpELValue         = regexp.MustCompile(`@Value\s*\(\s*"#\{`)
	reSpELRequestParam  = regexp.MustCompile(`request\.getParameter|@RequestParam|@PathVariable|@RequestBody`)
)

// JAVA-004: Hibernate HQL Injection
var (
	reHQLCreateQuery  = regexp.MustCompile(`\.createQuery\s*\(\s*"[^"]*"\s*\+`)
	reHQLCreateQueryV = regexp.MustCompile(`\.createQuery\s*\(\s*[a-zA-Z_]\w*\s*\+`)
	reHQLSession      = regexp.MustCompile(`session\s*\.createQuery\s*\(\s*[a-zA-Z_]\w*`)
	reCriteriaBuilder = regexp.MustCompile(`CriteriaBuilder|CriteriaQuery`)
)

// JAVA-005: JDBC Connection String Injection
var (
	reJDBCDriverManager = regexp.MustCompile(`DriverManager\.getConnection\s*\(\s*[a-zA-Z_]\w*`)
	reJDBCConnConcat    = regexp.MustCompile(`DriverManager\.getConnection\s*\(\s*"[^"]*"\s*\+`)
	reJDBCDataSource    = regexp.MustCompile(`\.getConnection\s*\(\s*"[^"]*"\s*\+`)
)

// JAVA-006: Java RMI Deserialization
var (
	reRMIRegistryBind   = regexp.MustCompile(`\.(?:bind|rebind|lookup)\s*\(`)
	reRMILocateRegistry = regexp.MustCompile(`LocateRegistry\.(?:getRegistry|createRegistry)\s*\(`)
	reRMINaming         = regexp.MustCompile(`Naming\.(?:bind|rebind|lookup)\s*\(`)
	reRMIContext        = regexp.MustCompile(`(?:Registry|UnicastRemoteObject|LocateRegistry|Naming)`)
)

// JAVA-007: Insecure SSL/TLS TrustManager
var (
	reX509TrustManager      = regexp.MustCompile(`implements\s+X509TrustManager`)
	reTrustAllCerts         = regexp.MustCompile(`new\s+X509TrustManager\s*\(\s*\)\s*\{`)
	reCheckServerTrustedEmpty = regexp.MustCompile(`checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}`)
	reTrustManagerFactory    = regexp.MustCompile(`TrustManagerFactory`)
	reSSLContextInit         = regexp.MustCompile(`SSLContext\.getInstance\s*\(`)
	reSSLContextInitNull     = regexp.MustCompile(`\.init\s*\(\s*null\s*,\s*\w+\s*,`)
)

// JAVA-008: Unrestricted File Upload
var (
	reMultipartFile        = regexp.MustCompile(`MultipartFile\b`)
	reTransferTo           = regexp.MustCompile(`\.transferTo\s*\(`)
	reGetOriginalFilename  = regexp.MustCompile(`\.getOriginalFilename\s*\(`)
	reFileExtCheck         = regexp.MustCompile(`(?i)(?:endsWith|contains|matches|contentType|getContentType|getMimeType|extension)`)
)

// JAVA-009: Server-Side Template Injection (extended Java patterns)
var (
	reVelocityEvaluate   = regexp.MustCompile(`Velocity\.evaluate\s*\(`)
	reVelocityMerge      = regexp.MustCompile(`\.merge\s*\(\s*[a-zA-Z_]\w*`)
	reFreemarkerProcess  = regexp.MustCompile(`\.process\s*\(\s*[a-zA-Z_]\w*`)
	reFreemarkerNewTmpl  = regexp.MustCompile(`new\s+Template\s*\(\s*[^"'\s)]`)
	reThymeleafProcess   = regexp.MustCompile(`templateEngine\.process\s*\(\s*[a-zA-Z_]\w*`)
	reSSTIUserInput      = regexp.MustCompile(`request\.getParameter|@RequestParam|@PathVariable`)
)

// JAVA-010: Improper Certificate/Hostname Validation
var (
	reHostnameVerifierAllowAll = regexp.MustCompile(`ALLOW_ALL_HOSTNAME_VERIFIER`)
	reHostnameVerifierNoOp     = regexp.MustCompile(`NoopHostnameVerifier`)
	reHostnameVerifierReturn   = regexp.MustCompile(`verify\s*\([^)]*\)\s*\{\s*return\s+true`)
	reHostnameVerifierImpl     = regexp.MustCompile(`implements\s+HostnameVerifier`)
	reSetHostnameVerifier      = regexp.MustCompile(`\.setHostnameVerifier\s*\(`)
)

// JAVA-011: Hardcoded JDBC Credentials
var (
	reJDBCPasswordInline   = regexp.MustCompile(`DriverManager\.getConnection\s*\(\s*"[^"]*"\s*,\s*"[^"]+"\s*,\s*"[^"]+"`)
	reJDBCURLPassword      = regexp.MustCompile(`"jdbc:[^"]*password=[^"]*"`)
	reDataSourceSetPassword = regexp.MustCompile(`\.setPassword\s*\(\s*"[^"]+"`)
	rePropertiesPassword   = regexp.MustCompile(`(?i)(?:password|passwd)\s*=\s*"[^"]+"`)
)

// JAVA-012: Regex DoS (ReDoS)
var (
	rePatternCompileVar   = regexp.MustCompile(`Pattern\.compile\s*\(\s*[a-zA-Z_]\w*`)
	rePatternCompileConcat = regexp.MustCompile(`Pattern\.compile\s*\(\s*"[^"]*"\s*\+`)
	reStringMatchesVar    = regexp.MustCompile(`\.matches\s*\(\s*[a-zA-Z_]\w*`)
	reReqParam            = regexp.MustCompile(`request\.getParameter|@RequestParam|@PathVariable|@RequestBody`)
)

// JAVA-013: Information Exposure in Error Messages
var (
	rePrintStackTrace      = regexp.MustCompile(`\.printStackTrace\s*\(`)
	rePrintStackTraceResp  = regexp.MustCompile(`\.printStackTrace\s*\(\s*(?:response|res|out|writer|outputStream)`)
	reExceptionToResponse  = regexp.MustCompile(`(?:response\.getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)|out\.print(?:ln)?|writer\.write|writer\.println)\s*\([^)]*(?:\.getMessage|\.toString|\.getStackTrace|stackTrace)`)
	reExceptionCatchAll    = regexp.MustCompile(`catch\s*\(\s*(?:Exception|Throwable)\s+\w+\s*\)`)
	reResponseGetWriter    = regexp.MustCompile(`response\.getWriter|response\.getOutputStream`)
)

// JAVA-014: Insecure Random in Security Context
var (
	reJavaUtilRandom        = regexp.MustCompile(`\bnew\s+Random\s*\(`)
	reJavaRandomImport      = regexp.MustCompile(`\bjava\.util\.Random\b`)
	reThreadLocalRandom     = regexp.MustCompile(`ThreadLocalRandom\.current\(\)`)
	reJavaSecurityContext   = regexp.MustCompile(`(?i)(token|password|key|secret|nonce|salt|otp|csrf|session|uuid|auth|api[_\-]?key|encrypt|hash|credential|certificate)`)
	reJavaSecureRandom      = regexp.MustCompile(`SecureRandom`)
)

// JAVA-015: Missing HttpOnly/Secure on Cookies (broader pattern)
var (
	reNewCookie            = regexp.MustCompile(`new\s+Cookie\s*\(`)
	reAddCookie            = regexp.MustCompile(`\.addCookie\s*\(`)
	reSetHttpOnly          = regexp.MustCompile(`\.setHttpOnly\s*\(\s*true`)
	reSetSecure            = regexp.MustCompile(`\.setSecure\s*\(\s*true`)
	reCookieSensitiveName  = regexp.MustCompile(`(?i)(?:session|token|auth|jwt|csrf|api[_\-]?key|remember)`)
)

// JAVA-016: SSRF via URL class
var (
	reNewURL            = regexp.MustCompile(`new\s+URL\s*\(\s*[a-zA-Z_]\w*`)
	reNewURLConcat      = regexp.MustCompile(`new\s+URL\s*\(\s*"[^"]*"\s*\+`)
	reURLOpenConnection = regexp.MustCompile(`\.openConnection\s*\(`)
	reURLOpenStream     = regexp.MustCompile(`\.openStream\s*\(`)
	reHttpClientExec    = regexp.MustCompile(`(?:HttpClient|CloseableHttpClient)\s*.*\.execute\s*\(`)
	reURICreate         = regexp.MustCompile(`URI\.create\s*\(\s*[a-zA-Z_]\w*`)
)

// JAVA-017: Zip Slip
var (
	reZipEntryGetName    = regexp.MustCompile(`\.getName\s*\(\s*\)`)
	reZipInputStream     = regexp.MustCompile(`ZipInputStream|ZipFile|JarInputStream|JarFile`)
	reFileOutputZip      = regexp.MustCompile(`new\s+File\s*\([^)]*(?:getName|entryName|entry\.getName|zipEntry)`)
	rePathNormalize      = regexp.MustCompile(`(?:normalize|canonical|startsWith|contains\s*\(\s*"\.\.")`)
)

// JAVA-018: Thread Safety Issues (SimpleDateFormat)
var (
	reStaticSimpleDateFormat = regexp.MustCompile(`static\s+(?:final\s+)?SimpleDateFormat\b`)
	reSimpleDateFormatField  = regexp.MustCompile(`(?:private|protected|public)\s+SimpleDateFormat\b`)
	reDateTimeFormatter      = regexp.MustCompile(`DateTimeFormatter`)
	reThreadLocal            = regexp.MustCompile(`ThreadLocal<.*SimpleDateFormat`)
	reSynchronized           = regexp.MustCompile(`synchronized`)
)

// ---------------------------------------------------------------------------
// JAVA-001: JNDI Injection
// ---------------------------------------------------------------------------

type JNDIInjection struct{}

func (r *JNDIInjection) ID() string                      { return "GTSS-JAVA-001" }
func (r *JNDIInjection) Name() string                    { return "JNDIInjection" }
func (r *JNDIInjection) Description() string             { return "Detects JNDI lookup with user-controlled input, enabling remote code execution via Log4Shell-style attacks." }
func (r *JNDIInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JNDIInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JNDIInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasJNDI := reJNDIContext.MatchString(ctx.Content)
	if !hasJNDI {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reJNDILookupConcat.FindString(line); loc != "" {
			matched = loc
			detail = "JNDI lookup with string concatenation"
		} else if loc := reJNDILookup.FindString(line); loc != "" {
			// Only flag if user input is nearby
			if hasNearbyPattern(lines, i, reSpELRequestParam) {
				matched = loc
				detail = "JNDI lookup with user-controlled variable"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JNDI Injection: " + detail,
				Description:   "JNDI lookups with user-controlled input allow remote code execution via LDAP/RMI/DNS rebinding attacks (Log4Shell-style). An attacker can load arbitrary classes from a remote server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to JNDI lookup(). Use an allowlist of permitted JNDI names. Disable remote class loading with com.sun.jndi.ldap.object.trustURLCodebase=false.",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "jndi", "injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-002: Expression Language Injection
// ---------------------------------------------------------------------------

type ELInjection struct{}

func (r *ELInjection) ID() string                      { return "GTSS-JAVA-002" }
func (r *ELInjection) Name() string                    { return "ELInjection" }
func (r *ELInjection) Description() string             { return "Detects Java Expression Language (EL) injection where user input is evaluated as EL expressions." }
func (r *ELInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ELInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *ELInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasELFactory := reELExprFactory.MatchString(ctx.Content)
	if !hasELFactory && !strings.Contains(ctx.Content, "ValueExpression") && !strings.Contains(ctx.Content, "MethodExpression") {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reELConcat.FindString(line); loc != "" {
			matched = loc
			detail = "EL expression created with string concatenation"
		} else if loc := reELValueExpr.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "EL value expression with user-controlled input"
			}
		} else if loc := reELMethodExpr.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "EL method expression with user-controlled input"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Expression Language Injection: " + detail,
				Description:   "User-controlled input evaluated as Java EL expressions can lead to remote code execution. Attackers can call arbitrary methods and access system properties.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to EL expression evaluation. Use parameterized templates or sanitize input against an allowlist of permitted expression patterns.",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "el-injection", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-003: Spring SpEL Injection
// ---------------------------------------------------------------------------

type SpELInjection struct{}

func (r *SpELInjection) ID() string                      { return "GTSS-JAVA-003" }
func (r *SpELInjection) Name() string                    { return "SpELInjection" }
func (r *SpELInjection) Description() string             { return "Detects Spring Expression Language (SpEL) injection where user input is parsed as SpEL expressions." }
func (r *SpELInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SpELInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *SpELInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasSpEL := reSpELParser.MatchString(ctx.Content) || strings.Contains(ctx.Content, "SpelExpression")
	if !hasSpEL {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reSpELParseConcat.FindString(line); loc != "" {
			matched = loc
			detail = "SpEL expression parsed with string concatenation"
		} else if loc := reSpELParseExpr.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reSpELRequestParam) {
				matched = loc
				detail = "SpEL expression parsed with user-controlled input"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring SpEL Injection: " + detail,
				Description:   "Parsing user-controlled input as Spring Expression Language (SpEL) enables remote code execution. Attackers can execute arbitrary system commands via T(java.lang.Runtime).getRuntime().exec().",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to SpelExpressionParser.parseExpression(). Use SimpleEvaluationContext instead of StandardEvaluationContext to restrict available types and methods.",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "spel", "spring", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-004: Hibernate HQL Injection
// ---------------------------------------------------------------------------

type HQLInjection struct{}

func (r *HQLInjection) ID() string                      { return "GTSS-JAVA-004" }
func (r *HQLInjection) Name() string                    { return "HQLInjection" }
func (r *HQLInjection) Description() string             { return "Detects Hibernate HQL/JPQL queries built with string concatenation." }
func (r *HQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *HQLInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *HQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Skip if using CriteriaBuilder (safe API)
	if reCriteriaBuilder.MatchString(ctx.Content) {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if loc := reHQLCreateQuery.FindString(line); loc != "" {
			matched = loc
		} else if loc := reHQLCreateQueryV.FindString(line); loc != "" {
			matched = loc
		} else if loc := reHQLSession.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "HQL Injection: query built with string concatenation",
				Description:   "Hibernate HQL/JPQL queries built with string concatenation are vulnerable to HQL injection. Attackers can manipulate query logic to access or modify data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized HQL queries: session.createQuery(\"FROM User WHERE name = :name\").setParameter(\"name\", value). Or use CriteriaBuilder API.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "hibernate", "hql", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-005: JDBC Connection String Injection
// ---------------------------------------------------------------------------

type JDBCConnectionInjection struct{}

func (r *JDBCConnectionInjection) ID() string                      { return "GTSS-JAVA-005" }
func (r *JDBCConnectionInjection) Name() string                    { return "JDBCConnectionInjection" }
func (r *JDBCConnectionInjection) Description() string             { return "Detects JDBC connection strings built with user-controlled input, enabling connection string injection." }
func (r *JDBCConnectionInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *JDBCConnectionInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JDBCConnectionInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reJDBCConnConcat.FindString(line); loc != "" {
			matched = loc
			detail = "JDBC connection string built with concatenation"
		} else if loc := reJDBCDriverManager.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "JDBC connection with user-controlled variable"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JDBC Connection String Injection: " + detail,
				Description:   "JDBC connection strings built with user-controlled input can allow attackers to redirect database connections, inject connection properties, or trigger SSRF via database protocols.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a connection pool (HikariCP, C3P0) with hardcoded connection strings. Load connection parameters from environment variables or secure configuration, never from user input.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "jdbc", "connection-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-006: Java RMI Deserialization
// ---------------------------------------------------------------------------

type RMIDeserialization struct{}

func (r *RMIDeserialization) ID() string                      { return "GTSS-JAVA-006" }
func (r *RMIDeserialization) Name() string                    { return "RMIDeserialization" }
func (r *RMIDeserialization) Description() string             { return "Detects Java RMI usage which is vulnerable to deserialization attacks." }
func (r *RMIDeserialization) DefaultSeverity() rules.Severity { return rules.High }
func (r *RMIDeserialization) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *RMIDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasRMI := reRMIContext.MatchString(ctx.Content)
	if !hasRMI {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reRMINaming.FindString(line); loc != "" {
			matched = loc
			detail = "java.rmi.Naming bind/lookup exposes deserialization surface"
		} else if loc := reRMILocateRegistry.FindString(line); loc != "" {
			matched = loc
			detail = "RMI Registry exposes a deserialization attack surface"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Java RMI Deserialization: " + detail,
				Description:   "Java RMI uses Java serialization for all remote method calls. Any RMI endpoint is a deserialization sink that can be exploited for remote code execution using gadget chains (ysoserial).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid exposing RMI endpoints to untrusted networks. Use JEP 290 deserialization filters (ObjectInputFilter). Consider replacing RMI with REST/gRPC. Use JMX authentication if RMI is required.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "rmi", "deserialization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-007: Insecure SSL TrustManager
// ---------------------------------------------------------------------------

type InsecureSSLTrustManager struct{}

func (r *InsecureSSLTrustManager) ID() string                      { return "GTSS-JAVA-007" }
func (r *InsecureSSLTrustManager) Name() string                    { return "InsecureSSLTrustManager" }
func (r *InsecureSSLTrustManager) Description() string             { return "Detects X509TrustManager implementations that accept all certificates, disabling SSL/TLS validation." }
func (r *InsecureSSLTrustManager) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *InsecureSSLTrustManager) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *InsecureSSLTrustManager) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Quick bail: only scan files with TrustManager-related code
	if !strings.Contains(ctx.Content, "TrustManager") && !strings.Contains(ctx.Content, "checkServerTrusted") {
		return nil
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if reX509TrustManager.MatchString(line) {
			// Check if the implementation has empty checkServerTrusted
			context := surroundingContext(lines, i, 20)
			if reCheckServerTrustedEmpty.MatchString(context) || strings.Contains(context, "// trust all") || strings.Contains(context, "// accept all") {
				matched = strings.TrimSpace(line)
				detail = "X509TrustManager that accepts all certificates"
			}
		} else if reTrustAllCerts.MatchString(line) {
			matched = strings.TrimSpace(line)
			detail = "Anonymous X509TrustManager accepting all certificates"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure SSL: " + detail,
				Description:   "A custom X509TrustManager that accepts all certificates disables SSL/TLS certificate validation, enabling man-in-the-middle attacks. Any HTTPS connection using this trust manager provides no security.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use the default TrustManagerFactory with the system trust store. If custom validation is needed, implement proper certificate chain and hostname verification.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "ssl", "tls", "certificate"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-008: Unrestricted File Upload
// ---------------------------------------------------------------------------

type UnrestrictedFileUpload struct{}

func (r *UnrestrictedFileUpload) ID() string                      { return "GTSS-JAVA-008" }
func (r *UnrestrictedFileUpload) Name() string                    { return "UnrestrictedFileUpload" }
func (r *UnrestrictedFileUpload) Description() string             { return "Detects MultipartFile usage without file type validation, enabling arbitrary file upload." }
func (r *UnrestrictedFileUpload) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnrestrictedFileUpload) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *UnrestrictedFileUpload) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !reMultipartFile.MatchString(ctx.Content) {
		return nil
	}

	// Check if file type validation exists
	hasValidation := reFileExtCheck.MatchString(ctx.Content)
	if hasValidation {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reTransferTo.MatchString(line) || (reGetOriginalFilename.MatchString(line) && strings.Contains(ctx.Content, "new File")) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unrestricted file upload without validation",
				Description:   "MultipartFile is saved without validating file extension, content type, or file size. This allows uploading malicious files (web shells, executables) that could lead to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate file extension against an allowlist, check content type, enforce file size limits, and store files outside the web root with generated filenames. Scan uploads with antivirus.",
				CWEID:         "CWE-434",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "file-upload", "spring"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-009: Server-Side Template Injection (Java-specific)
// ---------------------------------------------------------------------------

type JavaSSTI struct{}

func (r *JavaSSTI) ID() string                      { return "GTSS-JAVA-009" }
func (r *JavaSSTI) Name() string                    { return "JavaSSTI" }
func (r *JavaSSTI) Description() string             { return "Detects Java server-side template injection via Velocity, Freemarker, and Thymeleaf with user-controlled templates." }
func (r *JavaSSTI) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JavaSSTI) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JavaSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reVelocityEvaluate.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reSSTIUserInput) {
				matched = loc
				detail = "Velocity.evaluate() with user-controlled template"
			}
		} else if loc := reFreemarkerNewTmpl.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reSSTIUserInput) {
				matched = loc
				detail = "Freemarker Template constructor with user-controlled input"
			}
		} else if loc := reThymeleafProcess.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reSSTIUserInput) {
				matched = loc
				detail = "Thymeleaf templateEngine.process with user-controlled template name"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Server-Side Template Injection: " + detail,
				Description:   "User-controlled input used as template content or template name in Velocity/Freemarker/Thymeleaf enables server-side template injection. Attackers can achieve remote code execution via template directives.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never use user input as template content. Use fixed template names and pass user data as template variables only. For Thymeleaf, use th:text instead of th:utext for user data.",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "ssti", "template-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-010: Improper Certificate/Hostname Validation
// ---------------------------------------------------------------------------

type ImproperCertValidation struct{}

func (r *ImproperCertValidation) ID() string                      { return "GTSS-JAVA-010" }
func (r *ImproperCertValidation) Name() string                    { return "ImproperCertValidation" }
func (r *ImproperCertValidation) Description() string             { return "Detects disabled or permissive hostname verification in HTTPS connections." }
func (r *ImproperCertValidation) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ImproperCertValidation) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *ImproperCertValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reHostnameVerifierAllowAll.FindString(line); loc != "" {
			matched = loc
			detail = "ALLOW_ALL_HOSTNAME_VERIFIER disables hostname checking"
		} else if loc := reHostnameVerifierNoOp.FindString(line); loc != "" {
			matched = loc
			detail = "NoopHostnameVerifier disables hostname checking"
		} else if reHostnameVerifierImpl.MatchString(line) {
			context := surroundingContext(lines, i, 10)
			if reHostnameVerifierReturn.MatchString(context) {
				matched = strings.TrimSpace(line)
				detail = "HostnameVerifier that always returns true"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Improper Certificate Validation: " + detail,
				Description:   "Disabling hostname verification allows man-in-the-middle attacks. An attacker with any valid certificate can intercept HTTPS traffic by impersonating the target server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use the default HostnameVerifier which validates the server's hostname against the certificate's Subject Alternative Names. Never use ALLOW_ALL or NoopHostnameVerifier in production.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "ssl", "hostname-verification"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-011: Hardcoded JDBC Credentials
// ---------------------------------------------------------------------------

type HardcodedJDBCCredentials struct{}

func (r *HardcodedJDBCCredentials) ID() string                      { return "GTSS-JAVA-011" }
func (r *HardcodedJDBCCredentials) Name() string                    { return "HardcodedJDBCCredentials" }
func (r *HardcodedJDBCCredentials) Description() string             { return "Detects hardcoded database credentials in JDBC connection strings or DataSource configuration." }
func (r *HardcodedJDBCCredentials) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedJDBCCredentials) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *HardcodedJDBCCredentials) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reJDBCPasswordInline.FindString(line); loc != "" {
			matched = loc
			detail = "JDBC connection with inline username and password"
		} else if loc := reJDBCURLPassword.FindString(line); loc != "" {
			matched = loc
			detail = "JDBC URL contains embedded password"
		} else if loc := reDataSourceSetPassword.FindString(line); loc != "" {
			matched = loc
			detail = "DataSource password set with hardcoded string"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded JDBC Credentials: " + detail,
				Description:   "Database credentials embedded in source code can be extracted by anyone with access to the code or binary. They are impossible to rotate without code changes and often leak into version control history.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Load database credentials from environment variables, a secrets manager (Vault, AWS Secrets Manager), or encrypted configuration. Use Spring's @Value with property files or JNDI DataSource.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "jdbc", "hardcoded-credentials"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-012: Regex DoS (ReDoS)
// ---------------------------------------------------------------------------

type RegexDoS struct{}

func (r *RegexDoS) ID() string                      { return "GTSS-JAVA-012" }
func (r *RegexDoS) Name() string                    { return "RegexDoS" }
func (r *RegexDoS) Description() string             { return "Detects Pattern.compile or String.matches with user-controlled regex input, enabling ReDoS attacks." }
func (r *RegexDoS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RegexDoS) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *RegexDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := rePatternCompileVar.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "Pattern.compile with user-controlled regex"
			}
		} else if loc := rePatternCompileConcat.FindString(line); loc != "" {
			matched = loc
			detail = "Pattern.compile with concatenated regex"
		} else if loc := reStringMatchesVar.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "String.matches with user-controlled pattern"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regex DoS (ReDoS): " + detail,
				Description:   "User-controlled regex patterns can contain catastrophic backtracking patterns (e.g., (a+)+ or (a|a)*) that cause exponential execution time, leading to denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never compile user-controlled strings as regex patterns. Use Pattern.quote() to escape user input used in patterns. Set timeouts or use RE2J for safe regex execution.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "regex", "dos"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-013: Information Exposure in Error Messages
// ---------------------------------------------------------------------------

type InfoExposureErrors struct{}

func (r *InfoExposureErrors) ID() string                      { return "GTSS-JAVA-013" }
func (r *InfoExposureErrors) Name() string                    { return "InfoExposureErrors" }
func (r *InfoExposureErrors) Description() string             { return "Detects stack traces and exception details exposed to HTTP responses." }
func (r *InfoExposureErrors) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InfoExposureErrors) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *InfoExposureErrors) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasResponseWriter := reResponseGetWriter.MatchString(ctx.Content)

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string
		confidence := "medium"

		if loc := rePrintStackTraceResp.FindString(line); loc != "" {
			matched = loc
			detail = "printStackTrace() output sent to HTTP response"
			confidence = "high"
		} else if loc := reExceptionToResponse.FindString(line); loc != "" {
			matched = loc
			detail = "Exception details written to HTTP response"
			confidence = "high"
		} else if rePrintStackTrace.MatchString(line) && hasResponseWriter {
			matched = rePrintStackTrace.FindString(line)
			detail = "printStackTrace() in code that handles HTTP responses"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Information Exposure: " + detail,
				Description:   "Stack traces and exception details sent to users reveal internal implementation details including class names, method names, library versions, and file paths. This information aids attackers in crafting targeted exploits.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Log stack traces server-side using a logging framework (SLF4J/Log4j). Return generic error messages to users. Use @ExceptionHandler or @ControllerAdvice for centralized error handling.",
				CWEID:         "CWE-209",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"java", "information-exposure", "error-handling"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-014: Insecure Random in Security Context
// ---------------------------------------------------------------------------

type JavaInsecureRandom struct{}

func (r *JavaInsecureRandom) ID() string                      { return "GTSS-JAVA-014" }
func (r *JavaInsecureRandom) Name() string                    { return "JavaInsecureRandom" }
func (r *JavaInsecureRandom) Description() string             { return "Detects java.util.Random or ThreadLocalRandom used for security-sensitive operations." }
func (r *JavaInsecureRandom) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaInsecureRandom) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JavaInsecureRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Skip if SecureRandom is already used
	if reJavaSecureRandom.MatchString(ctx.Content) {
		return nil
	}

	hasUtilRandom := reJavaRandomImport.MatchString(ctx.Content)

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reJavaUtilRandom.FindString(line); loc != "" {
			if reJavaSecurityContext.MatchString(line) || reJavaSecurityContext.MatchString(surroundingContext(lines, i, 5)) {
				matched = loc
				detail = "java.util.Random used in security context"
			}
		} else if hasUtilRandom {
			if loc := reThreadLocalRandom.FindString(line); loc != "" {
				if reJavaSecurityContext.MatchString(line) || reJavaSecurityContext.MatchString(surroundingContext(lines, i, 5)) {
					matched = loc
					detail = "ThreadLocalRandom used in security context"
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure Random: " + detail,
				Description:   "java.util.Random and ThreadLocalRandom use a linear congruential generator that is predictable. Their output can be reverse-engineered from a small number of observed values.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use java.security.SecureRandom for tokens, session IDs, passwords, nonces, OTPs, CSRF tokens, and any security-sensitive random values.",
				CWEID:         "CWE-330",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "random", "crypto"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-015: Missing HttpOnly/Secure on Cookies
// ---------------------------------------------------------------------------

type JavaInsecureCookies struct{}

func (r *JavaInsecureCookies) ID() string                      { return "GTSS-JAVA-015" }
func (r *JavaInsecureCookies) Name() string                    { return "JavaInsecureCookies" }
func (r *JavaInsecureCookies) Description() string             { return "Detects cookies created without HttpOnly or Secure flags, especially for sensitive cookies." }
func (r *JavaInsecureCookies) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaInsecureCookies) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JavaInsecureCookies) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !reNewCookie.MatchString(ctx.Content) {
		return nil
	}

	hasHttpOnly := reSetHttpOnly.MatchString(ctx.Content)
	hasSecure := reSetSecure.MatchString(ctx.Content)

	if hasHttpOnly && hasSecure {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if !reNewCookie.MatchString(line) {
			continue
		}

		// Check if cookie name suggests sensitivity
		isSensitive := reCookieSensitiveName.MatchString(line) || reCookieSensitiveName.MatchString(surroundingContext(lines, i, 5))

		var missing []string
		if !hasHttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if !hasSecure {
			missing = append(missing, "Secure")
		}

		if len(missing) > 0 {
			confidence := "medium"
			if isSensitive {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Cookie missing " + strings.Join(missing, " and ") + " flag",
				Description:   "Cookies created without HttpOnly flag are accessible to JavaScript (XSS cookie theft). Without Secure flag, cookies are sent over unencrypted HTTP connections.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set cookie.setHttpOnly(true) and cookie.setSecure(true). Consider using SameSite=Strict or Lax for CSRF protection.",
				CWEID:         "CWE-1004",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"java", "cookie", "security-config"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-016: SSRF via URL class
// ---------------------------------------------------------------------------

type JavaSSRF struct{}

func (r *JavaSSRF) ID() string                      { return "GTSS-JAVA-016" }
func (r *JavaSSRF) Name() string                    { return "JavaSSRF" }
func (r *JavaSSRF) Description() string             { return "Detects SSRF vulnerabilities via Java URL/URI classes with user-controlled input." }
func (r *JavaSSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaSSRF) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JavaSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reNewURLConcat.FindString(line); loc != "" {
			matched = loc
			detail = "new URL() with concatenated user input"
		} else if loc := reNewURL.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "new URL() with user-controlled variable"
			}
		} else if loc := reURICreate.FindString(line); loc != "" {
			if hasNearbyPattern(lines, i, reReqParam) {
				matched = loc
				detail = "URI.create() with user-controlled variable"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SSRF: " + detail,
				Description:   "Creating URL/URI objects from user-controlled input and opening connections enables Server-Side Request Forgery. Attackers can access internal services, cloud metadata endpoints (169.254.169.254), or perform port scanning.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate URLs against an allowlist of permitted domains/IPs. Block private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x). Use a URL parser to check the scheme and host before connecting.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-Server-Side Request Forgery",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "ssrf", "url"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-017: Zip Slip
// ---------------------------------------------------------------------------

type ZipSlip struct{}

func (r *ZipSlip) ID() string                      { return "GTSS-JAVA-017" }
func (r *ZipSlip) Name() string                    { return "ZipSlip" }
func (r *ZipSlip) Description() string             { return "Detects Zip Slip vulnerability where archive entries are extracted without validating the path." }
func (r *ZipSlip) DefaultSeverity() rules.Severity { return rules.High }
func (r *ZipSlip) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *ZipSlip) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !reZipInputStream.MatchString(ctx.Content) {
		return nil
	}

	// Check if path validation exists
	hasPathValidation := rePathNormalize.MatchString(ctx.Content)
	if hasPathValidation {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reZipEntryGetName.MatchString(line) && (strings.Contains(ctx.Content, "new File") || strings.Contains(ctx.Content, "Paths.get")) {
			// Check nearby for file creation
			context := surroundingContext(lines, i, 10)
			if strings.Contains(context, "new File") || strings.Contains(context, "Paths.get") || strings.Contains(context, "FileOutputStream") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Zip Slip: archive entry extracted without path validation",
					Description:   "ZipEntry.getName() can contain path traversal sequences (../../). Without validation, extracting the entry creates files outside the intended directory, potentially overwriting critical system files or application code.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Validate that the resolved path starts with the target directory: File destFile = new File(destDir, entry.getName()); if (!destFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())) throw new Exception(\"Zip Slip\");",
					CWEID:         "CWE-22",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"java", "zip-slip", "path-traversal"},
				})
				break // one finding per file is sufficient
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-018: Thread Safety Issues (SimpleDateFormat)
// ---------------------------------------------------------------------------

type ThreadSafetyIssues struct{}

func (r *ThreadSafetyIssues) ID() string                      { return "GTSS-JAVA-018" }
func (r *ThreadSafetyIssues) Name() string                    { return "ThreadSafetyIssues" }
func (r *ThreadSafetyIssues) Description() string             { return "Detects thread-unsafe SimpleDateFormat shared across threads." }
func (r *ThreadSafetyIssues) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ThreadSafetyIssues) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *ThreadSafetyIssues) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if thread-safe alternatives are used
	if reDateTimeFormatter.MatchString(ctx.Content) || reThreadLocal.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var detail string

		if loc := reStaticSimpleDateFormat.FindString(line); loc != "" {
			// Check if synchronized is used in the file
			if !reSynchronized.MatchString(ctx.Content) {
				matched = loc
				detail = "static SimpleDateFormat shared across threads without synchronization"
			}
		} else if loc := reSimpleDateFormatField.FindString(line); loc != "" {
			// Only flag if the class appears to be a singleton or shared (has @Component, @Service, @Bean, etc.)
			if strings.Contains(ctx.Content, "@Component") || strings.Contains(ctx.Content, "@Service") ||
				strings.Contains(ctx.Content, "@Repository") || strings.Contains(ctx.Content, "@Controller") ||
				strings.Contains(ctx.Content, "@RestController") || strings.Contains(ctx.Content, "@Bean") ||
				strings.Contains(ctx.Content, "@Singleton") {
				matched = loc
				detail = "SimpleDateFormat instance field in shared bean (not thread-safe)"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Thread Safety: " + detail,
				Description:   "SimpleDateFormat is not thread-safe. When shared across threads (static field or Spring bean instance field), concurrent access causes corrupted date parsing/formatting, producing silent data corruption or ArrayIndexOutOfBoundsException.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use java.time.format.DateTimeFormatter (thread-safe, immutable) from Java 8+. If SimpleDateFormat is required, use ThreadLocal<SimpleDateFormat> or create new instances per use.",
				CWEID:         "CWE-362",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "thread-safety", "concurrency"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&JNDIInjection{})
	rules.Register(&ELInjection{})
	rules.Register(&SpELInjection{})
	rules.Register(&HQLInjection{})
	rules.Register(&JDBCConnectionInjection{})
	rules.Register(&RMIDeserialization{})
	rules.Register(&InsecureSSLTrustManager{})
	rules.Register(&UnrestrictedFileUpload{})
	rules.Register(&JavaSSTI{})
	rules.Register(&ImproperCertValidation{})
	rules.Register(&HardcodedJDBCCredentials{})
	rules.Register(&RegexDoS{})
	rules.Register(&InfoExposureErrors{})
	rules.Register(&JavaInsecureRandom{})
	rules.Register(&JavaInsecureCookies{})
	rules.Register(&JavaSSRF{})
	rules.Register(&ZipSlip{})
	rules.Register(&ThreadSafetyIssues{})
}
