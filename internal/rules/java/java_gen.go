package java

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for BATOU-JAVA-031 .. BATOU-JAVA-040
// ---------------------------------------------------------------------------

// JAVA-031: Spring Actuator exposed
var (
	reActuatorExposeProp = regexp.MustCompile(`management\.endpoints\.web\.exposure\.include\s*=\s*\*`)
	reActuatorExposeYAML = regexp.MustCompile(`include\s*:\s*["']\*["']`)
	reActuatorContext    = regexp.MustCompile(`(?i)management|actuator|endpoints`)
)

// JAVA-032: SpEL injection via parser
var (
	reSpELParserParse   = regexp.MustCompile(`SpelExpressionParser\s*\(\s*\)\s*\.\s*parseExpression\s*\(`)
	reSpELUserInput     = regexp.MustCompile(`(?i)(?:request|param|input|getParameter|getHeader|getQueryString|getPathInfo)`)
)

// JAVA-033: Spring annotation bypass on generics
var (
	reSpringSecAnnotation = regexp.MustCompile(`@(?:PreAuthorize|Secured|RolesAllowed)\s*\(`)
	reGenericInterface    = regexp.MustCompile(`(?:interface\s+\w+\s*<|<\s*[A-Z]\w*\s*(?:extends|super))`)
)

// JAVA-034: ObjectInputStream without filter
var (
	reNewObjectInputStream = regexp.MustCompile(`new\s+ObjectInputStream\s*\(`)
	reObjectInputFilter    = regexp.MustCompile(`setObjectInputFilter`)
)

// JAVA-035: Jackson polymorphic deser
var (
	reJacksonTypeInfo      = regexp.MustCompile(`@JsonTypeInfo\s*\([^)]*Id\s*\.\s*CLASS`)
	reJacksonDefaultTyping = regexp.MustCompile(`enableDefaultTyping\s*\(`)
)

// JAVA-036: gRPC without TLS
var (
	reGRPCServerBuilder     = regexp.MustCompile(`ServerBuilder\s*\.\s*forPort\s*\(`)
	reGRPCTransportSecurity = regexp.MustCompile(`useTransportSecurity`)
)

// JAVA-037: Fail-open exception in auth
var (
	reFailOpenCatch    = regexp.MustCompile(`catch\s*\(`)
	reFailOpenReturn   = regexp.MustCompile(`(?i)return\s+true|grant|allow|permit|authenticated\s*=\s*true`)
	reAuthContext      = regexp.MustCompile(`(?i)(?:auth|login|verify|validate|check(?:Password|Credential|Access)|isAllowed|isAuthorized|canAccess|hasRole|hasPermission)`)
)

// JAVA-038: Spring STOMP without auth
var (
	reStompEndpoint       = regexp.MustCompile(`registerStompEndpoints\s*\(`)
	reStompInboundChannel = regexp.MustCompile(`configureClientInboundChannel`)
)

// JAVA-039: Weak cipher strings
var (
	reWeakCipher = regexp.MustCompile(`Cipher\s*\.\s*getInstance\s*\(\s*["'](?:DES|DESede|AES/ECB|RC4|RC2|Blowfish|ARCFOUR)`)
)

// JAVA-040: Missing Content-Type on upload
var (
	reMultipartFileGen   = regexp.MustCompile(`MultipartFile\b`)
	reGetContentTypeGen  = regexp.MustCompile(`getContentType`)
)

// ---------------------------------------------------------------------------
// BATOU-JAVA-031: Spring Actuator Exposed
// ---------------------------------------------------------------------------

type SpringActuatorExposed struct{}

func (r *SpringActuatorExposed) ID() string                      { return "BATOU-JAVA-031" }
func (r *SpringActuatorExposed) Name() string                    { return "JavaSpringActuatorExposed" }
func (r *SpringActuatorExposed) Description() string             { return "Detects Spring Actuator endpoints exposed to all via wildcard include." }
func (r *SpringActuatorExposed) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SpringActuatorExposed) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *SpringActuatorExposed) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool

		if reActuatorExposeProp.MatchString(line) {
			matched = true
		} else if reActuatorExposeYAML.MatchString(line) && hasNearbyPattern(lines, i, reActuatorContext) {
			matched = true
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring Actuator endpoints exposed with wildcard",
				Description:   "Exposing all Spring Actuator endpoints (include=*) reveals sensitive operational data such as environment variables, heap dumps, thread dumps, and beans. Attackers can use /env to read secrets, /heapdump to extract credentials from memory, or /shutdown to cause DoS.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Only expose specific endpoints needed for monitoring: management.endpoints.web.exposure.include=health,info,metrics. Protect sensitive endpoints with Spring Security authentication.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "spring", "actuator", "misconfiguration"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-032: SpEL Injection via Parser
// ---------------------------------------------------------------------------

type SpELParserInjection struct{}

func (r *SpELParserInjection) ID() string                      { return "BATOU-JAVA-032" }
func (r *SpELParserInjection) Name() string                    { return "JavaSpELParserInjection" }
func (r *SpELParserInjection) Description() string             { return "Detects SpelExpressionParser.parseExpression with user input, enabling SpEL injection." }
func (r *SpELParserInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SpELParserInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *SpELParserInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reSpELParserParse.MatchString(line) {
			continue
		}
		if reSpELUserInput.MatchString(line) || hasNearbyPattern(lines, i, reSpELUserInput) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SpEL injection via SpelExpressionParser with user input",
				Description:   "SpelExpressionParser().parseExpression() with user-controlled input allows an attacker to execute arbitrary code via Spring Expression Language. SpEL can access any Java class, invoke methods, read/write files, and execute OS commands (e.g., T(Runtime).getRuntime().exec()).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use SimpleEvaluationContext instead of StandardEvaluationContext to restrict SpEL capabilities. Never pass user input to parseExpression(). If dynamic expressions are needed, use a strict allowlist of permitted expression patterns.",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "spring", "spel", "injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-033: Spring Annotation Bypass on Generics
// ---------------------------------------------------------------------------

type SpringAnnotationGenericBypass struct{}

func (r *SpringAnnotationGenericBypass) ID() string                      { return "BATOU-JAVA-033" }
func (r *SpringAnnotationGenericBypass) Name() string                    { return "JavaSpringAnnotationGenericBypass" }
func (r *SpringAnnotationGenericBypass) Description() string             { return "Detects @PreAuthorize/@Secured on generic interfaces where type erasure may bypass checks." }
func (r *SpringAnnotationGenericBypass) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SpringAnnotationGenericBypass) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *SpringAnnotationGenericBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reSpringSecAnnotation.MatchString(line) {
			continue
		}
		if hasNearbyPattern(lines, i, reGenericInterface) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring security annotation on generic interface may be bypassed",
				Description:   "Placing @PreAuthorize, @Secured, or @RolesAllowed on a generic interface method may not be enforced on the implementing class due to Java type erasure and how Spring AOP proxies handle bridge methods. The security check can be silently skipped.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Place security annotations on the concrete implementing class method instead of the generic interface. Use @EnableGlobalMethodSecurity(prePostEnabled = true) and verify annotations are applied at the implementation level.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"java", "spring", "authorization", "generics"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-034: ObjectInputStream Without Filter
// ---------------------------------------------------------------------------

type ObjectInputStreamNoFilter struct{}

func (r *ObjectInputStreamNoFilter) ID() string                      { return "BATOU-JAVA-034" }
func (r *ObjectInputStreamNoFilter) Name() string                    { return "JavaObjectInputStreamNoFilter" }
func (r *ObjectInputStreamNoFilter) Description() string             { return "Detects new ObjectInputStream without setObjectInputFilter, enabling unrestricted deserialization." }
func (r *ObjectInputStreamNoFilter) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ObjectInputStreamNoFilter) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *ObjectInputStreamNoFilter) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	// If setObjectInputFilter appears anywhere in the file, skip (developer is likely aware)
	if reObjectInputFilter.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reNewObjectInputStream.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "ObjectInputStream without deserialization filter",
			Description:   "Creating an ObjectInputStream without calling setObjectInputFilter() (Java 9+) allows unrestricted deserialization of arbitrary classes. Attackers can craft serialized payloads that chain gadget classes (e.g., Commons Collections, Spring, Groovy) to achieve remote code execution.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Call setObjectInputFilter() to restrict allowed classes immediately after creating the ObjectInputStream. Use an allowlist approach: ois.setObjectInputFilter(info -> info.serialClass() == AllowedClass.class ? Status.ALLOWED : Status.REJECTED). Consider alternatives like JSON or Protocol Buffers.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"java", "deserialization", "objectinputstream", "rce"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-035: Jackson Polymorphic Deserialization
// ---------------------------------------------------------------------------

type JacksonPolymorphicDeser struct{}

func (r *JacksonPolymorphicDeser) ID() string                      { return "BATOU-JAVA-035" }
func (r *JacksonPolymorphicDeser) Name() string                    { return "JavaJacksonPolymorphicDeser" }
func (r *JacksonPolymorphicDeser) Description() string             { return "Detects Jackson @JsonTypeInfo(Id.CLASS) or enableDefaultTyping which allow polymorphic deserialization attacks." }
func (r *JacksonPolymorphicDeser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JacksonPolymorphicDeser) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *JacksonPolymorphicDeser) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
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

		if reJacksonTypeInfo.MatchString(line) {
			matched = true
			title = "Jackson @JsonTypeInfo with Id.CLASS enables polymorphic deserialization"
			desc = "@JsonTypeInfo(use = Id.CLASS) allows an attacker to specify arbitrary Java classes in JSON input. Combined with gadget classes on the classpath, this leads to remote code execution. CVE-2017-7525 and many subsequent CVEs exploit this pattern."
		} else if reJacksonDefaultTyping.MatchString(line) {
			matched = true
			title = "Jackson enableDefaultTyping enables polymorphic deserialization globally"
			desc = "ObjectMapper.enableDefaultTyping() enables polymorphic type handling for all types, allowing attackers to instantiate arbitrary classes via JSON. This is the most dangerous Jackson configuration and has been deprecated."
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
				Suggestion:    "Use @JsonTypeInfo(use = Id.NAME) with @JsonSubTypes to restrict allowed subtypes. Replace enableDefaultTyping() with activateDefaultTyping(ptv, DefaultTyping.NON_FINAL, As.PROPERTY) using a PolymorphicTypeValidator. Update Jackson to the latest version.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "jackson", "deserialization", "polymorphic", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-036: gRPC Without TLS
// ---------------------------------------------------------------------------

type GRPCWithoutTLS struct{}

func (r *GRPCWithoutTLS) ID() string                      { return "BATOU-JAVA-036" }
func (r *GRPCWithoutTLS) Name() string                    { return "JavaGRPCWithoutTLS" }
func (r *GRPCWithoutTLS) Description() string             { return "Detects gRPC ServerBuilder.forPort without useTransportSecurity, sending data in plaintext." }
func (r *GRPCWithoutTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r *GRPCWithoutTLS) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *GRPCWithoutTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	// If useTransportSecurity appears in the file, likely configured
	if reGRPCTransportSecurity.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reGRPCServerBuilder.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "gRPC server without TLS (plaintext transport)",
			Description:   "ServerBuilder.forPort() without useTransportSecurity() creates a gRPC server that communicates in plaintext. All RPC data including authentication tokens, sensitive payloads, and metadata can be intercepted by network attackers.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Add .useTransportSecurity(certChainFile, privateKeyFile) to the ServerBuilder chain. For development, use .useTransportSecurity() with self-signed certificates rather than disabling TLS entirely.",
			CWEID:         "CWE-319",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"java", "grpc", "tls", "plaintext"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-037: Fail-Open Exception in Auth
// ---------------------------------------------------------------------------

type FailOpenAuthException struct{}

func (r *FailOpenAuthException) ID() string                      { return "BATOU-JAVA-037" }
func (r *FailOpenAuthException) Name() string                    { return "JavaFailOpenAuthException" }
func (r *FailOpenAuthException) Description() string             { return "Detects catch blocks that return true/grant/allow in authentication/authorization context (fail-open)." }
func (r *FailOpenAuthException) DefaultSeverity() rules.Severity { return rules.High }
func (r *FailOpenAuthException) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *FailOpenAuthException) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	// Only scan files that appear to be in an auth context
	if !reAuthContext.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	inCatch := false
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reFailOpenCatch.MatchString(line) {
			inCatch = true
			continue
		}
		if inCatch {
			if strings.Contains(line, "}") {
				inCatch = false
				continue
			}
			if reFailOpenReturn.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Fail-open exception handling in authentication/authorization",
					Description:   "A catch block in an authentication or authorization context returns true, grants access, or sets an authenticated flag. This is a fail-open pattern: if any exception occurs during the security check (database error, timeout, null pointer), access is granted instead of denied.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "In security-sensitive catch blocks, always deny access by default (return false / throw AccessDeniedException). Log the exception for investigation. Follow the fail-closed principle: if the check cannot be completed, deny access.",
					CWEID:         "CWE-755",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"java", "auth", "fail-open", "exception"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-038: Spring STOMP Without Auth
// ---------------------------------------------------------------------------

type SpringSTOMPNoAuth struct{}

func (r *SpringSTOMPNoAuth) ID() string                      { return "BATOU-JAVA-038" }
func (r *SpringSTOMPNoAuth) Name() string                    { return "JavaSpringSTOMPNoAuth" }
func (r *SpringSTOMPNoAuth) Description() string             { return "Detects Spring STOMP endpoints registered without configureClientInboundChannel for authentication." }
func (r *SpringSTOMPNoAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringSTOMPNoAuth) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *SpringSTOMPNoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	if !reStompEndpoint.MatchString(ctx.Content) {
		return nil
	}
	// If configureClientInboundChannel is also present, auth is likely set up
	if reStompInboundChannel.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reStompEndpoint.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Spring STOMP WebSocket endpoint without authentication",
			Description:   "registerStompEndpoints() is called without a corresponding configureClientInboundChannel() override to enforce authentication on WebSocket messages. Unauthenticated users can connect and send/receive messages on any subscribed topic, potentially accessing sensitive data or triggering actions.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Override configureClientInboundChannel() and add a ChannelInterceptor that validates the user's authentication token on CONNECT and SEND frames. Use @MessageMapping with @AuthenticationPrincipal to enforce per-message authorization.",
			CWEID:         "CWE-306",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"java", "spring", "stomp", "websocket", "authentication"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-039: Weak Cipher Strings
// ---------------------------------------------------------------------------

type WeakCipherInstance struct{}

func (r *WeakCipherInstance) ID() string                      { return "BATOU-JAVA-039" }
func (r *WeakCipherInstance) Name() string                    { return "JavaWeakCipherInstance" }
func (r *WeakCipherInstance) Description() string             { return "Detects Cipher.getInstance with weak algorithms (DES, AES/ECB, RC4, Blowfish)." }
func (r *WeakCipherInstance) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WeakCipherInstance) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *WeakCipherInstance) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reWeakCipher.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Weak cipher algorithm in Cipher.getInstance()",
				Description:   "Cipher.getInstance() is called with a weak or deprecated algorithm. DES has a 56-bit key (brute-forceable). AES/ECB leaks patterns in ciphertext. RC4 has known biases. Blowfish has a 64-bit block size vulnerable to birthday attacks (Sweet32).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use AES with a secure mode: Cipher.getInstance(\"AES/GCM/NoPadding\") for authenticated encryption, or \"AES/CBC/PKCS5Padding\" with a separate HMAC. Use a 256-bit key with SecureRandom for key generation.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"java", "crypto", "cipher", "weak-algorithm"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JAVA-040: Missing Content-Type Check on Upload
// ---------------------------------------------------------------------------

type MissingUploadContentType struct{}

func (r *MissingUploadContentType) ID() string                      { return "BATOU-JAVA-040" }
func (r *MissingUploadContentType) Name() string                    { return "JavaMissingUploadContentType" }
func (r *MissingUploadContentType) Description() string             { return "Detects MultipartFile handling without getContentType validation, allowing arbitrary file upload." }
func (r *MissingUploadContentType) DefaultSeverity() rules.Severity { return rules.High }
func (r *MissingUploadContentType) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *MissingUploadContentType) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	if !reMultipartFileGen.MatchString(ctx.Content) {
		return nil
	}
	// If getContentType appears in the file, validation is likely present
	if reGetContentTypeGen.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reMultipartFileGen.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "MultipartFile without Content-Type validation",
			Description:   "A MultipartFile parameter is used without calling getContentType() to validate the uploaded file type. Without content-type validation, attackers can upload executable files (JSP, PHP, EXE) that may be served or executed by the application server.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Validate the Content-Type of uploaded files: file.getContentType() must match an allowlist of permitted MIME types. Also validate the file extension and use a random filename for storage. Never store uploads in a web-accessible directory.",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"java", "upload", "content-type", "multipart"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&SpringActuatorExposed{})
	rules.Register(&SpELParserInjection{})
	rules.Register(&SpringAnnotationGenericBypass{})
	rules.Register(&ObjectInputStreamNoFilter{})
	rules.Register(&JacksonPolymorphicDeser{})
	rules.Register(&GRPCWithoutTLS{})
	rules.Register(&FailOpenAuthException{})
	rules.Register(&SpringSTOMPNoAuth{})
	rules.Register(&WeakCipherInstance{})
	rules.Register(&MissingUploadContentType{})
}
