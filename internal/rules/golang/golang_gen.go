package golang

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Generated patterns for GO-027 through GO-036
// ---------------------------------------------------------------------------

// GO-027: gRPC server without TLS
var (
	reGenGRPCNewServer = regexp.MustCompile(`grpc\.NewServer\s*\(`)
	reGenGRPCCreds     = regexp.MustCompile(`grpc\.Creds\s*\(`)
)

// GO-028: Missing context timeout on HTTP calls
var (
	reGenHTTPDefaultCall = regexp.MustCompile(`\bhttp\.(?:Get|Post|Do)\s*\(`)
	reGenContextTimeout  = regexp.MustCompile(`context\.WithTimeout|context\.WithDeadline|http\.NewRequestWithContext`)
)

// GO-029: LLM prompt injection
var (
	reGenLLMCall     = regexp.MustCompile(`(?i)(?:openai|anthropic|llm|completion|chat\.Create|CreateChatCompletion|CreateCompletion|Messages\.Create)\s*\(`)
	reGenLLMConcat   = regexp.MustCompile(`(?:fmt\.Sprintf|"\s*\+\s*[a-zA-Z_]|\+\s*")\s*.*(?i)(?:prompt|message|content|system|user)`)
	reGenLLMUserInput = regexp.MustCompile(`(?:r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)|(?:c|ctx)\.(?:Query|Param|QueryParam|FormValue))\s*\(`)
)

// GO-030: Unbounded goroutine spawning in loops
var (
	reGenForLoop     = regexp.MustCompile(`\bfor\s`)
	reGenGoStatement = regexp.MustCompile(`\bgo\s+(?:func\s*\(|[a-zA-Z_]\w*\s*\()`)
)

// GO-031: Unsafe reflect with user input
var (
	reGenReflectCall   = regexp.MustCompile(`reflect\.(?:ValueOf|New|TypeOf)\s*\(`)
	reGenReflectInput  = regexp.MustCompile(`(?:r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)|(?:c|ctx)\.(?:Query|Param|QueryParam|FormValue))\s*\(`)
)

// GO-032: fmt.Sprintf SQL injection
var (
	reGenSprintfSQL = regexp.MustCompile(`fmt\.Sprintf\s*\(\s*"[^"]*(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|UNION)\b`)
	reGenQueryExec  = regexp.MustCompile(`\.(?:Query|QueryRow|Exec|ExecContext|QueryContext|QueryRowContext|Prepare)\s*\(`)
)

// GO-033: Container mount propagation
var (
	reGenSyscallMount = regexp.MustCompile(`syscall\.Mount\s*\(`)
	reGenMountShared  = regexp.MustCompile(`(?:MS_SHARED|MS_SLAVE|syscall\.MS_SHARED|syscall\.MS_SLAVE)`)
)

// GO-034: Deprecated RSA key size
var (
	reGenRSAKeygen = regexp.MustCompile(`rsa\.GenerateKey\s*\(\s*\w+\s*,\s*(?:1024|2048)\s*\)`)
)

// GO-035: Fail-open error handling
var (
	reGenFailOpen    = regexp.MustCompile(`if\s+err\s*!=\s*nil\s*\{\s*(?:return\s+nil|return\s+false|return\s+""|continue)`)
	reGenAuthContext = regexp.MustCompile(`(?i)(?:auth|login|verify|validate|check[Pp]assword|check[Tt]oken|check[Ss]ession|authenticate|authorize|permission|access[Cc]ontrol)`)
)

// GO-036: Supply chain replace directive
var (
	reGenGoModReplace = regexp.MustCompile(`(?m)^\s*replace\s+\S+\s+=>\s+\.\.?/`)
)

func init() {
	rules.Register(&GRPCServerNoTLS{})
	rules.Register(&MissingContextTimeout{})
	rules.Register(&LLMPromptInjection{})
	rules.Register(&UnboundedGoroutineLoop{})
	rules.Register(&UnsafeReflectInput{})
	rules.Register(&SprintfSQLInjection{})
	rules.Register(&ContainerMountPropagation{})
	rules.Register(&DeprecatedRSAKeySize{})
	rules.Register(&FailOpenErrorHandling{})
	rules.Register(&SupplyChainReplace{})
}

// --- GO-027: gRPC server without TLS ---

type GRPCServerNoTLS struct{}

func (r *GRPCServerNoTLS) ID() string                      { return "BATOU-GO-027" }
func (r *GRPCServerNoTLS) Name() string                    { return "GRPCServerNoTLS" }
func (r *GRPCServerNoTLS) Description() string             { return "Detects gRPC server creation without TLS credentials, exposing traffic to interception." }
func (r *GRPCServerNoTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r *GRPCServerNoTLS) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *GRPCServerNoTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if TLS credentials are configured in the file
	if reGenGRPCCreds.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenGRPCNewServer.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "gRPC server without TLS credentials",
				Description:   "grpc.NewServer() without grpc.Creds() starts a plaintext gRPC server. All RPCs including authentication tokens are transmitted unencrypted and vulnerable to interception.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add TLS credentials: grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig))). Use credentials.NewServerTLSFromFile() for file-based certs.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "grpc", "tls", "plaintext"},
			})
		}
	}
	return findings
}

// --- GO-028: Missing context timeout ---

type MissingContextTimeout struct{}

func (r *MissingContextTimeout) ID() string                      { return "BATOU-GO-028" }
func (r *MissingContextTimeout) Name() string                    { return "MissingContextTimeout" }
func (r *MissingContextTimeout) Description() string             { return "Detects HTTP calls (http.Get/Post/Do) without context.WithTimeout, risking indefinite hangs." }
func (r *MissingContextTimeout) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingContextTimeout) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *MissingContextTimeout) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if context timeout is used anywhere in the file
	if reGenContextTimeout.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenHTTPDefaultCall.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "HTTP call without context timeout",
				Description:   "http.Get/Post/Do without context.WithTimeout uses the default client with no timeout, which can hang indefinitely if the remote server is slow or unresponsive, leading to resource exhaustion.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use http.NewRequestWithContext with context.WithTimeout: ctx, cancel := context.WithTimeout(ctx, 10*time.Second); defer cancel(); req, _ := http.NewRequestWithContext(ctx, ...)",
				CWEID:         "CWE-400",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "http", "timeout", "context"},
			})
		}
	}
	return findings
}

// --- GO-029: LLM prompt injection ---

type LLMPromptInjection struct{}

func (r *LLMPromptInjection) ID() string                      { return "BATOU-GO-029" }
func (r *LLMPromptInjection) Name() string                    { return "LLMPromptInjection" }
func (r *LLMPromptInjection) Description() string             { return "Detects user input concatenated into LLM/AI API calls, enabling prompt injection attacks." }
func (r *LLMPromptInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *LLMPromptInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *LLMPromptInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files that reference LLM/AI APIs
	if !reGenLLMCall.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenLLMConcat.MatchString(line) && hasNearbyUserInput(lines, i, 10) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LLM prompt injection via user input concatenation",
				Description:   "User input concatenated directly into LLM prompts enables prompt injection. An attacker can override system instructions, extract training data, or manipulate model behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Separate system and user messages using the API's role-based format. Apply input validation, length limits, and output filtering. Never concatenate user input into system prompts.",
				CWEID:         "CWE-77",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "llm", "prompt-injection", "ai"},
			})
		}
	}
	return findings
}

// --- GO-030: Unbounded goroutine spawning in loops ---

type UnboundedGoroutineLoop struct{}

func (r *UnboundedGoroutineLoop) ID() string                      { return "BATOU-GO-030" }
func (r *UnboundedGoroutineLoop) Name() string                    { return "UnboundedGoroutineLoop" }
func (r *UnboundedGoroutineLoop) Description() string             { return "Detects go func() or go calls inside for loops without bounded concurrency, risking goroutine exhaustion." }
func (r *UnboundedGoroutineLoop) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UnboundedGoroutineLoop) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *UnboundedGoroutineLoop) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if bounded concurrency patterns are present
	if reSemaphore.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	inForLoop := false
	braceDepth := 0
	forBraceDepth := 0

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		// Track brace depth
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		if reGenForLoop.MatchString(line) {
			inForLoop = true
			forBraceDepth = braceDepth
		}

		if inForLoop && braceDepth < forBraceDepth {
			inForLoop = false
		}

		if inForLoop && reGenGoStatement.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unbounded goroutine spawning in loop",
				Description:   "Launching goroutines in a loop without concurrency limits can exhaust memory and CPU. Each goroutine consumes at least 2KB of stack, and millions of goroutines can crash the process.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use a worker pool pattern with a semaphore channel (make(chan struct{}, maxWorkers)), errgroup with SetLimit(), or a pool library like ants/tunny.",
				CWEID:         "CWE-770",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "goroutine", "loop", "resource-exhaustion"},
			})
		}
	}
	return findings
}

// --- GO-031: Unsafe reflect with user input ---

type UnsafeReflectInput struct{}

func (r *UnsafeReflectInput) ID() string                      { return "BATOU-GO-031" }
func (r *UnsafeReflectInput) Name() string                    { return "UnsafeReflectInput" }
func (r *UnsafeReflectInput) Description() string             { return "Detects reflect.ValueOf/reflect.New with user-controlled request parameters nearby, enabling unsafe type manipulation." }
func (r *UnsafeReflectInput) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeReflectInput) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *UnsafeReflectInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenReflectCall.MatchString(line) && hasNearbyUserInput(lines, i, 10) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe reflect usage with user-controlled input",
				Description:   "reflect.ValueOf/New with user-controlled data can enable unsafe type instantiation, method invocation, or field manipulation that bypasses compile-time type safety.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use a type registry (map[string]reflect.Type) with an allowlist of safe types instead of reflecting arbitrary user input. Validate and sanitize input before reflection.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "reflect", "unsafe", "user-input"},
			})
		}
	}
	return findings
}

// --- GO-032: fmt.Sprintf SQL injection ---

type SprintfSQLInjection struct{}

func (r *SprintfSQLInjection) ID() string                      { return "BATOU-GO-032" }
func (r *SprintfSQLInjection) Name() string                    { return "SprintfSQLInjection" }
func (r *SprintfSQLInjection) Description() string             { return "Detects fmt.Sprintf with SQL keywords passed to query/exec methods, enabling SQL injection." }
func (r *SprintfSQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SprintfSQLInjection) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *SprintfSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenSprintfSQL.MatchString(line) {
			// Check if result is passed to a query method nearby
			context := surroundingContext(lines, i, 5)
			if reGenQueryExec.MatchString(context) || reGenQueryExec.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SQL injection via fmt.Sprintf in query",
					Description:   "Building SQL queries with fmt.Sprintf and passing them to database query/exec methods enables SQL injection. The %s and %v verbs insert values without escaping.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = $1\", userID). Never use fmt.Sprintf to build SQL strings.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"go", "sql-injection", "sprintf"},
				})
			}
		}
	}
	return findings
}

// --- GO-033: Container mount propagation ---

type ContainerMountPropagation struct{}

func (r *ContainerMountPropagation) ID() string                      { return "BATOU-GO-033" }
func (r *ContainerMountPropagation) Name() string                    { return "ContainerMountPropagation" }
func (r *ContainerMountPropagation) Description() string             { return "Detects syscall.Mount with MS_SHARED/MS_SLAVE flags, which can expose host filesystem to containers." }
func (r *ContainerMountPropagation) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ContainerMountPropagation) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *ContainerMountPropagation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenSyscallMount.MatchString(line) && reGenMountShared.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Container mount propagation with MS_SHARED/MS_SLAVE",
				Description:   "syscall.Mount with MS_SHARED or MS_SLAVE propagation flags can leak mount events between namespaces, allowing container escapes or host filesystem exposure.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use MS_PRIVATE or MS_REC|MS_PRIVATE for mount propagation to prevent mount events from leaking between namespaces.",
				CWEID:         "CWE-269",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "container", "mount", "privilege-escalation"},
			})
		}
	}
	return findings
}

// --- GO-034: Deprecated RSA key size ---

type DeprecatedRSAKeySize struct{}

func (r *DeprecatedRSAKeySize) ID() string                      { return "BATOU-GO-034" }
func (r *DeprecatedRSAKeySize) Name() string                    { return "DeprecatedRSAKeySize" }
func (r *DeprecatedRSAKeySize) Description() string             { return "Detects rsa.GenerateKey with 1024 or 2048 bit keys, which are considered deprecated or weak." }
func (r *DeprecatedRSAKeySize) DefaultSeverity() rules.Severity { return rules.High }
func (r *DeprecatedRSAKeySize) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *DeprecatedRSAKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenRSAKeygen.MatchString(line) {
			severity := "weak RSA key (2048-bit)"
			if strings.Contains(line, "1024") {
				severity = "broken RSA key (1024-bit)"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Deprecated RSA key size: " + severity,
				Description:   "RSA 1024-bit keys are broken and factorable. RSA 2048-bit keys are being deprecated by NIST (target 2030). Modern applications should use at least 3072-bit RSA or switch to ECDSA/Ed25519.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use rsa.GenerateKey(rand, 4096) for RSA, or switch to ecdsa.GenerateKey(elliptic.P256(), rand) or ed25519.GenerateKey(rand) for better performance and security.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "crypto", "rsa", "key-size"},
			})
		}
	}
	return findings
}

// --- GO-035: Fail-open error handling ---

type FailOpenErrorHandling struct{}

func (r *FailOpenErrorHandling) ID() string                      { return "BATOU-GO-035" }
func (r *FailOpenErrorHandling) Name() string                    { return "FailOpenErrorHandling" }
func (r *FailOpenErrorHandling) Description() string             { return "Detects fail-open error handling (if err != nil { return nil }) in authentication or security contexts." }
func (r *FailOpenErrorHandling) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FailOpenErrorHandling) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *FailOpenErrorHandling) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag in auth/security contexts
	if !reGenAuthContext.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenFailOpen.MatchString(line) {
			// Verify we're near an auth context
			context := surroundingContext(lines, i, 10)
			if reGenAuthContext.MatchString(context) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Fail-open error handling in security context",
					Description:   "Returning nil/false on error in authentication or authorization code creates a fail-open condition. If the security check errors (e.g., database timeout), access is granted instead of denied.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Return an error or deny access on failure: if err != nil { return fmt.Errorf(\"auth failed: %w\", err) }. Security checks should fail closed.",
					CWEID:         "CWE-755",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"go", "auth", "error-handling", "fail-open"},
				})
			}
		}
	}
	return findings
}

// --- GO-036: Supply chain replace directive ---

type SupplyChainReplace struct{}

func (r *SupplyChainReplace) ID() string                      { return "BATOU-GO-036" }
func (r *SupplyChainReplace) Name() string                    { return "SupplyChainReplace" }
func (r *SupplyChainReplace) Description() string             { return "Detects go.mod replace directives with local paths, which can be exploited for supply chain attacks." }
func (r *SupplyChainReplace) DefaultSeverity() rules.Severity { return rules.High }
func (r *SupplyChainReplace) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (r *SupplyChainReplace) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan go.mod files
	if !strings.HasSuffix(ctx.FilePath, "go.mod") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenGoModReplace.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Supply chain risk: go.mod replace with local path",
				Description:   "A replace directive pointing to a local path (=> ./) in go.mod can be used for supply chain attacks. If committed, builds on other machines will fail or use different code than expected.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove local replace directives before committing. Use go.work for local development instead, or pin to a specific version tag.",
				CWEID:         "CWE-829",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "supply-chain", "go-mod", "replace"},
			})
		}
	}
	return findings
}
