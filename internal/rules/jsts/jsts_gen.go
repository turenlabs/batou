package jsts

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Generated patterns for JSTS-031 through JSTS-040
// ---------------------------------------------------------------------------

// JSTS-031: Prototype pollution via deep merge
var (
	reGenDeepMerge  = regexp.MustCompile(`\b(?:deepMerge|merge|assign|extend|defaults|defaultsDeep)\s*\(`)
	reGenProtoKey   = regexp.MustCompile(`(?:__proto__|constructor|prototype)`)
	reGenMergeGuard = regexp.MustCompile(`(?:hasOwnProperty|Object\.keys|Object\.freeze|Object\.create\s*\(\s*null\s*\))`)
)

// JSTS-032: LLM prompt injection
var (
	reGenJSLLMCall    = regexp.MustCompile("(?i)(?:openai|anthropic|langchain|ChatOpenAI|ChatAnthropic|createChatCompletion|createCompletion|messages\\.create)\\s*[\\(.]")
	reGenJSLLMInterp  = regexp.MustCompile("(?:`[^`]*\\$\\{[^}]*(?i)(?:user|input|query|param|body|req|request)[^}]*\\}|\\+\\s*(?:req|request|user|input|query|params)\\.).*(?i)(?:prompt|message|content|system|instruction)")
	reGenJSUserInput  = regexp.MustCompile(`(?:req\.(?:body|query|params|headers)|request\.(?:body|query|params)|ctx\.(?:request|query|params))`)
)

// JSTS-033: npm install hook execution
var (
	reGenNPMHook     = regexp.MustCompile(`"(?:preinstall|postinstall|preuninstall|postuninstall|prepare|prepublish)"\s*:\s*"[^"]*(?:curl|wget|node|sh|bash|python|ruby|exec|eval)`)
)

// JSTS-034: GraphQL introspection enabled
var (
	reGenIntrospection = regexp.MustCompile(`introspection\s*:\s*true`)
)

// JSTS-035: GraphQL depth unlimited
var (
	reGenGraphQLServer = regexp.MustCompile(`(?:ApolloServer|graphqlHTTP|GraphQLServer|createServer)\s*\(`)
	reGenDepthLimit    = regexp.MustCompile(`(?i)(?:depthLimit|depth[_-]?limit|maxDepth|max[_-]?depth|validationRules)`)
)

// JSTS-036: Next.js Server Actions SSRF
var (
	reGenUseServer   = regexp.MustCompile(`["']use server["']`)
	reGenFetchCall   = regexp.MustCompile(`\bfetch\s*\(`)
	reGenUserURL     = regexp.MustCompile(`(?:req\.(?:body|query|params)|request\.(?:body|query|params)|formData\.get|searchParams\.get)\s*[\[\(.]`)
)

// JSTS-037: Node.js vm sandbox escape
var (
	reGenVMRequire  = regexp.MustCompile(`require\s*\(\s*['"]vm['"]\s*\)`)
	reGenVMImport   = regexp.MustCompile(`from\s+['"]vm['"]`)
	reGenVMContext  = regexp.MustCompile(`\b(?:createContext|runInNewContext|runInContext|Script|compileFunction)\s*\(`)
)

// JSTS-038: Prisma raw query injection
var (
	reGenPrismaRaw = regexp.MustCompile("\\$(?:queryRaw|executeRaw)\\s*\\(\\s*`[^`]*\\$\\{")
	reGenPrismaRawConcat = regexp.MustCompile(`\$(?:queryRaw|executeRaw)\s*\(\s*(?:['"][^'"]*['"]\s*\+|\w+\s*\+)`)
)

// JSTS-039: Secrets in client bundle
var (
	reGenClientPath   = regexp.MustCompile(`(?i)(?:src/(?:client|frontend|components|pages|app)|public|static|\.next|\.nuxt)`)
	reGenEnvSecret    = regexp.MustCompile(`process\.env\.(?:[A-Z_]*(?:SECRET|PASSWORD|API_KEY|PRIVATE_KEY|TOKEN|CREDENTIAL|AUTH)[A-Z_]*)`)
)

// JSTS-040: Unsafe eval of AI output
var (
	reGenJSEval      = regexp.MustCompile(`\b(?:eval|Function|new\s+Function)\s*\(`)
	reGenJSAIOutput  = regexp.MustCompile(`(?i)(?:response|completion|generated|ai[_.]?output|llm[_.]?output|model[_.]?output|result|answer)`)
)

func init() {
	rules.Register(&PrototypePollutionMerge{})
	rules.Register(&JSLLMPromptInjection{})
	rules.Register(&NPMInstallHook{})
	rules.Register(&GraphQLIntrospection{})
	rules.Register(&GraphQLDepthUnlimited{})
	rules.Register(&NextJSServerActionSSRF{})
	rules.Register(&VMSandboxEscapeGen{})
	rules.Register(&PrismaRawInjection{})
	rules.Register(&SecretsInClientBundle{})
	rules.Register(&EvalAIOutput{})
}

// --- JSTS-031: Prototype pollution via deep merge ---

type PrototypePollutionMerge struct{}

func (r *PrototypePollutionMerge) ID() string                      { return "BATOU-JSTS-031" }
func (r *PrototypePollutionMerge) Name() string                    { return "PrototypePollutionMerge" }
func (r *PrototypePollutionMerge) Description() string             { return "Detects deep merge/assign/extend operations with __proto__ or constructor access, enabling prototype pollution." }
func (r *PrototypePollutionMerge) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PrototypePollutionMerge) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *PrototypePollutionMerge) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if prototype guards are present
	if reGenMergeGuard.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenDeepMerge.MatchString(line) && reGenProtoKey.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Prototype pollution via deep merge with __proto__/constructor",
				Description:   "Deep merge operations that do not filter __proto__ or constructor keys allow attackers to modify Object.prototype, affecting all objects in the application and enabling RCE or auth bypass.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use Object.create(null) for merge targets, filter __proto__/constructor keys, or use libraries with prototype pollution protection (e.g., lodash >= 4.17.21).",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "prototype-pollution", "merge"},
			})
		}
	}
	return findings
}

// --- JSTS-032: LLM prompt injection ---

type JSLLMPromptInjection struct{}

func (r *JSLLMPromptInjection) ID() string                      { return "BATOU-JSTS-032" }
func (r *JSLLMPromptInjection) Name() string                    { return "JSLLMPromptInjection" }
func (r *JSLLMPromptInjection) Description() string             { return "Detects template literal interpolation with user input in AI/LLM API calls." }
func (r *JSLLMPromptInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *JSLLMPromptInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *JSLLMPromptInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files that reference LLM/AI APIs
	if !reGenJSLLMCall.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenJSLLMInterp.MatchString(line) {
			confidence := "medium"
			if hasNearbyMatch(lines, i, reGenJSUserInput, 10) {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LLM prompt injection via template literal interpolation",
				Description:   "User input interpolated into LLM prompts via template literals enables prompt injection. Attackers can override system instructions, exfiltrate data, or manipulate AI behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use the API's structured message format with separate system/user roles. Apply input validation, length limits, and output filtering. Never interpolate user input into system prompts.",
				CWEID:         "CWE-77",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"jsts", "llm", "prompt-injection", "ai"},
			})
		}
	}
	return findings
}

// --- JSTS-033: npm install hook execution ---

type NPMInstallHook struct{}

func (r *NPMInstallHook) ID() string                      { return "BATOU-JSTS-033" }
func (r *NPMInstallHook) Name() string                    { return "NPMInstallHook" }
func (r *NPMInstallHook) Description() string             { return "Detects npm preinstall/postinstall hooks that execute shell commands, a common supply chain attack vector." }
func (r *NPMInstallHook) DefaultSeverity() rules.Severity { return rules.High }
func (r *NPMInstallHook) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *NPMInstallHook) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan package.json files
	if !strings.HasSuffix(ctx.FilePath, "package.json") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if reGenNPMHook.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Suspicious npm install hook with shell execution",
				Description:   "npm lifecycle hooks (preinstall/postinstall) executing shell commands (curl, wget, sh) are a primary supply chain attack vector. Malicious packages use these to download and execute payloads.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Avoid preinstall/postinstall hooks that execute shell commands. Use --ignore-scripts during install. Audit all install hooks in dependencies with 'npm explain'.",
				CWEID:         "CWE-829",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "npm", "supply-chain", "install-hook"},
			})
		}
	}
	return findings
}

// --- JSTS-034: GraphQL introspection enabled ---

type GraphQLIntrospection struct{}

func (r *GraphQLIntrospection) ID() string                      { return "BATOU-JSTS-034" }
func (r *GraphQLIntrospection) Name() string                    { return "GraphQLIntrospection" }
func (r *GraphQLIntrospection) Description() string             { return "Detects GraphQL introspection enabled in production, exposing the full schema to attackers." }
func (r *GraphQLIntrospection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GraphQLIntrospection) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *GraphQLIntrospection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenIntrospection.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL introspection enabled",
				Description:   "GraphQL introspection exposes the entire API schema including types, fields, mutations, and relationships. Attackers use this for reconnaissance to discover sensitive endpoints and data structures.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Disable introspection in production: introspection: process.env.NODE_ENV !== 'production'. Use schema-based documentation instead.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"jsts", "graphql", "introspection", "information-disclosure"},
			})
		}
	}
	return findings
}

// --- JSTS-035: GraphQL depth unlimited ---

type GraphQLDepthUnlimited struct{}

func (r *GraphQLDepthUnlimited) ID() string                      { return "BATOU-JSTS-035" }
func (r *GraphQLDepthUnlimited) Name() string                    { return "GraphQLDepthUnlimited" }
func (r *GraphQLDepthUnlimited) Description() string             { return "Detects GraphQL servers (Apollo/express-graphql) without query depth limiting, enabling DoS via nested queries." }
func (r *GraphQLDepthUnlimited) DefaultSeverity() rules.Severity { return rules.High }
func (r *GraphQLDepthUnlimited) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *GraphQLDepthUnlimited) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if depth limiting is configured
	if reGenDepthLimit.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenGraphQLServer.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL server without query depth limit",
				Description:   "GraphQL servers without depth limiting are vulnerable to denial of service via deeply nested queries. An attacker can craft a query with recursive relationships to exhaust server resources.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add query depth limiting: validationRules: [depthLimit(10)] using the graphql-depth-limit package. Also consider query cost analysis and rate limiting.",
				CWEID:         "CWE-400",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"jsts", "graphql", "dos", "depth-limit"},
			})
		}
	}
	return findings
}

// --- JSTS-036: Next.js Server Actions SSRF ---

type NextJSServerActionSSRF struct{}

func (r *NextJSServerActionSSRF) ID() string                      { return "BATOU-JSTS-036" }
func (r *NextJSServerActionSSRF) Name() string                    { return "NextJSServerActionSSRF" }
func (r *NextJSServerActionSSRF) Description() string             { return "Detects fetch() with user-controlled URLs in Next.js Server Actions ('use server'), enabling SSRF." }
func (r *NextJSServerActionSSRF) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *NextJSServerActionSSRF) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *NextJSServerActionSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files with 'use server' directive
	if !reGenUseServer.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenFetchCall.MatchString(line) && hasNearbyMatch(lines, i, reGenUserURL, 10) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SSRF via fetch() in Next.js Server Action",
				Description:   "fetch() with user-controlled URLs in a 'use server' context runs server-side, enabling SSRF. Attackers can access internal services (metadata APIs, databases) via the server's network.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate and allowlist URLs before fetching. Block internal IP ranges (169.254.0.0/16, 10.0.0.0/8, 127.0.0.0/8). Use a URL parser to verify the hostname against an allowlist.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-Server-Side Request Forgery",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "nextjs", "ssrf", "server-actions"},
			})
		}
	}
	return findings
}

// --- JSTS-037: Node.js vm sandbox escape ---

type VMSandboxEscapeGen struct{}

func (r *VMSandboxEscapeGen) ID() string                      { return "BATOU-JSTS-037" }
func (r *VMSandboxEscapeGen) Name() string                    { return "VMSandboxEscapeGen" }
func (r *VMSandboxEscapeGen) Description() string             { return "Detects Node.js vm module usage (createContext/runInNewContext), which is not a security sandbox." }
func (r *VMSandboxEscapeGen) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *VMSandboxEscapeGen) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *VMSandboxEscapeGen) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan files that import vm
	if !reGenVMRequire.MatchString(ctx.Content) && !reGenVMImport.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenVMContext.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Node.js vm module used as sandbox (escapable)",
				Description:   "Node.js vm module is NOT a security sandbox. Code running in vm contexts can escape via this.constructor, prototype chain traversal, or accessing global objects to achieve full RCE.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use vm2 (deprecated but safer), isolated-vm, or run untrusted code in a separate process/container with restricted permissions. Never use Node.js vm for security isolation.",
				CWEID:         "CWE-265",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "vm", "sandbox-escape", "rce"},
			})
		}
	}
	return findings
}

// --- JSTS-038: Prisma raw query injection ---

type PrismaRawInjection struct{}

func (r *PrismaRawInjection) ID() string                      { return "BATOU-JSTS-038" }
func (r *PrismaRawInjection) Name() string                    { return "PrismaRawInjection" }
func (r *PrismaRawInjection) Description() string             { return "Detects Prisma $queryRaw/$executeRaw with template interpolation, enabling SQL injection." }
func (r *PrismaRawInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PrismaRawInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *PrismaRawInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		var desc string

		if reGenPrismaRaw.MatchString(line) {
			matched = true
			desc = "template literal interpolation in $queryRaw/$executeRaw"
		} else if reGenPrismaRawConcat.MatchString(line) {
			matched = true
			desc = "string concatenation in $queryRaw/$executeRaw"
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Prisma SQL injection via " + desc,
				Description:   "Prisma's $queryRaw and $executeRaw with template interpolation or concatenation bypass Prisma's built-in SQL injection protection. The tagged template literal form (Prisma.sql``) is safe, but regular template literals are not.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use Prisma's tagged template: prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE id = ${id}`). The Prisma.sql tag adds parameterization automatically.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "prisma", "sql-injection", "orm"},
			})
		}
	}
	return findings
}

// --- JSTS-039: Secrets in client bundle ---

type SecretsInClientBundle struct{}

func (r *SecretsInClientBundle) ID() string                      { return "BATOU-JSTS-039" }
func (r *SecretsInClientBundle) Name() string                    { return "SecretsInClientBundle" }
func (r *SecretsInClientBundle) Description() string             { return "Detects process.env.SECRET/PASSWORD/API_KEY references in client-side code paths." }
func (r *SecretsInClientBundle) DefaultSeverity() rules.Severity { return rules.High }
func (r *SecretsInClientBundle) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *SecretsInClientBundle) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag in client-side file paths
	if !reGenClientPath.MatchString(ctx.FilePath) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenEnvSecret.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Secret environment variable in client-side code",
				Description:   "process.env variables containing SECRET, PASSWORD, API_KEY, or PRIVATE_KEY in client-side paths will be bundled into the JavaScript sent to browsers, exposing secrets to all users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Move secret access to server-side API routes. Use NEXT_PUBLIC_ or REACT_APP_ prefixes only for non-sensitive values. Access secrets via API calls from client code.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "secrets", "client-bundle", "environment"},
			})
		}
	}
	return findings
}

// --- JSTS-040: Unsafe eval of AI output ---

type EvalAIOutput struct{}

func (r *EvalAIOutput) ID() string                      { return "BATOU-JSTS-040" }
func (r *EvalAIOutput) Name() string                    { return "EvalAIOutput" }
func (r *EvalAIOutput) Description() string             { return "Detects eval/Function called with AI/LLM response variables, enabling arbitrary code execution." }
func (r *EvalAIOutput) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *EvalAIOutput) Languages() []rules.Language     { return []rules.Language{rules.LangJavaScript, rules.LangTypeScript} }

func (r *EvalAIOutput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reGenJSEval.MatchString(line) && reGenJSAIOutput.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Arbitrary code execution via eval/Function of AI output",
				Description:   "Passing LLM/AI-generated text to eval() or new Function() enables arbitrary code execution. LLM outputs are untrusted and can be manipulated via prompt injection to produce malicious code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never eval AI output. Parse structured responses with JSON.parse(). Use a sandboxed interpreter (e.g., isolated-vm) if code execution is needed. Apply Content Security Policy to prevent eval in browsers.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jsts", "eval", "llm", "ai", "rce"},
			})
		}
	}
	return findings
}
