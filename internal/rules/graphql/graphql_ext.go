package graphql

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended GraphQL rules
// ---------------------------------------------------------------------------

// BATOU-GQL-003: GraphQL introspection enabled in production
var (
	reIntrospectionProd    = regexp.MustCompile(`(?i)(?:introspection\s*[:=]\s*true|enableIntrospection\s*[:=]\s*true|introspection\s*=\s*True|\.introspection\s*\(\s*true\s*\))`)
	reProdFile             = regexp.MustCompile(`(?i)(?:production|prod\.|\.prod|deploy|release)`)
	reIntrospectionGuarded = regexp.MustCompile(`(?i)(?:process\.env|NODE_ENV|RAILS_ENV|DJANGO_SETTINGS|__debug__|isDev|isProduction|isProd)`)
)

// BATOU-GQL-004: GraphQL query depth not limited
var (
	reGQLSchemaSetup = regexp.MustCompile(`(?i)(?:new\s+ApolloServer|createYoga|graphqlHTTP|GraphQLModule|new\s+GraphQLServer|graphql\.NewHandler|graphql\.Handler)\s*\(`)
	reGQLDepthCheck  = regexp.MustCompile(`(?i)(?:depthLimit|maxDepth|depth[_-]?limit|queryDepth|MaxDepth|max_depth)`)
)

// BATOU-GQL-005: GraphQL field-level authorization missing
var (
	reGQLResolverFunc = regexp.MustCompile(`(?i)(?:resolve\s*[:=]\s*(?:async\s+)?(?:function|\()|\w+\s*:\s*\{\s*(?:type|resolve)|def\s+resolve_\w+|@ResolveField|func\s+\(\w+\s+\*\w+Resolver\))`)
	reGQLAuthCheck    = regexp.MustCompile(`(?i)(?:authorize|auth|permission|isAuthenticated|currentUser|context\.user|ctx\.user|@Authorized|@PreAuthorize|@Secured|requireAuth|checkAuth|hasPermission|@login_required|@permission_required|authenticate)`)
)

// BATOU-GQL-006: GraphQL batch query attack
var (
	reGQLBatchEnabled  = regexp.MustCompile(`(?i)(?:batch\s*[:=]\s*true|batching\s*[:=]\s*true|allowBatchedHttpRequests\s*[:=]\s*true)`)
	reGQLBatchLimit    = regexp.MustCompile(`(?i)(?:batchLimit|batch_limit|maxBatch|max_batch|BatchLimit|maxOperationsPerRequest)`)
)

// BATOU-GQL-007: GraphQL SQL injection via resolver
var (
	reGQLResolverSQL = regexp.MustCompile(`(?i)(?:resolve|resolver)\b[^}]*(?:query|execute|raw|rawQuery|executeQuery)\s*\([^)]*(?:\$\{|` + "`" + `|\+\s*(?:args|input|parent|root|context|info)\b|%s|%v|format|f['"])`)
	reGQLRawQuery    = regexp.MustCompile(`(?i)(?:db\.query|connection\.query|pool\.query|\.raw|\.execute|cursor\.execute|\.rawQuery)\s*\(\s*(?:` + "`" + `[^` + "`" + `]*\$\{|['"][^'"]*['"]\s*\+|f['"])`)
)

// BATOU-GQL-008: GraphQL mutation without authentication
var (
	reGQLMutation        = regexp.MustCompile(`(?i)(?:type\s+Mutation|Mutation\s*[:=]|\.mutation\s*\(|@Mutation|mutation_type|MutationType)`)
	reGQLMutationResolve = regexp.MustCompile(`(?i)(?:Mutation\s*[:=]\s*\{|mutation\s*[:=]\s*new|mutationType\s*[:=])`)
)

// BATOU-GQL-009: GraphQL persisted queries disabled
var (
	reGQLPersistedOff    = regexp.MustCompile(`(?i)(?:persistedQueries\s*[:=]\s*false|persisted[_-]?queries\s*[:=]\s*false|automaticPersistedQueries\s*[:=]\s*false)`)
	reGQLPersistedOn     = regexp.MustCompile(`(?i)(?:persistedQueries|persisted_queries|automaticPersistedQueries|PersistedQueryLink|persistedQueries\s*[:=]\s*true)`)
)

// BATOU-GQL-010: GraphQL error message information disclosure
var (
	reGQLErrorDetail = regexp.MustCompile(`(?i)(?:formatError|format_error|error_formatter)\s*[:=]\s*(?:function|\(|=>)`)
	reGQLErrorStack  = regexp.MustCompile(`(?i)(?:error|err|e)\.(?:stack|stackTrace|originalError|message)\b`)
	reGQLDebugErrors = regexp.MustCompile(`(?i)(?:debug\s*[:=]\s*true|includeStacktrace|includeExceptionDetails|showDetailedErrors)\b`)
)

// ---------------------------------------------------------------------------
// BATOU-GQL-003: GraphQL Introspection Enabled in Production
// ---------------------------------------------------------------------------

type IntrospectionEnabledProd struct{}

func (r *IntrospectionEnabledProd) ID() string                     { return "BATOU-GQL-003" }
func (r *IntrospectionEnabledProd) Name() string                   { return "IntrospectionEnabledProd" }
func (r *IntrospectionEnabledProd) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *IntrospectionEnabledProd) Description() string {
	return "Detects GraphQL introspection enabled unconditionally (not guarded by environment check), likely active in production."
}
func (r *IntrospectionEnabledProd) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo, rules.LangRuby}
}

func (r *IntrospectionEnabledProd) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reIntrospectionProd.FindStringIndex(line); loc != nil {
			// Skip if guarded by environment check
			if reIntrospectionGuarded.MatchString(line) {
				continue
			}
			// Higher confidence if file looks like production config
			confidence := "medium"
			if reProdFile.MatchString(ctx.FilePath) {
				confidence = "high"
			}
			matched := line[loc[0]:loc[1]]
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL introspection enabled unconditionally (may be active in production)",
				Description:   "GraphQL introspection is enabled without an environment guard. In production, introspection exposes the entire API schema including all types, fields, queries, and mutations, enabling targeted attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Guard introspection with an environment check: introspection: process.env.NODE_ENV !== 'production'. Or disable entirely and use schema documentation tools instead.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"graphql", "introspection", "production", "cwe-200"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-004: GraphQL Query Depth Not Limited
// ---------------------------------------------------------------------------

type GQLQueryDepthNotLimited struct{}

func (r *GQLQueryDepthNotLimited) ID() string                     { return "BATOU-GQL-004" }
func (r *GQLQueryDepthNotLimited) Name() string                   { return "GQLQueryDepthNotLimited" }
func (r *GQLQueryDepthNotLimited) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GQLQueryDepthNotLimited) Description() string {
	return "Detects GraphQL schema setup without query depth limiting, allowing deeply nested queries that cause denial of service."
}
func (r *GQLQueryDepthNotLimited) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLQueryDepthNotLimited) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// If depth limiting is present anywhere, skip
	if reGQLDepthCheck.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reGQLSchemaSetup.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL server without query depth limit",
				Description:   "GraphQL server is configured without a query depth limit. Attackers can craft deeply nested queries (e.g., { user { friends { friends { friends { ... } } } } }) causing exponential resource consumption and denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Add query depth limiting using a library like graphql-depth-limit. Set maxDepth to a reasonable value (typically 7-10). Also consider adding query complexity analysis.",
				CWEID:         "CWE-400",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"graphql", "dos", "depth-limit", "cwe-400"},
			})
			return findings
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-005: GraphQL Field-Level Authorization Missing
// ---------------------------------------------------------------------------

type GQLFieldAuthMissing struct{}

func (r *GQLFieldAuthMissing) ID() string                     { return "BATOU-GQL-005" }
func (r *GQLFieldAuthMissing) Name() string                   { return "GQLFieldAuthMissing" }
func (r *GQLFieldAuthMissing) DefaultSeverity() rules.Severity { return rules.High }
func (r *GQLFieldAuthMissing) Description() string {
	return "Detects GraphQL resolvers without authorization checks, potentially exposing data to unauthenticated or unauthorized users."
}
func (r *GQLFieldAuthMissing) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLFieldAuthMissing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if file has auth patterns globally
	if reGQLAuthCheck.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reGQLResolverFunc.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL resolver without authorization check",
				Description:   "A GraphQL resolver function does not include any authorization check. Without field-level authorization, any authenticated (or unauthenticated) user can access data they should not have permission to see.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Add authorization checks in resolvers. Use a middleware/directive like @auth, @authorized, or check context.user permissions before returning data. Implement field-level authorization, not just route-level.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"graphql", "authorization", "access-control", "cwe-862"},
			})
			return findings
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-006: GraphQL Batch Query Attack
// ---------------------------------------------------------------------------

type GQLBatchQueryAttack struct{}

func (r *GQLBatchQueryAttack) ID() string                     { return "BATOU-GQL-006" }
func (r *GQLBatchQueryAttack) Name() string                   { return "GQLBatchQueryAttack" }
func (r *GQLBatchQueryAttack) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GQLBatchQueryAttack) Description() string {
	return "Detects GraphQL batch query support enabled without a batch size limit, allowing attackers to send hundreds of queries in a single request."
}
func (r *GQLBatchQueryAttack) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLBatchQueryAttack) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// If batch limit is configured, skip
	if reGQLBatchLimit.MatchString(ctx.Content) {
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reGQLBatchEnabled.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL batch queries enabled without limit",
				Description:   "GraphQL batching is enabled without a batch size limit. Attackers can send hundreds of operations in a single HTTP request to bypass rate limiting, brute-force authentication, or cause denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Set a batch query limit (e.g., maxOperationsPerRequest: 5). Consider disabling batching entirely if not needed, or implement per-operation rate limiting.",
				CWEID:         "CWE-770",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"graphql", "batch", "dos", "rate-limit", "cwe-770"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-007: GraphQL SQL Injection via Resolver
// ---------------------------------------------------------------------------

type GQLSQLInjection struct{}

func (r *GQLSQLInjection) ID() string                     { return "BATOU-GQL-007" }
func (r *GQLSQLInjection) Name() string                   { return "GQLSQLInjection" }
func (r *GQLSQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *GQLSQLInjection) Description() string {
	return "Detects SQL queries in GraphQL resolvers that use string concatenation or interpolation with resolver arguments, enabling SQL injection."
}
func (r *GQLSQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reGQLRawQuery.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQL injection in GraphQL resolver via string interpolation",
				Description:   "A raw SQL query in a GraphQL resolver uses string concatenation or template interpolation with resolver arguments. Attackers can inject SQL through GraphQL query variables.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [args.id]). Never concatenate resolver arguments into SQL strings. Use an ORM or query builder.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"graphql", "sql-injection", "resolver", "cwe-89"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-008: GraphQL Mutation Without Authentication
// ---------------------------------------------------------------------------

type GQLMutationNoAuth struct{}

func (r *GQLMutationNoAuth) ID() string                     { return "BATOU-GQL-008" }
func (r *GQLMutationNoAuth) Name() string                   { return "GQLMutationNoAuth" }
func (r *GQLMutationNoAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *GQLMutationNoAuth) Description() string {
	return "Detects GraphQL mutation definitions without authentication checks, allowing unauthenticated users to modify data."
}
func (r *GQLMutationNoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLMutationNoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if auth checks are present in the file
	if reGQLAuthCheck.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reGQLMutation.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL mutation without authentication check",
				Description:   "GraphQL mutations (data modification operations) are defined without any authentication or authorization checks. This allows unauthenticated users to create, update, or delete data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Add authentication middleware or directive to all mutations. Use @auth directive, context.user checks, or middleware that runs before mutation resolvers. At minimum, verify the user is authenticated.",
				CWEID:         "CWE-306",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"graphql", "mutation", "authentication", "cwe-306"},
			})
			return findings
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-009: GraphQL Persisted Queries Disabled
// ---------------------------------------------------------------------------

type GQLPersistedQueriesDisabled struct{}

func (r *GQLPersistedQueriesDisabled) ID() string                     { return "BATOU-GQL-009" }
func (r *GQLPersistedQueriesDisabled) Name() string                   { return "GQLPersistedQueriesDisabled" }
func (r *GQLPersistedQueriesDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GQLPersistedQueriesDisabled) Description() string {
	return "Detects GraphQL configurations that explicitly disable persisted queries, allowing arbitrary queries from untrusted clients."
}
func (r *GQLPersistedQueriesDisabled) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLPersistedQueriesDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reGQLPersistedOff.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL persisted queries disabled (arbitrary queries allowed)",
				Description:   "Persisted queries are explicitly disabled. Without persisted queries, any client can send arbitrary GraphQL operations, increasing the attack surface for injection, DoS via complex queries, and data exfiltration.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Enable persisted queries in production so only pre-approved queries can be executed. Use automatic persisted queries (APQ) for a smoother developer experience while limiting arbitrary query execution.",
				CWEID:         "CWE-20",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"graphql", "persisted-queries", "cwe-20"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-010: GraphQL Error Message Information Disclosure
// ---------------------------------------------------------------------------

type GQLErrorDisclosure struct{}

func (r *GQLErrorDisclosure) ID() string                     { return "BATOU-GQL-010" }
func (r *GQLErrorDisclosure) Name() string                   { return "GQLErrorDisclosure" }
func (r *GQLErrorDisclosure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GQLErrorDisclosure) Description() string {
	return "Detects GraphQL error formatting that exposes stack traces, internal error details, or original error messages to clients."
}
func (r *GQLErrorDisclosure) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo}
}

func (r *GQLErrorDisclosure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		matched := ""
		if loc := reGQLDebugErrors.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		} else if reGQLErrorDetail.MatchString(line) {
			// Check if the error formatter returns stack traces
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			for j := i; j < end; j++ {
				if reGQLErrorStack.MatchString(lines[j]) {
					matched = strings.TrimSpace(line)
					break
				}
			}
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL error messages expose internal details",
				Description:   "GraphQL error handling is configured to expose stack traces, original error messages, or internal details to clients. This reveals implementation details, file paths, and database structure that aids attackers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "In production, return generic error messages. Use formatError to strip stack traces and internal details. Log detailed errors server-side: formatError: (err) => ({ message: 'Internal error', locations: err.locations }).",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"graphql", "error-disclosure", "information-leak", "cwe-209"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&IntrospectionEnabledProd{})
	rules.Register(&GQLQueryDepthNotLimited{})
	rules.Register(&GQLFieldAuthMissing{})
	rules.Register(&GQLBatchQueryAttack{})
	rules.Register(&GQLSQLInjection{})
	rules.Register(&GQLMutationNoAuth{})
	rules.Register(&GQLPersistedQueriesDisabled{})
	rules.Register(&GQLErrorDisclosure{})
}
