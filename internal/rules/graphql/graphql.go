package graphql

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled patterns
// ---------------------------------------------------------------------------

// BATOU-GQL-001: GraphQL Introspection Enabled
var (
	// introspection: true in schema config
	reIntrospectionEnabled = regexp.MustCompile(`(?i)\bintrospection\s*[:=]\s*true\b`)
	// enableIntrospection: true
	reEnableIntrospection = regexp.MustCompile(`(?i)\benableIntrospection\s*[:=]\s*true\b`)
	// GraphQL schema creation without introspection disabled
	reSchemaCreate = regexp.MustCompile(`(?i)(?:new\s+(?:ApolloServer|GraphQLServer)|makeExecutableSchema|createServer|graphqlHTTP)\s*\(`)
	// __schema query (introspection query)
	reSchemaQuery = regexp.MustCompile(`(?i)__schema\b`)
	// Introspection disabled patterns (used as guard)
	reIntrospectionDisabled = regexp.MustCompile(`(?i)\bintrospection\s*[:=]\s*false\b`)
	reDisableIntrospection  = regexp.MustCompile(`(?i)\b(?:disableIntrospection|NoIntrospection|IntrospectionDisabled)\b`)
	// Java/Spring GraphQL introspection config
	reJavaIntrospection = regexp.MustCompile(`(?i)\.introspection\s*\(\s*true\s*\)`)
	// Python graphene/strawberry/ariadne introspection
	rePyIntrospection = regexp.MustCompile(`(?i)\bintrospection\s*=\s*True\b`)
)

// BATOU-GQL-002: No Query Depth Limiting
var (
	// Apollo Server / graphql-yoga / express-graphql creation
	reGQLServerCreate = regexp.MustCompile(`(?i)(?:new\s+ApolloServer|createYoga|graphqlHTTP|new\s+GraphQLServer)\s*\(\s*\{`)
	// Depth limiting patterns (used as guard)
	reDepthLimit     = regexp.MustCompile(`(?i)\b(?:depthLimit|maxDepth|depth[_-]?limit|queryDepth|MaxDepth)\b`)
	reComplexity     = regexp.MustCompile(`(?i)\b(?:costAnalysis|query[_-]?complexity|complexityLimit|maxComplexity|complexity[_-]?limit)\b`)
	reValidationRule = regexp.MustCompile(`(?i)\bvalidationRules\b`)
)

// ---------------------------------------------------------------------------
// Comment detection
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|#|--|;|%|/\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// BATOU-GQL-001: GraphQL Introspection Enabled
// ---------------------------------------------------------------------------

type IntrospectionEnabled struct{}

func (r IntrospectionEnabled) ID() string                    { return "BATOU-GQL-001" }
func (r IntrospectionEnabled) Name() string                  { return "GraphQL Introspection Enabled" }
func (r IntrospectionEnabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r IntrospectionEnabled) Description() string {
	return "Detects GraphQL schemas with introspection enabled, which exposes the entire API schema to attackers and aids in reconnaissance."
}
func (r IntrospectionEnabled) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython,
		rules.LangJava, rules.LangGo, rules.LangRuby,
	}
}

func (r IntrospectionEnabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if introspection is explicitly disabled anywhere in the file
	for _, l := range lines {
		if reIntrospectionDisabled.MatchString(l) || reDisableIntrospection.MatchString(l) {
			return findings
		}
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if loc := reIntrospectionEnabled.FindString(line); loc != "" {
			matched = loc
		}
		if matched == "" {
			if loc := reEnableIntrospection.FindString(line); loc != "" {
				matched = loc
			}
		}
		if matched == "" {
			if loc := rePyIntrospection.FindString(line); loc != "" {
				matched = loc
			}
		}
		if matched == "" {
			if loc := reJavaIntrospection.FindString(line); loc != "" {
				matched = loc
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GraphQL introspection enabled in schema configuration",
				Description:   "GraphQL introspection allows clients to query the full API schema, exposing all types, fields, and operations. This aids attackers in discovering sensitive endpoints and crafting targeted attacks. Introspection should be disabled in production.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Disable introspection in production: set introspection: false in Apollo Server, or use the NoIntrospection validation rule. Keep it enabled only in development.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"graphql", "introspection", "information-disclosure"},
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GQL-002: No Query Depth Limiting
// ---------------------------------------------------------------------------

type NoDepthLimiting struct{}

func (r NoDepthLimiting) ID() string                    { return "BATOU-GQL-002" }
func (r NoDepthLimiting) Name() string                  { return "GraphQL No Depth Limiting" }
func (r NoDepthLimiting) DefaultSeverity() rules.Severity { return rules.Medium }
func (r NoDepthLimiting) Description() string {
	return "Detects GraphQL server configurations without query depth limiting or complexity analysis, which allows deeply nested queries that can cause denial of service."
}
func (r NoDepthLimiting) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython,
		rules.LangJava, rules.LangGo,
	}
}

func (r NoDepthLimiting) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if depth limiting or complexity analysis is configured anywhere
	for _, l := range lines {
		if reDepthLimit.MatchString(l) || reComplexity.MatchString(l) {
			return findings
		}
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if loc := reGQLServerCreate.FindString(line); loc != "" {
			// Check if validationRules is configured in a window after the server creation
			hasValidation := false
			end := i + 20
			if end > len(lines) {
				end = len(lines)
			}
			for _, subsequent := range lines[i:end] {
				if reValidationRule.MatchString(subsequent) || reDepthLimit.MatchString(subsequent) || reComplexity.MatchString(subsequent) {
					hasValidation = true
					break
				}
			}

			if !hasValidation {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "GraphQL server without query depth limiting or complexity analysis",
					Description:   "GraphQL server is created without depth limiting or query complexity analysis. Attackers can craft deeply nested queries that cause exponential resource consumption (denial of service). For example: { user { friends { friends { friends { ... } } } } }.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(loc, 120),
					Suggestion:    "Add depth limiting (e.g., graphql-depth-limit) and/or query complexity analysis (e.g., graphql-query-complexity) to your GraphQL server configuration's validationRules.",
					CWEID:         "CWE-400",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"graphql", "dos", "depth-limit", "complexity"},
				})
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(IntrospectionEnabled{})
	rules.Register(NoDepthLimiting{})
}
