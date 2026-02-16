package nosql

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended NoSQL detection
// ---------------------------------------------------------------------------

var (
	// BATOU-NOSQL-004: MongoDB $where with user input
	reExtMongoWhere      = regexp.MustCompile(`(?i)\$where\s*['":]`)
	reExtMongoWhereConcat = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*(?:[^"'\n]*\+|[^"'\n]*\$\{|f["']|[^"'\n]*\.format|[^"'\n]*%\s)`)
	reExtMongoWhereFunc  = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*['"](?:function|this\.)`)

	// BATOU-NOSQL-005: Redis EVAL with user input
	reExtRedisEval       = regexp.MustCompile(`(?i)(?:redis|client|r|conn)\s*\.\s*(?:eval|evalsha)\s*\(`)
	reExtRedisEvalConcat = regexp.MustCompile(`(?i)(?:redis|client|r|conn)\s*\.\s*eval\s*\([^)]*(?:\+|req\.|request\.|params|user_?input|\$_)`)

	// BATOU-NOSQL-006: CouchDB Mango query injection
	reExtCouchDBFind     = regexp.MustCompile(`(?i)(?:couch|couchdb|nano|cradle).*\.(?:find|view|query)\s*\(`)
	reExtCouchDBUserInput = regexp.MustCompile(`(?i)(?:couch|couchdb|nano|cradle).*\.(?:find|view|query)\s*\(\s*(?:req\.(?:body|query|params)|request\.|JSON\.parse|params\[)`)

	// BATOU-NOSQL-007: Elasticsearch query_string with user input
	reExtESQueryString    = regexp.MustCompile(`(?i)(?:query_string|query_?string)\s*['":]`)
	reExtESQueryUserInput = regexp.MustCompile(`(?i)(?:query_string|query_?string)\s*['":]\s*[^}]*(?:req\.|request\.|params|user_?input|query|input|\$_|\+\s*[a-zA-Z_])`)
	reExtESSearch         = regexp.MustCompile(`(?i)(?:elastic|es|client)\s*\.\s*search\s*\(`)

	// BATOU-NOSQL-008: Cassandra CQL injection via concat
	reExtCQLConcat = regexp.MustCompile(`(?i)(?:session|cassandra|cluster)\s*\.\s*execute\s*\(\s*(?:["'][^"']*["']\s*\+|f["']|["'][^"']*["']\s*%\s*|["'][^"']*["']\s*\.format\s*\()`)
	reExtCQLPrepared = regexp.MustCompile(`(?i)(?:session|cassandra|cluster)\s*\.\s*(?:prepare|execute)\s*\(\s*["'][^"']*\?\s*["']`)

	// BATOU-NOSQL-009: DynamoDB filter expression injection
	reExtDynamoFilter    = regexp.MustCompile(`(?i)(?:FilterExpression|KeyConditionExpression|ProjectionExpression|ConditionExpression)\s*[:=]\s*(?:[^"'\n]*\+|f["']|[^"'\n]*\.format|[^"'\n]*%\s)`)
	reExtDynamoSafe      = regexp.MustCompile(`(?i)ExpressionAttributeValues`)

	// BATOU-NOSQL-010: Firebase Realtime DB rules bypass
	reExtFirebaseNoAuth  = regexp.MustCompile(`(?i)['"]\s*\.(?:read|write)['"]\s*:\s*['"]?\s*true\s*['"]?`)
	reExtFirebaseRules   = regexp.MustCompile(`(?i)(?:database\.rules|firestore\.rules|security\s*rules|firebase.*rules)`)

	// BATOU-NOSQL-011: Neo4j Cypher injection via concat
	reExtCypherConcat = regexp.MustCompile(`(?i)(?:session|driver|neo4j|tx)\s*\.\s*(?:run|query|execute|cypher)\s*\(\s*(?:["'][^"']*["']\s*\+|f["']|["'][^"']*["']\s*%\s*|["'][^"']*["']\s*\.format\s*\()`)
	reExtCypherParam  = regexp.MustCompile(`(?i)(?:session|driver|neo4j|tx)\s*\.\s*(?:run|query|execute)\s*\(\s*["'][^"']*\$[a-zA-Z_]`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&MongoWhereExt{})
	rules.Register(&RedisEvalRule{})
	rules.Register(&CouchDBInjection{})
	rules.Register(&ESQueryStringRule{})
	rules.Register(&CQLInjection{})
	rules.Register(&DynamoFilterRule{})
	rules.Register(&FirebaseRulesRule{})
	rules.Register(&CypherInjection{})
}

// ========================================================================
// BATOU-NOSQL-004: MongoDB $where with User Input
// ========================================================================

type MongoWhereExt struct{}

func (r *MongoWhereExt) ID() string                     { return "BATOU-NOSQL-004" }
func (r *MongoWhereExt) Name() string                   { return "MongoWhereExt" }
func (r *MongoWhereExt) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *MongoWhereExt) Description() string {
	return "Detects MongoDB $where operator with string concatenation or interpolation, enabling server-side JavaScript execution."
}
func (r *MongoWhereExt) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *MongoWhereExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if m := reExtMongoWhereConcat.FindString(line); m != "" {
			matched = m
		} else if m := reExtMongoWhereFunc.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "MongoDB $where with user input (code execution risk)",
				Description:   "The $where operator executes server-side JavaScript on the MongoDB server. String concatenation or interpolation in $where enables NoSQL injection and arbitrary code execution on the database.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove $where and use standard MongoDB query operators ($eq, $gt, $regex, etc.). If $where is required, never include user input in the expression.",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"nosql", "injection", "mongodb", "where", "code-execution"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-005: Redis EVAL with User Input
// ========================================================================

type RedisEvalRule struct{}

func (r *RedisEvalRule) ID() string                     { return "BATOU-NOSQL-005" }
func (r *RedisEvalRule) Name() string                   { return "RedisEval" }
func (r *RedisEvalRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *RedisEvalRule) Description() string {
	return "Detects Redis EVAL/EVALSHA commands with user-controlled Lua script content, enabling code execution on the Redis server."
}
func (r *RedisEvalRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *RedisEvalRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtRedisEvalConcat.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Redis EVAL with user input (Lua injection risk)",
				Description:   "Redis EVAL executes Lua scripts on the server. If the script content includes user input via concatenation, an attacker can execute arbitrary Lua code, access any key, or call dangerous Redis commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Pass user input as KEYS and ARGV arguments to EVAL, not as part of the script string. Use EVALSHA with pre-registered scripts.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"nosql", "injection", "redis", "lua"},
			})
		} else if m := reExtRedisEval.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "Redis EVAL usage (verify script is not user-controlled)",
				Description:   "Redis EVAL executes Lua scripts on the server. Ensure the Lua script content is not derived from user input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use EVALSHA with pre-loaded scripts. Pass dynamic values via KEYS and ARGV arrays.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"nosql", "redis", "lua"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-006: CouchDB Mango Query Injection
// ========================================================================

type CouchDBInjection struct{}

func (r *CouchDBInjection) ID() string                     { return "BATOU-NOSQL-006" }
func (r *CouchDBInjection) Name() string                   { return "CouchDBInjection" }
func (r *CouchDBInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *CouchDBInjection) Description() string {
	return "Detects CouchDB Mango query operations with user-controlled input, enabling query manipulation."
}
func (r *CouchDBInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython}
}

func (r *CouchDBInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtCouchDBUserInput.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CouchDB query with user-controlled input",
				Description:   "A CouchDB Mango query is constructed from user input. An attacker can inject query operators to bypass access controls or exfiltrate data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Validate and sanitize query parameters. Use a schema to restrict allowed fields and operators. Never pass raw user input to find() queries.",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"nosql", "injection", "couchdb"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-007: Elasticsearch query_string with User Input
// ========================================================================

type ESQueryStringRule struct{}

func (r *ESQueryStringRule) ID() string                     { return "BATOU-NOSQL-007" }
func (r *ESQueryStringRule) Name() string                   { return "ESQueryString" }
func (r *ESQueryStringRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *ESQueryStringRule) Description() string {
	return "Detects Elasticsearch query_string queries with user-controlled input, which supports a rich query syntax that can be abused."
}
func (r *ESQueryStringRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *ESQueryStringRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtESQueryUserInput.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Elasticsearch query_string with user input",
				Description:   "The query_string query type supports Lucene query syntax including field access, wildcards, and regex. User input in query_string can query any field, bypass access controls, or cause denial of service via expensive queries.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use simple_query_string instead (it ignores invalid syntax). Restrict searchable fields with the 'fields' parameter. Validate and sanitize user input before using in queries.",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"nosql", "injection", "elasticsearch"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-008: Cassandra CQL Injection via Concatenation
// ========================================================================

type CQLInjection struct{}

func (r *CQLInjection) ID() string                     { return "BATOU-NOSQL-008" }
func (r *CQLInjection) Name() string                   { return "CQLInjection" }
func (r *CQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *CQLInjection) Description() string {
	return "Detects Cassandra CQL queries built via string concatenation instead of parameterized queries."
}
func (r *CQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJava, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *CQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtCQLConcat.FindString(line); m != "" {
			// Skip if prepared statements are used
			if reExtCQLPrepared.MatchString(line) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Cassandra CQL injection via string concatenation",
				Description:   "A CQL query is built using string concatenation or formatting. An attacker can inject CQL commands to bypass authentication, read unauthorized data, or modify/delete data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use parameterized queries (prepared statements) with ? placeholders: session.execute(prepared_stmt, [param1, param2]).",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"nosql", "injection", "cassandra", "cql"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-009: DynamoDB Filter Expression Injection
// ========================================================================

type DynamoFilterRule struct{}

func (r *DynamoFilterRule) ID() string                     { return "BATOU-NOSQL-009" }
func (r *DynamoFilterRule) Name() string                   { return "DynamoFilterInjection" }
func (r *DynamoFilterRule) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DynamoFilterRule) Description() string {
	return "Detects DynamoDB filter/condition expressions built via string concatenation instead of expression attribute values."
}
func (r *DynamoFilterRule) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo}
}

func (r *DynamoFilterRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtDynamoFilter.FindString(line); m != "" {
			// Check if ExpressionAttributeValues is used nearby
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			block := strings.Join(lines[i:end], "\n")
			if reExtDynamoSafe.MatchString(block) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "DynamoDB expression injection via string concatenation",
				Description:   "A DynamoDB filter or condition expression is built using string concatenation. An attacker can inject expression syntax to modify query behavior or access unauthorized data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use ExpressionAttributeValues and ExpressionAttributeNames with placeholder syntax (:value, #name) instead of string concatenation.",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"nosql", "injection", "dynamodb", "aws"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-010: Firebase Realtime DB Rules Bypass
// ========================================================================

type FirebaseRulesRule struct{}

func (r *FirebaseRulesRule) ID() string                     { return "BATOU-NOSQL-010" }
func (r *FirebaseRulesRule) Name() string                   { return "FirebaseRulesBypass" }
func (r *FirebaseRulesRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *FirebaseRulesRule) Description() string {
	return "Detects Firebase Realtime Database or Firestore security rules that allow unrestricted read/write access."
}
func (r *FirebaseRulesRule) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *FirebaseRulesRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtFirebaseNoAuth.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Firebase security rules allow unrestricted access",
				Description:   "Firebase Realtime Database or Firestore rules are set to allow read/write access to everyone (.read: true or .write: true). This means any user, including unauthenticated users, can read or modify all data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Restrict access using Firebase Authentication: \".read\": \"auth != null\". Use per-resource rules: \".read\": \"auth.uid === $uid\". Never deploy with open rules in production.",
				CWEID:         "CWE-284",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"nosql", "firebase", "access-control", "rules"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-NOSQL-011: Neo4j Cypher Injection via Concatenation
// ========================================================================

type CypherInjection struct{}

func (r *CypherInjection) ID() string                     { return "BATOU-NOSQL-011" }
func (r *CypherInjection) Name() string                   { return "CypherInjection" }
func (r *CypherInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *CypherInjection) Description() string {
	return "Detects Neo4j Cypher queries built via string concatenation instead of parameterized queries."
}
func (r *CypherInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJava, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *CypherInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtCypherConcat.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Neo4j Cypher injection via string concatenation",
				Description:   "A Cypher query is built using string concatenation or formatting. An attacker can inject Cypher clauses to read unauthorized nodes/relationships, modify graph data, or call APOC procedures for code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use parameterized queries with $parameter syntax: session.run('MATCH (n) WHERE n.name = $name', {name: userInput}).",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"nosql", "injection", "neo4j", "cypher"},
			})
		}
	}
	return findings
}
