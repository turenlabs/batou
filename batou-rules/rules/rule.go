package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Severity determines the action taken when a finding is reported.
type Severity int

const (
	Info     Severity = 0
	Low      Severity = 1
	Medium   Severity = 2
	High     Severity = 3
	Critical Severity = 4
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

func (s Severity) Icon() string {
	switch s {
	case Info:
		return "i"
	case Low:
		return "L"
	case Medium:
		return "M"
	case High:
		return "H"
	case Critical:
		return "!"
	}
	return "?"
}

// ShouldBlock returns true if this severity should block a file write.
func (s Severity) ShouldBlock() bool {
	return s >= Critical
}

// ShouldWarn returns true if this severity warrants a warning to Claude.
func (s Severity) ShouldWarn() bool {
	return s >= High
}

// ImpactWeight returns the risk multiplier for this severity level.
// Used to compute RiskScore = ImpactWeight × ConfidenceScore.
func (s Severity) ImpactWeight() float64 {
	switch s {
	case Critical:
		return 1.0
	case High:
		return 0.8
	case Medium:
		return 0.5
	case Low:
		return 0.25
	case Info:
		return 0.1
	default:
		return 0.1
	}
}

// Language represents a programming language for rule targeting.
type Language string

const (
	LangGo         Language = "go"
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangJava       Language = "java"
	LangRuby       Language = "ruby"
	LangPHP        Language = "php"
	LangCSharp     Language = "csharp"
	LangKotlin     Language = "kotlin"
	LangGroovy     Language = "groovy"
	LangSwift      Language = "swift"
	LangRust       Language = "rust"
	LangC          Language = "c"
	LangCPP        Language = "cpp"
	LangShell      Language = "shell"
	LangSQL        Language = "sql"
	LangYAML       Language = "yaml"
	LangJSON       Language = "json"
	LangPerl       Language = "perl"
	LangLua        Language = "lua"
	LangZig        Language = "zig"
	LangDocker     Language = "dockerfile"
	LangTerraform  Language = "terraform"
	LangAny        Language = "*"
)

// Finding represents a single security finding detected by a rule.
type Finding struct {
	RuleID        string   `json:"rule_id"`
	Severity      Severity `json:"severity"`
	SeverityLabel string   `json:"severity_label"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	FilePath      string   `json:"file_path"`
	LineNumber    int      `json:"line_number,omitempty"`
	Column        int      `json:"column,omitempty"`
	MatchedText   string   `json:"matched_text,omitempty"`
	Suggestion    string   `json:"suggestion,omitempty"`
	CWEID         string   `json:"cwe_id,omitempty"`
	OWASPCategory string   `json:"owasp_category,omitempty"`
	Language      Language `json:"language,omitempty"`
	Confidence      string   `json:"confidence"`                  // high, medium, low
	ConfidenceScore float64  `json:"confidence_score"`            // 0.0-1.0, computed by pipeline
	RiskScore       float64  `json:"risk_score"`                  // ImpactWeight(severity) × confidence, computed by pipeline
	Tags            []string `json:"tags,omitempty"`

	// Lifecycle tracking (populated by ComputeDeltas in main, passed through IPC to external dashboards)
	LifecycleStatus string `json:"lifecycle_status,omitempty"` // "new", "recurring", "fixed"
	SeenCount       int    `json:"seen_count,omitempty"`
	DedupKey        string `json:"dedup_key,omitempty"`        // Stable finding identity
}

// FormatShort returns a one-line summary of the finding.
func (f Finding) FormatShort() string {
	loc := f.FilePath
	if f.LineNumber > 0 {
		loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
	}
	return fmt.Sprintf("[%s] %s: %s (%s)", f.Severity.Icon(), f.RuleID, f.Title, loc)
}

// FormatDetail returns a multi-line detailed description.
func (f Finding) FormatDetail() string {
	result := fmt.Sprintf("[%s] %s: %s\n", f.Severity, f.RuleID, f.Title)
	loc := f.FilePath
	if f.LineNumber > 0 {
		loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
	}
	result += fmt.Sprintf("  File: %s\n", loc)
	if f.MatchedText != "" {
		snippet := f.MatchedText
		if len(snippet) > 120 {
			snippet = snippet[:120] + "..."
		}
		result += fmt.Sprintf("  Match: %s\n", snippet)
	}
	result += fmt.Sprintf("  %s\n", f.Description)
	if f.Suggestion != "" {
		result += fmt.Sprintf("  Fix: %s\n", f.Suggestion)
	}
	if f.CWEID != "" {
		result += fmt.Sprintf("  CWE: %s\n", f.CWEID)
	}
	if f.OWASPCategory != "" {
		result += fmt.Sprintf("  OWASP: %s\n", f.OWASPCategory)
	}
	if f.RiskScore > 0 {
		result += fmt.Sprintf("  Risk: %.0f%%\n", f.RiskScore*100)
	} else if f.ConfidenceScore > 0 {
		result += fmt.Sprintf("  Confidence: %.0f%%\n", f.ConfidenceScore*100)
	}
	return result
}

// ShouldBlock returns true if this individual finding warrants blocking a write.
// Uses RiskScore (ImpactWeight × Confidence) >= 0.7 as the single threshold.
// This means High-severity findings with strong multi-layer confirmation can
// block, while Critical regex-only findings (low confidence) become hints.
func (f Finding) ShouldBlock() bool {
	return f.RiskScore >= 0.7
}

// SyncConfidenceString updates the Confidence string label to match
// the computed ConfidenceScore.
func (f *Finding) SyncConfidenceString() {
	switch {
	case f.ConfidenceScore >= 0.7:
		f.Confidence = "high"
	case f.ConfidenceScore >= 0.4:
		f.Confidence = "medium"
	default:
		f.Confidence = "low"
	}
}

// ScanContext provides all context needed for a rule to analyze code.
type ScanContext struct {
	FilePath string
	Content  string
	Language Language
	IsNew    bool   // true for Write, false for Edit
	OldText  string // for Edit operations, the text being replaced
	NewText  string // for Edit operations, the replacement text

	// Tree is the parsed AST for the file, if available.  It is an
	// interface{} so that rule packages do not need to import the ast
	// package.  Use internal/ast.TreeFromContext(sctx) to obtain the
	// typed *ast.Tree.  May be nil when AST parsing is unavailable or
	// failed.
	Tree interface{}

	// TaintFlows caches the []taint.TaintFlow results from taint
	// analysis so that downstream phases (e.g. hint generation) can
	// reuse them without re-running the engine.  It is an interface{}
	// to avoid import cycles (same pattern as Tree).
	TaintFlows interface{}

	// GoASTFile caches the parsed go/ast result for Go files so that
	// the taint engine (astflow) and call graph builder can share the
	// same parse.  Stored as interface{} to avoid import cycles.
	// The concrete type is *astflow.GoParseResult.
	GoASTFile interface{}
}

// Rule is the interface all vulnerability detection rules must implement.
type Rule interface {
	// ID returns a unique identifier for this rule (e.g., "BATOU-INJ-001").
	ID() string

	// Name returns a human-readable name for the rule.
	Name() string

	// Description returns what this rule detects.
	Description() string

	// Severity returns the default severity of findings from this rule.
	DefaultSeverity() Severity

	// Languages returns which languages this rule applies to.
	// Return a slice containing LangAny to match all languages.
	Languages() []Language

	// Scan analyzes the given context and returns any findings.
	Scan(ctx *ScanContext) []Finding
}

// --- Registry ---

var (
	registry   []Rule
	registryMu sync.Mutex
)

// Register adds a rule to the global registry.
func Register(r Rule) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = append(registry, r)
}

// All returns all registered rules.
func All() []Rule {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// ForLanguage returns all rules applicable to a given language.
func ForLanguage(lang Language) []Rule {
	registryMu.Lock()
	defer registryMu.Unlock()
	var out []Rule
	for _, r := range registry {
		for _, l := range r.Languages() {
			if l == LangAny || l == lang {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// RuleRegistry is a convenience alias for accessing the global registry functions.
type RuleRegistry struct{}

// --- Shared helpers ---

// IsComment returns true if the trimmed line starts with a comment prefix.
func IsComment(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "<!--")
}

// Truncate returns s truncated to maxLen with "..." appended if needed.
func Truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// Browser-only API patterns that indicate frontend JavaScript.
var reFrontendAPIs = regexp.MustCompile(`(?:document\.|window\.|getElementById|addEventListener|innerHTML|\.querySelector|fetch\(|XMLHttpRequest|localStorage|sessionStorage|navigator\.|\.classList|\.style\.)`)

// Server-side patterns that indicate backend JavaScript/TypeScript.
var reServerSideAPIs = regexp.MustCompile(`(?:require\s*\(\s*['"]|import\s+.*from\s+['"](?:express|koa|hapi|fastify|next|pg|mysql|mysql2|sequelize|knex|prisma|typeorm|mongoose|mongodb|redis|ioredis|child_process|fs|path|net|http|https|crypto|os|cluster|worker_threads)['"]|\.getParameter\s*\(|HttpServletRequest|\breq\.(?:query|params|body|headers|cookies)\b|\bres\.(?:send|json|status|setHeader|cookie)\b|\bapp\.(?:get|post|put|delete|use|listen)\s*\(|\bexpress\s*\(\)|module\.exports|process\.env)`)

// IsFrontendJS returns true if a JS/TS file is browser-side code
// (contains browser-only APIs and no server-side patterns).
// Only meaningful for LangJavaScript and LangTypeScript.
func IsFrontendJS(ctx *ScanContext) bool {
	if ctx.Language != LangJavaScript && ctx.Language != LangTypeScript {
		return false
	}
	return reFrontendAPIs.MatchString(ctx.Content) && !reServerSideAPIs.MatchString(ctx.Content)
}

// IsServerSideCode returns true if the file contains server-side patterns
// (server framework imports, HTTP handler patterns, DB libraries).
// For non-JS/TS languages, always returns true.
func IsServerSideCode(ctx *ScanContext) bool {
	if ctx.Language != LangJavaScript && ctx.Language != LangTypeScript {
		return true
	}
	return reServerSideAPIs.MatchString(ctx.Content)
}

// Common HTML escape/sanitizer function names recognised across rules.
var reHTMLSanitizer = regexp.MustCompile(`(?i)\b(?:escapeHtml|escapeHTML|htmlEscape|sanitize|sanitizeHTML|sanitizeHtml|encode|encodeHTML|xssFilter|purify|DOMPurify\.sanitize|cleanHTML|clean_html|bleach\.clean|html\.escape|cgi\.escape|markupsafe\.escape|htmlspecialchars|htmlentities|strip_tags|HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml|Encode\.forHtml|ESAPI\.encoder)\b`)

// HasHTMLSanitizer returns true if the file defines or calls a known
// HTML escape / sanitiser function.
func HasHTMLSanitizer(content string) bool {
	return reHTMLSanitizer.MatchString(content)
}

// --- RegexRule: data-driven rule for simple regex-per-line scanning ---

// RegexRule implements the Rule interface for rules that scan line-by-line
// against a set of regex patterns and emit a static finding per match.
// This eliminates boilerplate for the majority of rules.
type RegexRule struct {
	RuleID   string
	RuleName string
	Desc     string
	Sev      Severity
	Langs    []Language
	Patterns []*regexp.Regexp

	// Finding metadata (static per rule).
	Title      string
	FindDesc   string
	Fix        string
	CWE        string
	OWASP      string
	Conf       string
	RuleTags   []string
}

func (r *RegexRule) ID() string              { return r.RuleID }
func (r *RegexRule) Name() string            { return r.RuleName }
func (r *RegexRule) Description() string     { return r.Desc }
func (r *RegexRule) DefaultSeverity() Severity { return r.Sev }
func (r *RegexRule) Languages() []Language   { return r.Langs }

func (r *RegexRule) Scan(ctx *ScanContext) []Finding {
	var findings []Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if IsComment(trimmed) {
			continue
		}
		for _, re := range r.Patterns {
			if m := re.FindString(line); m != "" {
				findings = append(findings, Finding{
					RuleID:        r.RuleID,
					Severity:      r.Sev,
					SeverityLabel: r.Sev.String(),
					Title:         r.Title,
					Description:   r.FindDesc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   Truncate(m, 120),
					Suggestion:    r.Fix,
					CWEID:         r.CWE,
					OWASPCategory: r.OWASP,
					Language:      ctx.Language,
					Confidence:    r.Conf,
					Tags:          r.RuleTags,
				})
				break
			}
		}
	}
	return findings
}

// CategoryForRule returns the suppress/hint category for a rule ID.
// This is the single source of truth — used by both suppress and hints.
//
// Contains-based matches are checked first (order matters: longer prefixes
// like OAUTH before shorter ones like AUTH). Prefix-based matches use a
// map for language-specific and framework rules.
func CategoryForRule(ruleID string) string {
	upper := strings.ToUpper(ruleID)

	// Taint rules: use the sink name as the category.
	// e.g. BATOU-TAINT-sql_query → "sql_query", BATOU-TAINT-file_write → "file_write"
	if strings.HasPrefix(upper, "BATOU-TAINT-") {
		return strings.ToLower(strings.TrimPrefix(ruleID, "BATOU-TAINT-"))
	}

	// Prefix-based matches (order-independent, checked via map).
	for prefix, cat := range rulePrefixCategory {
		if strings.HasPrefix(upper, prefix) {
			return cat
		}
	}

	// Contains-based matches (order matters — longer substrings first).
	for _, m := range ruleContainsCategory {
		if strings.Contains(upper, m.substr) {
			return m.category
		}
	}

	return "general"
}

// ruleContainsCategory maps substrings to categories. Order matters:
// longer/more-specific substrings must come before shorter ones
// (e.g. OAUTH before AUTH, NOSQL before SQL, MISCONF before MISC).
var ruleContainsCategory = []struct {
	substr   string
	category string
}{
	{"OAUTH", "oauth"},
	{"NOSQL", "injection"},
	{"MISCONF", "misconfig"},
	{"INTERPROC", "interprocedural"},
	{"INJ", "injection"},
	{"XSS", "xss"},
	{"SEC", "secrets"},
	{"CRY", "crypto"},
	{"TRV", "traversal"},
	{"AUTH", "auth"},
	{"SSRF", "ssrf"},
	{"DESER", "deserialize"},
	{"REDIR", "redirect"},
	{"XXE", "xxe"},
	{"CORS", "cors"},
	{"LOG", "logging"},
	{"MEM", "memory"},
	{"PROTO", "prototype"},
	{"MASS", "massassign"},
	{"GQL", "graphql"},
	{"JWT", "jwt"},
	{"SESS", "session"},
	{"RACE", "race"},
	{"SSTI", "ssti"},
	{"UPLOAD", "upload"},
	{"VAL", "validation"},
	{"HDR", "header"},
	{"ENC", "encoding"},
	{"WS", "websocket"},
	{"MISC", "misconfig"},
	{"GEN", "general"},
}

// rulePrefixCategory maps rule ID prefixes to categories.
// Taint rules use the sink name as the category (e.g. BATOU-TAINT-sql_query → "sql_query").
// Framework and language-specific rules use their own categories.
var rulePrefixCategory = map[string]string{
	"BATOU-FW-":    "framework",
	"BATOU-GO-":    "golang",
	"BATOU-PY-":    "python",
	"BATOU-PYAST-": "python",
	"BATOU-JSTS-":  "jsts",
	"BATOU-JAVA-":  "java",
	"BATOU-PHP-":   "php",
	"BATOU-RB-":    "ruby",
	"BATOU-RS-":    "rust",
	"BATOU-CS-":    "csharp",
	"BATOU-KT-":    "kotlin",
	"BATOU-SWIFT-": "swift",
	"BATOU-LUA-":   "lua",
	"BATOU-PL-":    "perl",
	"BATOU-GVY-":   "groovy",
	"BATOU-ZIG-":   "zig",
	"BATOU-CTR-":   "container",
}
