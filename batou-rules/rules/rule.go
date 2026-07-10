package rules

import (
	"fmt"
	"regexp"
	"regexp/syntax"
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

// TaintStep is one node in a finding's source→sink data-flow path.
//
// A sequence of TaintSteps describes how untrusted data travels from where
// it entered the program (Kind "source") through any number of intermediate
// assignments / argument passes (Kind "propagation"), past a bypassed
// sanitizer if present (Kind "sanitizer-bypassed"), to the dangerous call
// that consumes it (Kind "sink"). For interprocedural findings the path
// spans multiple files, so each step records its own File.
//
// The field set is deliberately a superset of what SARIF's threadFlow
// locations need (physicalLocation.artifactLocation.uri = File,
// region.startLine = Line, region.startColumn = Column, message.text =
// Label, region.snippet.text = Snippet) so that emitting SARIF codeFlows
// later is a mechanical mapping.
type TaintStep struct {
	File    string `json:"file"` // may differ from Finding.FilePath for interprocedural paths
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Kind    string `json:"kind"`              // "source" | "propagation" | "sanitizer-bypassed" | "sink"
	Label   string `json:"label"`             // e.g. "request.args.get('id')" / "assigned to query" / "passed to buildQuery(id)" / "cursor.execute(query)"
	Snippet string `json:"snippet,omitempty"` // optional one-line code excerpt
}

// TaintStep.Kind constants.
const (
	TaintStepSource            = "source"
	TaintStepPropagation       = "propagation"
	TaintStepSanitizerBypassed = "sanitizer-bypassed"
	TaintStepSink              = "sink"
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

	// Advisory / AdvisoryID carry a published security advisory citation for
	// "dependency dataflow-reachability" findings (BATOU-DEPVULN-*): untrusted
	// data reaching a library function with a known CVE/GHSA. Advisory is the
	// human-readable citation (e.g. "CVE-2021-44228 (Log4Shell) — ...");
	// AdvisoryID is the bare identifier(s) (e.g. "CVE-2021-44228"). Empty for
	// all other findings.
	Advisory   string `json:"advisory,omitempty"`
	AdvisoryID string `json:"advisory_id,omitempty"`

	Confidence      string   `json:"confidence"`       // high, medium, low
	ConfidenceScore float64  `json:"confidence_score"` // 0.0-1.0, computed by pipeline
	RiskScore       float64  `json:"risk_score"`       // ImpactWeight(severity) × confidence, computed by pipeline
	Tags            []string `json:"tags,omitempty"`

	// TaintPath is the structured source→sink data-flow path for taint and
	// interprocedural findings. Empty for regex/AST findings that don't
	// model dataflow. MatchedText carries a lossy textual rendering of the
	// same path for back-compat; TaintPath is the canonical form.
	TaintPath []TaintStep `json:"taint_path,omitempty"`

	// SourceCategory / SinkCategory are the taint source/sink classifiers
	// (e.g. "user_input" / "sql_query") for taint and interprocedural
	// findings. Empty for regex/AST findings. Used as cheap triage fields
	// in the `batou scan` JSONL output. The values mirror taint.SourceCategory
	// and taint.SinkCategory but are stored as strings here to avoid a
	// dependency cycle between batou-rules and batou-core/taint.
	SourceCategory string `json:"source_category,omitempty"`
	SinkCategory   string `json:"sink_category,omitempty"`

	// Lifecycle tracking (populated by ComputeDeltas in main, passed through to downstream consumers)
	LifecycleStatus string `json:"lifecycle_status,omitempty"` // "new", "recurring", "fixed"
	SeenCount       int    `json:"seen_count,omitempty"`
	DedupKey        string `json:"dedup_key,omitempty"` // Stable finding identity

	// SuppressReason carries the developer's stated justification from the
	// `batou:ignore <target> -- reason` directive that suppressed this finding.
	// Populated by the scanner only on suppressed findings (the ones in
	// reporter.ScanResult.SuppressedFindings); empty when the covering
	// directive carried no `-- reason`, and always empty on active findings.
	// Preserved here so the audit trail (findings store, ledger) records the
	// per-directive rationale instead of a generic "batou:ignore" marker.
	SuppressReason string `json:"suppress_reason,omitempty"`

	// RolledUp marks BATOU-INTERPROC-* findings that share the same leaf
	// sink (file + line + rule_id) as another, already-surfaced finding.
	// The first N (default 10) entries per group keep RolledUp=false; the
	// rest are tagged true. The underlying analysis output is NOT dropped
	// — every distinct flow stays in the JSONL stream so downstream
	// consumers (UI, batou findings command, CI gates) can choose to hide
	// the rolled-up duplicates by default and surface them on demand
	// (--rolled-up-include). This collapses middleware-chain explosion
	// (many callers funnelling the same flow into one leaf sink) without
	// losing recall.
	RolledUp bool `json:"rolled_up,omitempty"`
}

// FormatTaintPath renders a finding's TaintPath as a readable multi-line
// chain (one indented line per step). Returns "" when the path is empty.
// Used by the reporter and hint generator so the rendering is consistent.
func (f Finding) FormatTaintPath() string {
	if len(f.TaintPath) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("  Data-flow path:\n")
	for _, s := range f.TaintPath {
		loc := s.File
		if s.Line > 0 {
			loc = fmt.Sprintf("%s:%d", s.File, s.Line)
		}
		var role string
		switch s.Kind {
		case TaintStepSource:
			role = "source: "
		case TaintStepSink:
			role = "sink: "
		case TaintStepSanitizerBypassed:
			role = "bypassed sanitizer: "
		default:
			role = ""
		}
		fmt.Fprintf(&b, "    → %-28s %s%s", loc, role, s.Label)
		if s.Kind == TaintStepSink && f.CWEID != "" {
			fmt.Fprintf(&b, "   ⟵ %s", f.CWEID)
		}
		b.WriteString("\n")
	}
	return b.String()
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
	if path := f.FormatTaintPath(); path != "" {
		result += path
	} else if f.MatchedText != "" {
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
	// Lines is Content pre-split on "\n", computed once per file by the
	// scanner so the ~684 line-oriented rules don't each re-split the whole
	// file (the dominant heap allocator in profiling). May be nil when the
	// scanner did not populate it (callers must fall back to strings.Split).
	Lines []string
	// LinesLower is Lines with each line lowercased, computed once per file by
	// the scanner so the fold-aware line pre-gate (Prefilter.MightMatch /
	// rules.LineMightMatch) lowercases each line ONCE instead of once per
	// (?i) pattern. Same lifecycle and read-only contract as Lines; may be nil
	// when the scanner did not populate it (callers fall back via LowerLines()).
	LinesLower []string
	// ContentLower is Content lowercased, computed once per file by the scanner
	// (before the rule goroutines fan out, same lifecycle and read-only contract
	// as Lines/LinesLower). Hand-written rules guard their per-file early-exit
	// checks — `re.MatchString(ctx.Content)` over the whole file string, the
	// dominant remaining (?i) regex cost after the per-line gate — with the
	// fold-aware file pre-gate against this once-lowered content (via
	// rules.GMatchFile), instead of re-lowering per guard. May be nil when the
	// scanner did not populate it (callers fall back via ContentLower()).
	ContentLower string
	Language     Language
	IsNew        bool   // true for Write, false for Edit
	OldText      string // for Edit operations, the text being replaced
	NewText      string // for Edit operations, the replacement text

	// OriginalContent is the raw file content BEFORE Python/Shell/C
	// multi-line continuation joining. AST analyzers should use this when
	// they need to align their AST line numbers (which come from the
	// original source) with line-by-line helpers like PySinkVarIsSafe.
	// When preprocessing was a no-op for this language, this equals
	// Content.
	OriginalContent string

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

// SplitLines returns Content split on "\n". It reuses the scanner-populated
// Lines slice when available (the common case in the scan pipeline) so the
// hundreds of line-oriented rules don't each re-split the whole file —
// strings.Split on Content was the single largest heap allocator in
// profiling. When Lines is nil (standalone/test callers), it splits on
// demand. The scanner populates Lines before fanning out the rule goroutines,
// so reads here are race-free; the returned slice is shared and MUST NOT be
// mutated by callers.
func (c *ScanContext) SplitLines() []string {
	if c.Lines != nil {
		return c.Lines
	}
	return strings.Split(c.Content, "\n")
}

// LowerContent returns Content lowercased, reusing the scanner-populated
// ContentLower when available (the common case in the scan pipeline) so a rule's
// whole-file early-exit guards don't re-lower the file. When ContentLower is nil
// (standalone/test callers, which run single-threaded), it lowers on demand. The
// scanner populates ContentLower before fanning out the rule goroutines, so
// reads here are race-free; the returned string is shared and read-only.
func (c *ScanContext) LowerContent() string {
	if c.ContentLower != "" {
		return c.ContentLower
	}
	if c.Content == "" {
		return ""
	}
	return strings.ToLower(c.Content)
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
	forLangCache.Range(func(k, _ any) bool { forLangCache.Delete(k); return true })
}

// forLangCache memoizes ForLanguage's per-language rule slice. The registry is
// static after init(), so the applicable-rule list need not be rebuilt (and
// re-locked) for every file. Invalidated on Register so dynamic registration
// (tests) still sees new rules.
var forLangCache sync.Map // Language -> []Rule

// All returns all registered rules.
func All() []Rule {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// ForLanguage returns all rules applicable to a given language. The result is
// memoized per language (the registry is static after init); callers must treat
// the returned slice as read-only.
func ForLanguage(lang Language) []Rule {
	if v, ok := forLangCache.Load(lang); ok {
		return v.([]Rule)
	}
	registryMu.Lock()
	var out []Rule
	for _, r := range registry {
		for _, l := range r.Languages() {
			if l == LangAny || l == lang {
				out = append(out, r)
				break
			}
		}
	}
	registryMu.Unlock()
	forLangCache.Store(lang, out)
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
	return GMatchFile(reFrontendAPIs, ctx) && !GMatchFile(reServerSideAPIs, ctx)
}

// IsServerSideCode returns true if the file contains server-side patterns
// (server framework imports, HTTP handler patterns, DB libraries).
// For non-JS/TS languages, always returns true.
func IsServerSideCode(ctx *ScanContext) bool {
	if ctx.Language != LangJavaScript && ctx.Language != LangTypeScript {
		return true
	}
	return GMatchFile(reServerSideAPIs, ctx)
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
	Title    string
	FindDesc string
	Fix      string
	CWE      string
	OWASP    string
	Conf     string
	RuleTags []string

	// litOnce/prefilters memoize, per pattern, a fold-aware required-literal
	// AND-of-OR set (Prefilter) that MUST be satisfied by any match (computed
	// from the pattern's syntax tree). Used as a cheap pre-filter: if a
	// pattern's required literals are absent from a (lowercased) line, the RE2
	// engine — the dominant CPU cost — is skipped. Unlike a case-sensitive
	// single-literal filter, this lowercases all literals so it gates (?i)
	// patterns too, and understands alternation. An always-run Prefilter (empty
	// Groups) means the pattern is never skipped. Read-only after the sync.Once.
	litOnce    sync.Once
	prefilters []*Prefilter
}

func (r *RegexRule) ID() string                { return r.RuleID }
func (r *RegexRule) Name() string              { return r.RuleName }
func (r *RegexRule) Description() string       { return r.Desc }
func (r *RegexRule) DefaultSeverity() Severity { return r.Sev }
func (r *RegexRule) Languages() []Language     { return r.Langs }

func (r *RegexRule) Scan(ctx *ScanContext) []Finding {
	r.litOnce.Do(r.initLits)

	// File-level literal pre-filter: if every pattern has a required literal
	// set and no group is satisfiable anywhere in the (lowercased) file, the
	// rule cannot match — skip the whole line scan. Fold-aware and exact: a
	// required literal must appear in any match.
	contentLower := strings.ToLower(ctx.Content)
	if !r.anyCandidate(contentLower) {
		return nil
	}

	var findings []Finding
	lines := ctx.Lines // shared split populated by the scanner (avoids re-splitting per rule)
	if lines == nil {
		lines = ctx.SplitLines()
	}
	lowered := ctx.LinesLower // shared lowercased split (avoids re-lowering per rule)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if IsComment(trimmed) {
			continue
		}
		var lower string
		if lowered != nil {
			lower = lowered[i]
		} else {
			lower = strings.ToLower(line)
		}
		for pi, re := range r.Patterns {
			// Per-line fold-aware OR-set pre-filter: skip the (backtracking)
			// regex on lines that can't contain a match because a required
			// literal group is unsatisfied. Cheap strings.Contains on the
			// pre-lowered line vs expensive FindString.
			if !r.prefilters[pi].MightMatch(lower) {
				continue
			}
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

// initLits computes the per-pattern fold-aware required-literal pre-filter
// (called once).
func (r *RegexRule) initLits() {
	r.prefilters = make([]*Prefilter, len(r.Patterns))
	for i, re := range r.Patterns {
		r.prefilters[i] = CompilePrefilter(re.String())
	}
}

// anyCandidate reports whether any pattern could match the file: true if a
// pattern has no usable required-literal set (always a candidate) or all of its
// required-literal groups are satisfiable somewhere in the lowercased content.
func (r *RegexRule) anyCandidate(contentLower string) bool {
	for pi := range r.Patterns {
		if r.prefilters[pi].alwaysRun() || r.prefilters[pi].MightMatch(contentLower) {
			return true
		}
	}
	return false
}

// minGateLit is the minimum length a literal must have to be useful as a
// pre-filter element. Sub-3-char literals are so common (e.g. "(", "=", a
// folded single letter) that gating on them rarely skips a line, so they are
// dropped — the conservative effect is "always run", never a missed match.
const minGateLit = 3

// Prefilter is a line-level pre-gate for a single regex pattern. It holds an
// AND-of-OR set of required, lowercased literals: for every group, any string
// the pattern matches contains at least one of the group's elements. A lowered
// line is therefore a *candidate* iff every group has at least one element
// present; if any group has none present, the regex provably cannot match and
// is skipped. An empty Groups means "no usable constraint" → always a candidate
// (the pattern always runs, never a missed finding).
//
// This is the fold-aware generalisation of requiredLiteral: it lowercases all
// literals (so (?i) patterns gate too) and it understands OpAlternate (the gate
// for a top-level alternation is the union of its branches' required literals,
// usable only when *every* branch contributes one).
type Prefilter struct {
	Groups [][]string // AND of OR-sets; all lowercased; nil/empty ⇒ always run
}

// MightMatch reports whether loweredLine could contain a match for the pattern.
// loweredLine MUST already be lowercased by the caller (so the per-file lowering
// is done once, not once per pattern). Returns true (run the regex) when the
// prefilter has no usable constraint. Never returns false when the regex would
// actually match — that is the correctness invariant the unit tests assert.
func (p *Prefilter) MightMatch(loweredLine string) bool {
	for _, group := range p.Groups {
		hit := false
		for _, lit := range group {
			if strings.Contains(loweredLine, lit) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// alwaysRun is true when this prefilter can never skip a line.
func (p *Prefilter) alwaysRun() bool { return len(p.Groups) == 0 }

// prefilterCache memoizes Prefilters by regex source so that hand-written
// rules calling LineMightMatch don't recompile the syntax tree per line. The
// regex String() is a stable key (regexp is immutable after compile).
var prefilterCache sync.Map // string -> *Prefilter

// LineMightMatch reports whether loweredLine could contain a match for re,
// using a cached fold-aware required-literal pre-gate. loweredLine MUST already
// be lowercased by the caller (lowering once per file, not per pattern). It
// returns true (meaning "run re.FindString") whenever the gate is inconclusive,
// so it is always safe to wrap an existing `re.FindString(line)` as:
//
//	if rules.LineMightMatch(lower, re) {
//	    if m := re.FindString(line); m != "" { ... }
//	}
//
// The correctness invariant (unit-tested): LineMightMatch never returns false
// for a line on which re actually matches.
func LineMightMatch(loweredLine string, re *regexp.Regexp) bool {
	src := re.String()
	if v, ok := prefilterCache.Load(src); ok {
		return v.(*Prefilter).MightMatch(loweredLine)
	}
	pf := CompilePrefilter(src)
	prefilterCache.Store(src, pf)
	return pf.MightMatch(loweredLine)
}

// prefilterByPtr caches a *Prefilter per *regexp.Regexp pointer. The bulk
// per-line gate helpers (GFind/GMatch/…) look up by pointer, which is faster
// than the String()-keyed prefilterCache LineMightMatch uses, because these
// helpers sit on the hottest path (one call per pattern per line across ~140
// rules). The pointer is stable for a package-level compiled regex.
var prefilterByPtr sync.Map // *regexp.Regexp -> *Prefilter

func prefilterFor(re *regexp.Regexp) *Prefilter {
	if v, ok := prefilterByPtr.Load(re); ok {
		return v.(*Prefilter)
	}
	pf := CompilePrefilter(re.String())
	prefilterByPtr.Store(re, pf)
	return pf
}

// The GFind/GFindIndex/GFindSubmatch/GMatch helpers are drop-in, gate-first
// replacements for re.FindString(line) / re.FindStringIndex(line) /
// re.FindStringSubmatch(line) / re.MatchString(line). Each first runs the cheap
// fold-aware required-literal pre-gate against a lowercased copy of the line; if
// the gate proves the regex cannot match, it returns the zero value WITHOUT
// invoking the (backtracking) RE2 engine — the dominant scan cost. Because the
// gate never skips a line the regex would actually match (unit-tested
// invariant), substituting these for the bare regexp calls is finding-preserving
// for every rule, with no change to control flow: they are pure expressions, so
// they slot into `if`, `else if`, and `&&` chains unchanged.
//
// They lower the line themselves so call sites need no precomputed
// lowered-line slice in scope — that is what makes the substitution a
// mechanical one across the ~2,000 per-line regex call sites. Lowering is a
// pure O(len) pass (~65ns on a typical line) and is unconditionally far cheaper
// than the backtracking regex it guards (~860ns), so re-lowering per call still
// nets a large win while keeping the helpers stateless and race-free.

// lineMightMatchPtr is the shared gate body: true ⇒ run the regex. It skips the
// strings.ToLower allocation entirely for always-run prefilters (patterns with
// no usable required literal), which neither benefit from gating nor should pay
// the lowering cost. For ASCII-only lines (the overwhelming majority of source)
// it lowers with a cheap allocation-light path.
func lineMightMatchPtr(re *regexp.Regexp, line string) bool {
	pf := prefilterFor(re)
	if pf.alwaysRun() {
		return true
	}
	return pf.MightMatch(toLowerASCII(line))
}

const utf8RuneSelf = 0x80

// toLowerASCII lowercases line. For the common all-ASCII case it avoids the
// unicode machinery in strings.ToLower (and allocates nothing when the line is
// already lowercase); it falls back to strings.ToLower only when a non-ASCII
// byte is present (rare in source code). The result is used solely for
// substring presence checks against ASCII required literals, so the fallback's
// full Unicode folding is a sound superset of what the gate needs.
func toLowerASCII(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8RuneSelf {
			return strings.ToLower(s)
		}
		if 'A' <= c && c <= 'Z' {
			hasUpper = true
		}
	}
	if !hasUpper {
		return s // already lowercase ASCII; no allocation
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// GFind is the gated form of re.FindString(line).
func GFind(re *regexp.Regexp, line string) string {
	if !lineMightMatchPtr(re, line) {
		return ""
	}
	return re.FindString(line)
}

// GFindIndex is the gated form of re.FindStringIndex(line).
func GFindIndex(re *regexp.Regexp, line string) []int {
	if !lineMightMatchPtr(re, line) {
		return nil
	}
	return re.FindStringIndex(line)
}

// GFindSubmatch is the gated form of re.FindStringSubmatch(line).
func GFindSubmatch(re *regexp.Regexp, line string) []string {
	if !lineMightMatchPtr(re, line) {
		return nil
	}
	return re.FindStringSubmatch(line)
}

// GMatch is the gated form of re.MatchString(line).
func GMatch(re *regexp.Regexp, line string) bool {
	if !lineMightMatchPtr(re, line) {
		return false
	}
	return re.MatchString(line)
}

// lineMightMatchPtrLower is lineMightMatchPtr for a caller that already holds the
// lowercased line (e.g. ScanContext.LinesLower[i], lowered once per file by the
// scanner). It uses the same pointer-keyed prefilter as the GFind* helpers but
// skips the per-call toLowerASCII pass — the line is lowered once per file
// instead of once per (pattern × line). loweredLine MUST be the lowercase form
// of line.
func lineMightMatchPtrLower(re *regexp.Regexp, loweredLine string) bool {
	pf := prefilterFor(re)
	if pf.alwaysRun() {
		return true
	}
	return pf.MightMatch(loweredLine)
}

// The GFind*Lower helpers are the shared-lowered-line counterparts of the
// GFind* helpers: identical gate, identical regex, but the caller supplies the
// already-lowercased line so the gate does not re-lower per call. They are
// finding-identical drop-ins for the GFind* family inside a per-line loop that
// has ScanContext.LinesLower in scope:
//
//	lowered := ctx.LowerLines()
//	for i, line := range lines {
//	    lo := lowered[i]
//	    if loc := rules.GFindIndexLower(re, line, lo); loc != nil { ... }
//	}
//
// loweredLine MUST equal toLowerASCII(line) (which is what ctx.LinesLower holds,
// via strings.ToLower — a superset fold of the ASCII-only required literals the
// gate checks). Passing anything else can only suppress a real match, never
// invent one, so the contract is "pass the shared lowered line". The correctness
// invariant is the same as the GFind* family: the gate never skips a line the
// regex would actually match.

// GFindLower is GFind with a caller-supplied lowercased line.
func GFindLower(re *regexp.Regexp, line, loweredLine string) string {
	if !lineMightMatchPtrLower(re, loweredLine) {
		return ""
	}
	return re.FindString(line)
}

// GFindIndexLower is GFindIndex with a caller-supplied lowercased line.
func GFindIndexLower(re *regexp.Regexp, line, loweredLine string) []int {
	if !lineMightMatchPtrLower(re, loweredLine) {
		return nil
	}
	return re.FindStringIndex(line)
}

// GFindSubmatchLower is GFindSubmatch with a caller-supplied lowercased line.
func GFindSubmatchLower(re *regexp.Regexp, line, loweredLine string) []string {
	if !lineMightMatchPtrLower(re, loweredLine) {
		return nil
	}
	return re.FindStringSubmatch(line)
}

// GMatchLower is GMatch with a caller-supplied lowercased line.
func GMatchLower(re *regexp.Regexp, line, loweredLine string) bool {
	if !lineMightMatchPtrLower(re, loweredLine) {
		return false
	}
	return re.MatchString(line)
}

// FileMightMatch reports whether re could match anywhere in loweredContent,
// using the same pointer-keyed fold-aware required-literal prefilter as the
// GFind* helpers. loweredContent MUST be strings.ToLower of the file content the
// guard would scan. It is the whole-file analogue of lineMightMatchPtrLower: a
// gate for the `re.MatchString(ctx.Content)` early-exit guards that hand-written
// rules use to decide whether to enter their per-line loop. Callers lower the
// content once per file and reuse the result across every guard. Returns true
// (run the regex) whenever the gate is inconclusive, so it never suppresses a
// match the regex would find.
func FileMightMatch(re *regexp.Regexp, loweredContent string) bool {
	pf := prefilterFor(re)
	if pf.alwaysRun() {
		return true
	}
	return pf.MightMatch(loweredContent)
}

// GMatchFile is the gated form of re.MatchString(ctx.Content): the whole-file
// early-exit guard that hand-written rules use to decide whether to enter their
// per-line loop. It first runs the cheap fold-aware required-literal pre-gate
// against ctx.LowerContent() (the file lowered once by the scanner); only if the
// gate is satisfiable does it run the (backtracking, (?i)-folding) regex over the
// whole file. Because the gate never skips content the regex would actually
// match (the same correctness invariant the GFind* family carries), substituting
// GMatchFile(re, ctx) for re.MatchString(ctx.Content) is finding-identical. It is
// a pure expression, so it slots into `if`, `!`, `&&`, and `||` chains unchanged.
func GMatchFile(re *regexp.Regexp, ctx *ScanContext) bool {
	if !FileMightMatch(re, ctx.LowerContent()) {
		return false
	}
	return re.MatchString(ctx.Content)
}

// GFindAllSubmatch is the gated form of re.FindAllStringSubmatch(line, n).
// When the fold-aware pre-gate proves the regex cannot match the line it returns
// nil — the same zero value FindAllStringSubmatch returns for no match — without
// invoking the backtracking engine. Because the gate never skips a line the
// regex actually matches (unit-tested invariant), substituting it for the bare
// call is finding-preserving.
func GFindAllSubmatch(re *regexp.Regexp, line string, n int) [][]string {
	if !lineMightMatchPtr(re, line) {
		return nil
	}
	return re.FindAllStringSubmatch(line, n)
}

// GFindAllIndex is the gated form of re.FindAllStringIndex(line, n). It returns
// nil (FindAllStringIndex's no-match zero value) when the pre-gate proves no
// match is possible, skipping the regex engine.
func GFindAllIndex(re *regexp.Regexp, line string, n int) [][]int {
	if !lineMightMatchPtr(re, line) {
		return nil
	}
	return re.FindAllStringIndex(line, n)
}

// LowerLines returns ctx.LinesLower when populated, else lowercases ctx's lines
// on the fly. Hand-written rules call this once at the top of Scan and index
// the result by line number alongside the original lines.
func (c *ScanContext) LowerLines() []string {
	if c.LinesLower != nil {
		return c.LinesLower
	}
	lines := c.SplitLines()
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = strings.ToLower(l)
	}
	return out
}

// CompilePrefilter builds a fold-aware line pre-gate for the given pattern.
// On any parse error it returns an always-run prefilter (safe default).
func CompilePrefilter(pattern string) *Prefilter {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return &Prefilter{}
	}
	re = re.Simplify()
	groups := requiredLitGroupsFold(re)
	// Keep only groups whose *every* element is long enough to be useful. A
	// group with any too-short element would force a possible wrong skip through
	// that short branch, so we drop the whole group → conservative "always run"
	// for that node.
	out := groups[:0]
	for _, g := range groups {
		if usableGroup(g) {
			out = append(out, g)
		}
	}
	return &Prefilter{Groups: out}
}

// usableGroup reports whether every element of an OR-group is long enough to
// gate on. If any element is too short, the group cannot be used as a gate
// (skipping would risk dropping a match through the short branch), so the whole
// group is discarded by the caller.
func usableGroup(g []string) bool {
	if len(g) == 0 {
		return false
	}
	for _, lit := range g {
		if len(lit) < minGateLit {
			return false
		}
	}
	return true
}

// anyUsableGroup reports whether at least one of the AND-of-OR groups is usable
// as a gate on its own.
func anyUsableGroup(groups [][]string) bool {
	for _, g := range groups {
		if usableGroup(g) {
			return true
		}
	}
	return false
}

// requiredLitGroupsFold returns the fold-aware AND-of-OR required-literal
// groups for r. Semantics: for every returned group, any string matched by r
// contains ≥1 element of that group (all elements lowercased). A nil result
// means "no usable required-literal constraint for this node".
//
// Construction per Op:
//   - OpLiteral: one group = the single lowercased literal (fold-aware: the
//     case-folded form is lowercased so it gates an (?i) line).
//   - OpConcat: the union (AND) of every child's groups — every forced run must
//     appear, so each child group independently constrains the match.
//   - OpCapture / OpPlus: the child's groups (the sub is required ≥ once).
//   - OpAlternate: a *single* group = the union of one representative
//     required-literal per branch, valid ONLY when every branch yields at least
//     one usable literal. If any branch has none, the alternation is
//     unconstrained → nil.
//   - everything else (star, quest, char-class, anchors, …): nil.
func requiredLitGroupsFold(r *syntax.Regexp) [][]string {
	switch r.Op {
	case syntax.OpLiteral:
		return [][]string{{strings.ToLower(string(r.Rune))}}

	case syntax.OpConcat:
		// Coalesce adjacent literals into runs first (so "os" + "." gates on
		// "os." not just "os"), then AND-union every child's groups.
		var groups [][]string
		var cur []rune
		flush := func() {
			if len(cur) > 0 {
				groups = append(groups, []string{strings.ToLower(string(cur))})
				cur = nil
			}
		}
		for _, sub := range r.Sub {
			if sub.Op == syntax.OpLiteral {
				cur = append(cur, sub.Rune...)
				continue
			}
			flush()
			groups = append(groups, requiredLitGroupsFold(sub)...)
		}
		flush()
		// If no individual coalesced group is usable on its own, the concat may
		// still be gateable as a whole: Go prefix/suffix-factors alternations like
		// "security|ssl|server" into Concat[S, Alt[ECURITY, SL, ERVER]], where the
		// shared run "S" and the inner fragments are each too short alone but
		// recombine into the usable OR-set {security, ssl, server}. Distribute the
		// forced literal runs across the concat to recover it. Sound because every
		// cross-product element is a substring forced to appear contiguously in any
		// match. Only used as a fallback so the (cheaper, more-selective) per-child
		// AND-of-OR groups still win when they are usable.
		if !anyUsableGroup(groups) {
			if set, ok := forcedConcatLiteralSet(r); ok && usableGroup(set) {
				return [][]string{set}
			}
		}
		return groups

	case syntax.OpCapture:
		return requiredLitGroupsFold(r.Sub[0])

	case syntax.OpPlus:
		return requiredLitGroupsFold(r.Sub[0])

	case syntax.OpAlternate:
		// Union of each branch's forced-literal OR-set. Every branch MUST yield a
		// usable OR-set (≥1 element, each ≥ minGateLit) such that any match of the
		// branch contains one of them; otherwise that branch could match with no
		// fixed literal and the alternation as a whole cannot be gated → nil.
		//
		// A branch's OR-set is the set of full literal strings any of its matches
		// must contain. For a plain literal branch this is {lit}. For a branch that
		// Go's regexp/syntax has prefix/suffix-factored — e.g. "security|ssl"
		// simplifies to Concat[S, Alt[ECURITY, SL]] — branchLiteralSet distributes
		// the shared literal run into the nested alternation, recovering
		// {security, ssl}. Without that distribution such branches would yield only
		// the sub-3-char fragments ("s", "sl") and silently disable the entire
		// gate, which is exactly what defeated the (?i) disabled-security and
		// skip-verify rules (the dominant C/C++ regex cost on real repos).
		var union []string
		seen := map[string]struct{}{}
		for _, branch := range r.Sub {
			set := branchLiteralSet(branch)
			if !usableGroup(set) {
				return nil // unconstrained branch ⇒ whole alternation unconstrained
			}
			for _, lit := range set {
				if _, ok := seen[lit]; !ok {
					seen[lit] = struct{}{}
					union = append(union, lit)
				}
			}
		}
		if len(union) == 0 {
			return nil
		}
		return [][]string{union}
	}
	return nil
}

// branchLitSetCap bounds the cross-product size while distributing shared
// literal runs into nested alternations (e.g. a 3-way × 3-way factoring stays
// at 9). Past the cap, branchLiteralSet falls back to its AND-of-OR groups (a
// looser but still-sound gate) so a pathological branch can never blow up
// prefilter compilation.
const branchLitSetCap = 64

// branchLiteralSet returns a lowercased OR-set of full literal strings such that
// *every* match of branch contains at least one element of the set, or nil when
// no such usable set exists. It is the OR-set generalisation of the old
// single-literal branchRepresentative: a plain literal branch yields {lit}, and
// — crucially — a branch that regexp/syntax prefix/suffix-factored into
// Concat[run, Alt[...], run] has the shared run distributed into the alternation
// so the full pre-factoring literals are recovered (security|ssl ⇒ {security,
// ssl}, not the unusable {s}/{sl} fragments).
//
// Correctness: the returned set S satisfies "any string matching branch contains
// ≥1 element of S". For OpConcat this is the bounded cross-product of the
// per-segment forced OR-sets (each cross-product element is a substring forced
// to appear contiguously); if the cross-product is incomplete (a segment has no
// forced literal, or the product exceeds branchLitSetCap) we fall back to the
// single most-selective AND-of-OR group, which is still a sound required set.
func branchLiteralSet(branch *syntax.Regexp) []string {
	if set, ok := forcedConcatLiteralSet(branch); ok && usableGroup(set) {
		return set
	}
	// Fallback: pick the best usable OR-group from the AND-of-OR decomposition.
	// Any single AND-group is independently required, so gating on it is sound.
	var best []string
	for _, g := range requiredLitGroupsFold(branch) {
		if usableGroup(g) && (best == nil || groupMinLen(g) > groupMinLen(best)) {
			best = g
		}
	}
	return best
}

// forcedConcatLiteralSet returns the OR-set of contiguous literal strings forced
// by r (each element guaranteed to appear in any match of r), with ok=false when
// r contains a piece that forces no literal (star/quest/charclass/empty/anchor)
// or the bounded cross-product would exceed branchLitSetCap. The construction
// distributes adjacent literal runs into nested alternations, which is what
// recovers prefix/suffix-factored literals.
func forcedConcatLiteralSet(r *syntax.Regexp) ([]string, bool) {
	switch r.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(r.Rune))}, true

	case syntax.OpCapture, syntax.OpPlus:
		// Captured group / one-or-more: the sub is required at least once.
		return forcedConcatLiteralSet(r.Sub[0])

	case syntax.OpAlternate:
		// Each branch must forcibly contribute a literal; the result is their
		// union (any match goes through one branch, contributing its literal).
		var out []string
		for _, sub := range r.Sub {
			set, ok := forcedConcatLiteralSet(sub)
			if !ok {
				return nil, false
			}
			out = append(out, set...)
			if len(out) > branchLitSetCap {
				return nil, false
			}
		}
		return out, true

	case syntax.OpConcat:
		// Cross-product of each child's forced OR-set, concatenated in order.
		// Every child must force a literal; a single unforced child breaks the
		// contiguity guarantee, so we bail (ok=false) and let the caller fall
		// back to the AND-of-OR group decomposition.
		acc := []string{""}
		for _, sub := range r.Sub {
			set, ok := forcedConcatLiteralSet(sub)
			if !ok {
				return nil, false
			}
			next := make([]string, 0, len(acc)*len(set))
			for _, p := range acc {
				for _, s := range set {
					next = append(next, p+s)
				}
			}
			if len(next) > branchLitSetCap {
				return nil, false
			}
			acc = next
		}
		return acc, true
	}
	return nil, false
}

// groupMinLen is the length of the shortest element of an OR-group, used to
// prefer the more-selective group in branchLiteralSet's fallback path.
func groupMinLen(g []string) int {
	min := -1
	for _, s := range g {
		if min < 0 || len(s) < min {
			min = len(s)
		}
	}
	if min < 0 {
		return 0
	}
	return min
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
	"BATOU-SUPPRESS-": "suppress",
	"BATOU-OWNCLOUD-": "owncloud",
	"BATOU-FW-":       "framework",
	"BATOU-GO-":       "golang",
	"BATOU-PY-":       "python",
	"BATOU-PYAST-":    "python",
	"BATOU-JSTS-":     "jsts",
	"BATOU-JAVA-":     "java",
	"BATOU-PHP-":      "php",
	"BATOU-RB-":       "ruby",
	"BATOU-RS-":       "rust",
	"BATOU-CS-":       "csharp",
	"BATOU-KT-":       "kotlin",
	"BATOU-SWIFT-":    "swift",
	"BATOU-LUA-":      "lua",
	"BATOU-PL-":       "perl",
	"BATOU-GVY-":      "groovy",
	"BATOU-ZIG-":      "zig",
	"BATOU-CTR-":      "container",
}
