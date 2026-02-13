package rules

import (
	"fmt"
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
	Confidence    string   `json:"confidence"` // high, medium, low
	Tags          []string `json:"tags,omitempty"`
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
	return result
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
}

// Rule is the interface all vulnerability detection rules must implement.
type Rule interface {
	// ID returns a unique identifier for this rule (e.g., "GTSS-INJ-001").
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
