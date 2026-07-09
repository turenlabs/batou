// Package testutil provides lightweight test helpers for batou-rules tests.
//
// This package intentionally depends only on batou-rules so rules can be
// tested without importing batou-core.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// ScanResult is a minimal scan wrapper used by rules tests.
type ScanResult struct {
	Findings []rules.Finding
	Blocked  bool
}

var extToLanguage = map[string]rules.Language{
	".go":         rules.LangGo,
	".py":         rules.LangPython,
	".pyw":        rules.LangPython,
	".js":         rules.LangJavaScript,
	".jsx":        rules.LangJavaScript,
	".mjs":        rules.LangJavaScript,
	".cjs":        rules.LangJavaScript,
	".ts":         rules.LangTypeScript,
	".tsx":        rules.LangTypeScript,
	".vue":        rules.LangJavaScript, // Vue SFCs embed JS/TS; mirrors batou-core/analyzer
	".svelte":     rules.LangJavaScript, // Svelte components embed JS/TS
	".mts":        rules.LangTypeScript,
	".java":       rules.LangJava,
	".rb":         rules.LangRuby,
	".erb":        rules.LangRuby,
	".php":        rules.LangPHP,
	".kt":         rules.LangKotlin,
	".kts":        rules.LangKotlin,
	".groovy":     rules.LangGroovy,
	".gvy":        rules.LangGroovy,
	".gy":         rules.LangGroovy,
	".gsh":        rules.LangGroovy,
	".gsp":        rules.LangGroovy,
	"Jenkinsfile": rules.LangGroovy,
	".cs":         rules.LangCSharp,
	".csx":        rules.LangCSharp,
	".swift":      rules.LangSwift,
	".rs":         rules.LangRust,
	".c":          rules.LangC,
	".h":          rules.LangC,
	".cpp":        rules.LangCPP,
	".cc":         rules.LangCPP,
	".cxx":        rules.LangCPP,
	".c++":        rules.LangCPP,
	".hpp":        rules.LangCPP,
	".hh":         rules.LangCPP,
	".hxx":        rules.LangCPP,
	".h++":        rules.LangCPP,
	".pl":         rules.LangPerl,
	".pm":         rules.LangPerl,
	".cgi":        rules.LangPerl,
	".lua":        rules.LangLua,
	".zig":        rules.LangZig,
	".sh":         rules.LangShell,
	".bash":       rules.LangShell,
	".zsh":        rules.LangShell,
	".sql":        rules.LangSQL,
	".yaml":       rules.LangYAML,
	".yml":        rules.LangYAML,
	".json":       rules.LangJSON,
	".tf":         rules.LangTerraform,
	".tfvars":     rules.LangTerraform,
	"Dockerfile":  rules.LangDocker,
	".dockerfile": rules.LangDocker,
}

// ScanContent scans content using registered rules for the inferred language.
func ScanContent(t *testing.T, filePath string, content string) *ScanResult {
	t.Helper()

	lang := detectLanguage(filePath)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = joinContinuationLines(content, lang)

	ctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  content,
		Language: lang,
		IsNew:    true,
	}

	applicable := rules.ForLanguage(lang)
	findings := make([]rules.Finding, 0, 8)
	for _, r := range applicable {
		findings = append(findings, r.Scan(ctx)...)
	}

	return &ScanResult{
		Findings: findings,
		Blocked:  shouldBlock(findings),
	}
}

// ScanFixture loads a fixture and scans it.
func ScanFixture(t *testing.T, fixturePath string) *ScanResult {
	t.Helper()
	content := LoadFixture(t, fixturePath)
	fullPath := filepath.Join(FixtureDir(), fixturePath)
	return ScanContent(t, fullPath, content)
}

// MustFindRule asserts that at least one finding with ruleID exists.
func MustFindRule(t *testing.T, result *ScanResult, ruleID string) {
	t.Helper()
	if !HasFinding(result, ruleID) {
		t.Fatalf("expected finding %q, got: %v", ruleID, FindingRuleIDs(result))
	}
}

// MustFindAnyRule asserts that at least one of ruleIDs exists.
func MustFindAnyRule(t *testing.T, result *ScanResult, ruleIDs ...string) {
	t.Helper()
	for _, id := range ruleIDs {
		if HasFinding(result, id) {
			return
		}
	}
	t.Fatalf("expected any of %v, got: %v", ruleIDs, FindingRuleIDs(result))
}

// MustNotFindRule asserts that no finding with ruleID exists.
func MustNotFindRule(t *testing.T, result *ScanResult, ruleID string) {
	t.Helper()
	if HasFinding(result, ruleID) {
		t.Fatalf("did not expect finding %q, got: %v", ruleID, FindingRuleIDs(result))
	}
}

// AssertMinFindings asserts the scan returns at least n findings.
func AssertMinFindings(t *testing.T, result *ScanResult, n int) {
	t.Helper()
	if len(result.Findings) < n {
		t.Fatalf("expected at least %d findings, got %d", n, len(result.Findings))
	}
}

// HasFinding returns true when ruleID is present.
func HasFinding(result *ScanResult, ruleID string) bool {
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// FindingsByRule filters findings by rule ID.
func FindingsByRule(result *ScanResult, ruleID string) []rules.Finding {
	out := make([]rules.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// FindingRuleIDs returns sorted, unique finding rule IDs.
func FindingRuleIDs(result *ScanResult) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		out = append(out, f.RuleID)
	}
	sort.Strings(out)
	return out
}

// FixtureDir returns the absolute fixtures directory path.
func FixtureDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		abs, err := filepath.Abs("testdata/fixtures")
		if err != nil {
			return "testdata/fixtures"
		}
		return abs
	}
	moduleRoot := filepath.Dir(filepath.Dir(thisFile))
	return filepath.Join(moduleRoot, "testdata", "fixtures")
}

// LoadFixture reads a fixture from testdata/fixtures.
func LoadFixture(t *testing.T, relativePath string) string {
	t.Helper()
	fullPath := filepath.Join(FixtureDir(), relativePath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("failed to load fixture %q: %v", relativePath, err)
	}
	return string(data)
}

// FixtureExists reports whether a fixture exists.
func FixtureExists(relativePath string) bool {
	fullPath := filepath.Join(FixtureDir(), relativePath)
	_, err := os.Stat(fullPath)
	return err == nil
}

func shouldBlock(findings []rules.Finding) bool {
	for _, f := range findings {
		if f.ShouldBlock() {
			return true
		}
	}
	return false
}

func detectLanguage(filePath string) rules.Language {
	base := filepath.Base(filePath)
	if lang, ok := extToLanguage[base]; ok {
		return lang
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := extToLanguage[ext]; ok {
		return lang
	}
	return rules.LangAny
}

func joinContinuationLines(content string, lang rules.Language) string {
	switch lang {
	case rules.LangPython:
		return joinPythonContinuations(content)
	case rules.LangShell, rules.LangC, rules.LangCPP:
		return joinBackslashContinuations(content)
	default:
		return content
	}
}

func joinBackslashContinuations(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var pending string

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			pending += trimmed[:len(trimmed)-1]
			continue
		}
		if pending != "" {
			result = append(result, pending+line)
			pending = ""
			continue
		}
		result = append(result, line)
	}

	if pending != "" {
		result = append(result, pending)
	}
	return strings.Join(result, "\n")
}

func joinPythonContinuations(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var pending string
	depth := 0

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") && depth == 0 {
			pending += trimmed[:len(trimmed)-1]
			continue
		}

		if pending != "" && depth == 0 {
			line = pending + line
			pending = ""
		}

		if depth > 0 {
			pending += " " + strings.TrimSpace(line)
		} else {
			pending = line
		}

		depth += countBracketDelta(line)
		if depth <= 0 {
			depth = 0
			result = append(result, pending)
			pending = ""
		}
	}

	if pending != "" {
		result = append(result, pending)
	}
	return strings.Join(result, "\n")
}

func countBracketDelta(line string) int {
	delta := 0
	inString := false
	stringChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]

		if inString {
			if ch == '\\' && i+1 < len(line) {
				i++
				continue
			}
			if ch == stringChar {
				inString = false
			}
			continue
		}

		switch ch {
		case '"', '\'':
			if i+2 < len(line) && line[i+1] == ch && line[i+2] == ch {
				closer := string([]byte{ch, ch, ch})
				end := strings.Index(line[i+3:], closer)
				if end >= 0 {
					i = i + 3 + end + 2
				} else {
					return delta
				}
				continue
			}
			inString = true
			stringChar = ch
		case '#':
			return delta
		case '(', '[', '{':
			delta++
		case ')', ']', '}':
			delta--
		}
	}
	return delta
}
