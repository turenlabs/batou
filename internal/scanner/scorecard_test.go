package scanner_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/testutil"
)

// TestProductSecurityScorecard produces a comprehensive scorecard comparing
// BATOU-augmented Claude Code vs vanilla Claude Code (no scanner).
//
// Metrics:
//   - Block rate:      Critical findings that prevent code from being written
//   - Warn rate:       High findings that produce hints for Claude to self-correct
//   - Detect rate:     Any severity finding (Claude gets feedback)
//   - Pass-through:    Vulnerable code that ships with zero intervention
//   - FP rate:         Safe code incorrectly flagged
//   - Block FP rate:   Safe code incorrectly blocked (critical FP metric)
//
// Run: go test ./internal/scanner/ -run TestProductSecurityScorecard -v
func TestProductSecurityScorecard(t *testing.T) {
	if !testutil.BenchDirExists() {
		t.Skip("no bench fixtures directory; skipping scorecard")
	}

	vulnFixtures := testutil.BenchFixtures(t)
	safeFixtures := testutil.BenchSafeFixtures(t)

	if len(vulnFixtures) == 0 {
		t.Skip("no vulnerable bench fixtures found")
	}

	// --- Scan vulnerable fixtures ---
	type vulnResult struct {
		fixture   testutil.BenchFixture
		findings  []rules.Finding
		maxSev    rules.Severity
		blocked   bool
		warned    bool
		detected  bool
		owasp     string
		ruleIDs   []string
	}

	var vulnResults []vulnResult
	for _, fix := range vulnFixtures {
		scanPath := "/app/bench_target" + filepath.Ext(fix.FileName)
		result := testutil.ScanContent(t, scanPath, fix.Content)

		vr := vulnResult{
			fixture:  fix,
			findings: result.Findings,
			blocked:  result.Blocked,
			owasp:    inferOWASPFromFilename(fix.FileName),
		}

		for _, f := range result.Findings {
			vr.ruleIDs = append(vr.ruleIDs, f.RuleID)
			if f.Severity > vr.maxSev {
				vr.maxSev = f.Severity
			}
		}

		vr.detected = len(result.Findings) > 0
		vr.warned = vr.maxSev >= rules.High
		// blocked is already set from result.Blocked

		vulnResults = append(vulnResults, vr)
	}

	// --- Scan safe fixtures ---
	type safeResult struct {
		fixture  testutil.BenchFixture
		findings []rules.Finding
		blocked  bool
		fpCount  int // findings > Low
	}

	var safeResults []safeResult
	for _, fix := range safeFixtures {
		fakePath, ok := langToFakePath[fix.Lang]
		if !ok {
			fakePath = "/app/handler" + filepath.Ext(fix.FileName)
		}
		result := testutil.ScanContent(t, fakePath, fix.Content)

		sr := safeResult{
			fixture:  fix,
			findings: result.Findings,
			blocked:  result.Blocked,
		}
		for _, f := range result.Findings {
			if f.Severity > rules.Low {
				sr.fpCount++
			}
		}
		safeResults = append(safeResults, sr)
	}

	// --- Compute metrics ---
	totalVuln := len(vulnResults)
	var blocked, warned, detected, passthrough int
	for _, vr := range vulnResults {
		if vr.blocked {
			blocked++
		}
		if vr.warned {
			warned++
		}
		if vr.detected {
			detected++
		}
		if !vr.detected {
			passthrough++
		}
	}

	totalSafe := len(safeResults)
	var safeFPs, safeBlocked int
	for _, sr := range safeResults {
		if sr.fpCount > 0 {
			safeFPs++
		}
		if sr.blocked {
			safeBlocked++
		}
	}

	// --- OWASP breakdown ---
	type owaspStats struct {
		total, blocked, warned, detected int
	}
	owaspMap := make(map[string]*owaspStats)
	for _, vr := range vulnResults {
		code := vr.owasp
		st, ok := owaspMap[code]
		if !ok {
			st = &owaspStats{}
			owaspMap[code] = st
		}
		st.total++
		if vr.blocked {
			st.blocked++
		}
		if vr.warned {
			st.warned++
		}
		if vr.detected {
			st.detected++
		}
	}

	// --- Language breakdown ---
	type langStats struct {
		vulnTotal, vulnBlocked, vulnWarned, vulnDetected int
		safeTotal, safeFP, safeBlocked                   int
	}
	langMap := make(map[string]*langStats)
	for _, vr := range vulnResults {
		st, ok := langMap[vr.fixture.Lang]
		if !ok {
			st = &langStats{}
			langMap[vr.fixture.Lang] = st
		}
		st.vulnTotal++
		if vr.blocked {
			st.vulnBlocked++
		}
		if vr.warned {
			st.vulnWarned++
		}
		if vr.detected {
			st.vulnDetected++
		}
	}
	for _, sr := range safeResults {
		st, ok := langMap[sr.fixture.Lang]
		if !ok {
			st = &langStats{}
			langMap[sr.fixture.Lang] = st
		}
		st.safeTotal++
		if sr.fpCount > 0 {
			st.safeFP++
		}
		if sr.blocked {
			st.safeBlocked++
		}
	}

	// --- Render scorecard ---
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║            Batou Product Security Scorecard                      ║\n")
	sb.WriteString("║            Claude Code + Batou  vs  Vanilla Claude Code          ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════════╝\n")
	sb.WriteString("\n")

	// Headline metrics
	sb.WriteString("┌─────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│  VULNERABLE CODE INTERVENTION  (higher = better)                │\n")
	sb.WriteString("├──────────────────────┬──────────────┬───────────────────────────┤\n")
	sb.WriteString("│  Metric              │  Batou+Claude │  Vanilla Claude Code      │\n")
	sb.WriteString("├──────────────────────┼──────────────┼───────────────────────────┤\n")
	sb.WriteString(fmt.Sprintf("│  Blocked (Critical)  │  %3d/%d %4.0f%% │  0/%d   0%%  (no scanner)  │\n",
		blocked, totalVuln, pct(blocked, totalVuln), totalVuln))
	sb.WriteString(fmt.Sprintf("│  Warned  (High+)     │  %3d/%d %4.0f%% │  0/%d   0%%                │\n",
		warned, totalVuln, pct(warned, totalVuln), totalVuln))
	sb.WriteString(fmt.Sprintf("│  Detected (Any)      │  %3d/%d %4.0f%% │  0/%d   0%%                │\n",
		detected, totalVuln, pct(detected, totalVuln), totalVuln))
	sb.WriteString(fmt.Sprintf("│  Pass-through        │  %3d/%d %4.0f%% │  %d/%d 100%%  (all pass)    │\n",
		passthrough, totalVuln, pct(passthrough, totalVuln), totalVuln, totalVuln))
	sb.WriteString("└──────────────────────┴──────────────┴───────────────────────────┘\n")
	sb.WriteString("\n")

	sb.WriteString("┌─────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│  SAFE CODE ACCURACY  (lower = better)                           │\n")
	sb.WriteString("├──────────────────────┬──────────────┬───────────────────────────┤\n")
	sb.WriteString("│  Metric              │  Batou+Claude │  Vanilla Claude Code      │\n")
	sb.WriteString("├──────────────────────┼──────────────┼───────────────────────────┤\n")
	sb.WriteString(fmt.Sprintf("│  False positives     │  %3d/%d %4.0f%% │  0/%d   0%%  (no scanner)  │\n",
		safeFPs, totalSafe, pct(safeFPs, totalSafe), totalSafe))
	sb.WriteString(fmt.Sprintf("│  Safe code blocked   │  %3d/%d %4.0f%% │  0/%d   0%%                │\n",
		safeBlocked, totalSafe, pct(safeBlocked, totalSafe), totalSafe))
	sb.WriteString("└──────────────────────┴──────────────┴───────────────────────────┘\n")
	sb.WriteString("\n")

	// OWASP Top 10 coverage
	sb.WriteString("┌─────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│  OWASP TOP 10 COVERAGE                                         │\n")
	sb.WriteString("├──────────┬───────┬─────────┬────────┬──────────┬────────────────┤\n")
	sb.WriteString("│  OWASP   │ Total │ Blocked │ Warned │ Detected │ Detection Rate │\n")
	sb.WriteString("├──────────┼───────┼─────────┼────────┼──────────┼────────────────┤\n")

	var owaspCodes []string
	for code := range owaspMap {
		owaspCodes = append(owaspCodes, code)
	}
	sort.Strings(owaspCodes)

	owaspNames := map[string]string{
		"A01": "Broken Access Control",
		"A02": "Cryptographic Failures",
		"A03": "Injection",
		"A04": "Insecure Design",
		"A05": "Security Misconfiguration",
		"A06": "Vuln Components",
		"A07": "Auth Failures",
		"A08": "Data Integrity",
		"A09": "Logging Failures",
		"A10": "SSRF",
		"UNK": "Unknown",
	}

	for _, code := range owaspCodes {
		st := owaspMap[code]
		label := code
		if name, ok := owaspNames[code]; ok {
			label = code + " " + name
		}
		if len(label) > 8 {
			label = label[:8]
		}
		sb.WriteString(fmt.Sprintf("│  %-8s│  %3d  │   %3d   │   %3d  │    %3d   │     %4.0f%%      │\n",
			label, st.total, st.blocked, st.warned, st.detected, pct(st.detected, st.total)))
	}
	sb.WriteString("└──────────┴───────┴─────────┴────────┴──────────┴────────────────┘\n")
	sb.WriteString("\n")

	// Per-language breakdown
	sb.WriteString("┌─────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│  PER-LANGUAGE BREAKDOWN                                         │\n")
	sb.WriteString("├────────────┬───────┬─────────┬────────┬──────────┬──────────────┤\n")
	sb.WriteString("│  Language  │ Vulns │ Blocked │ Warned │ Detected │ Safe FPs     │\n")
	sb.WriteString("├────────────┼───────┼─────────┼────────┼──────────┼──────────────┤\n")

	var langs []string
	for lang := range langMap {
		langs = append(langs, lang)
	}
	sort.Strings(langs)

	for _, lang := range langs {
		st := langMap[lang]
		fpLabel := fmt.Sprintf("%d/%d", st.safeFP, st.safeTotal)
		if st.safeTotal == 0 {
			fpLabel = "n/a"
		}
		sb.WriteString(fmt.Sprintf("│  %-10s│  %3d  │   %3d   │   %3d  │   %3d %3.0f%% │ %-12s │\n",
			lang, st.vulnTotal, st.vulnBlocked, st.vulnWarned, st.vulnDetected,
			pct(st.vulnDetected, st.vulnTotal), fpLabel))
	}
	sb.WriteString("└────────────┴───────┴─────────┴────────┴──────────┴──────────────┘\n")
	sb.WriteString("\n")

	// Net security uplift
	sb.WriteString("┌─────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│  NET SECURITY UPLIFT                                            │\n")
	sb.WriteString("├─────────────────────────────────────────────────────────────────┤\n")
	vulnCaught := blocked + (warned - blocked)
	sb.WriteString(fmt.Sprintf("│  Vulnerabilities blocked before write:  %d/%d (%.0f%%)             │\n",
		blocked, totalVuln, pct(blocked, totalVuln)))
	sb.WriteString(fmt.Sprintf("│  Vulnerabilities warned + self-heal:    %d/%d (%.0f%%)             │\n",
		warned, totalVuln, pct(warned, totalVuln)))
	sb.WriteString(fmt.Sprintf("│  Total vulns with intervention:         %d/%d (%.0f%%)             │\n",
		detected, totalVuln, pct(detected, totalVuln)))
	_ = vulnCaught
	if passthrough > 0 {
		sb.WriteString(fmt.Sprintf("│  Remaining gaps:                        %d/%d (%.0f%%)             │\n",
			passthrough, totalVuln, pct(passthrough, totalVuln)))
	}
	sb.WriteString("├─────────────────────────────────────────────────────────────────┤\n")

	precision := 0.0
	if detected+safeFPs > 0 {
		precision = pct(detected, detected+safeFPs)
	}
	recall := pct(detected, totalVuln)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	sb.WriteString(fmt.Sprintf("│  Precision: %.0f%%   Recall: %.0f%%   F1: %.0f%%                       │\n",
		precision, recall, f1))
	sb.WriteString("└─────────────────────────────────────────────────────────────────┘\n")

	// Missed vulnerabilities
	var missed []vulnResult
	for _, vr := range vulnResults {
		if !vr.detected {
			missed = append(missed, vr)
		}
	}
	if len(missed) > 0 {
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("--- Missed Vulnerabilities (%d) ---\n", len(missed)))
		for _, vr := range missed {
			sb.WriteString(fmt.Sprintf("  MISS: [%s] %s/%s\n", vr.owasp, vr.fixture.Lang, vr.fixture.FileName))
		}
	}

	// Blocked safe code
	var blockedSafe []safeResult
	for _, sr := range safeResults {
		if sr.blocked {
			blockedSafe = append(blockedSafe, sr)
		}
	}
	if len(blockedSafe) > 0 {
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("--- Incorrectly Blocked Safe Code (%d) ---\n", len(blockedSafe)))
		for _, sr := range blockedSafe {
			var criticals []string
			for _, f := range sr.findings {
				if f.Severity >= rules.Critical {
					criticals = append(criticals, fmt.Sprintf("%s L%d", f.RuleID, f.LineNumber))
				}
			}
			sb.WriteString(fmt.Sprintf("  BLOCK: %s/%s  rules: %s\n",
				sr.fixture.Lang, sr.fixture.FileName, strings.Join(criticals, ", ")))
		}
	}

	sb.WriteString("\n")

	t.Log(sb.String())
}

func pct(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) / float64(denom) * 100
}
