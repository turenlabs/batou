package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/turenio/gtss/internal/hook"
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/scanner"
	"github.com/turenio/gtss/internal/taint"
	"github.com/turenio/gtss/internal/testutil"
)

// sampleEntry represents a single gold-standard sample with its scan results.
type sampleEntry struct {
	promptID   string
	owasp      string
	lang       string
	phase      string // "vuln" or "safe"
	filePath   string
	findings   []rules.Finding
	ruleIDs    []string
	maxSev     rules.Severity
	detected   bool
	blocked    bool
	taintFlows int
}

// auditProjectRoot returns the absolute path to the project root.
func auditProjectRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// auditSamplesDir returns the path to bench/testdata/samples/.
func auditSamplesDir() string {
	return filepath.Join(auditProjectRoot(), "bench", "testdata", "samples")
}

// scanWithResults scans code and returns findings plus taint flow count.
func scanWithResults(code, lang string) ([]rules.Finding, int) {
	ext := langToExt[lang]
	if ext == "" {
		ext = "." + lang
	}
	fakePath := "/app/bench_target" + ext

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: fakePath,
			Content:  code,
		},
	}

	result := scanner.Scan(input)

	langEnum := langToRulesLang(lang)
	flows := taint.Analyze(code, fakePath, langEnum)

	return result.Findings, len(flows)
}

// scanRegexOnly runs only the regex rules (no taint analysis) against code.
func scanRegexOnly(code, lang string) []rules.Finding {
	ext := langToExt[lang]
	if ext == "" {
		ext = "." + lang
	}
	fakePath := "/app/bench_target" + ext
	langEnum := langToRulesLang(lang)

	ctx := &rules.ScanContext{
		FilePath: fakePath,
		Content:  code,
		Language: langEnum,
		IsNew:    true,
	}

	applicable := rules.ForLanguage(langEnum)
	var findings []rules.Finding
	for _, r := range applicable {
		if r.ID() == "GTSS-TAINT" {
			continue
		}
		findings = append(findings, r.Scan(ctx)...)
	}
	return findings
}

// langToRulesLang maps string language names to rules.Language constants.
func langToRulesLang(lang string) rules.Language {
	switch lang {
	case "go":
		return rules.LangGo
	case "python":
		return rules.LangPython
	case "javascript":
		return rules.LangJavaScript
	case "typescript":
		return rules.LangTypeScript
	case "java":
		return rules.LangJava
	case "ruby":
		return rules.LangRuby
	case "php":
		return rules.LangPHP
	case "csharp":
		return rules.LangCSharp
	case "c":
		return rules.LangC
	case "cpp":
		return rules.LangCPP
	default:
		return rules.Language(lang)
	}
}

// discoverGoldSamples walks bench/testdata/samples/ and builds sampleEntry
// items for every vulnerable and secure file found.
func discoverGoldSamples(t *testing.T) []sampleEntry {
	t.Helper()
	root := auditSamplesDir()
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Skipf("gold-standard samples directory does not exist: %s", root)
	}

	var entries []sampleEntry

	owaspDirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading samples dir: %v", err)
	}

	for _, owaspDir := range owaspDirs {
		if !owaspDir.IsDir() {
			continue
		}
		owasp := owaspDir.Name()
		promptPath := filepath.Join(root, owasp)
		promptDirs, err := os.ReadDir(promptPath)
		if err != nil {
			continue
		}
		for _, promptDir := range promptDirs {
			if !promptDir.IsDir() {
				continue
			}
			promptID := promptDir.Name()
			langPath := filepath.Join(promptPath, promptID)
			langDirs, err := os.ReadDir(langPath)
			if err != nil {
				continue
			}
			for _, langDir := range langDirs {
				if !langDir.IsDir() {
					continue
				}
				lang := langDir.Name()
				filesPath := filepath.Join(langPath, lang)
				files, err := os.ReadDir(filesPath)
				if err != nil {
					continue
				}
				for _, f := range files {
					if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
						continue
					}
					phase := "unknown"
					if strings.Contains(f.Name(), "vulnerable") || strings.Contains(f.Name(), "vuln") {
						phase = "vuln"
					} else if strings.Contains(f.Name(), "secure") || strings.Contains(f.Name(), "safe") {
						phase = "safe"
					}
					entries = append(entries, sampleEntry{
						promptID: promptID,
						owasp:    owasp,
						lang:     lang,
						phase:    phase,
						filePath: filepath.Join(filesPath, f.Name()),
					})
				}
			}
		}
	}
	return entries
}

// discoverBenchFixtures loads all bench fixtures from testdata/fixtures/bench/.
func discoverBenchFixtures(t *testing.T) []sampleEntry {
	t.Helper()
	if !testutil.BenchDirExists() {
		return nil
	}

	var entries []sampleEntry

	for _, fix := range testutil.BenchFixtures(t) {
		owasp := auditInferOWASP(fix.FileName)
		entries = append(entries, sampleEntry{
			promptID: "bench-" + fix.Lang + "-" + strings.TrimSuffix(fix.FileName, filepath.Ext(fix.FileName)),
			owasp:    owasp,
			lang:     fix.Lang,
			phase:    "vuln",
			filePath: fix.FullPath,
		})
	}

	for _, fix := range testutil.BenchSafeFixtures(t) {
		entries = append(entries, sampleEntry{
			promptID: "bench-safe-" + fix.Lang + "-" + strings.TrimSuffix(fix.FileName, filepath.Ext(fix.FileName)),
			owasp:    "SAFE",
			lang:     fix.Lang,
			phase:    "safe",
			filePath: fix.FullPath,
		})
	}

	return entries
}

// auditInferOWASP extracts OWASP code from filename like "a03_sqli.py" -> "A03".
func auditInferOWASP(name string) string {
	lower := strings.ToLower(name)
	if len(lower) >= 3 && lower[0] == 'a' && lower[1] >= '0' && lower[1] <= '9' && lower[2] >= '0' && lower[2] <= '9' {
		return strings.ToUpper(lower[:3])
	}
	return "UNK"
}

// TestDetectionAudit is the comprehensive audit test.
func TestDetectionAudit(t *testing.T) {
	goldSamples := discoverGoldSamples(t)
	benchSamples := discoverBenchFixtures(t)

	allSamples := append(goldSamples, benchSamples...)
	if len(allSamples) == 0 {
		t.Skip("no samples found to audit")
	}

	// Scan each sample
	for i := range allSamples {
		s := &allSamples[i]
		code, err := os.ReadFile(s.filePath) //nolint:gosec // test code reads known fixture files
		if err != nil {
			t.Errorf("failed to read %s: %v", s.filePath, err)
			continue
		}

		findings, taintFlowCount := scanWithResults(string(code), s.lang)
		s.findings = findings
		s.taintFlows = taintFlowCount
		s.detected = len(findings) > 0

		seen := make(map[string]bool)
		for _, f := range findings {
			if !seen[f.RuleID] {
				s.ruleIDs = append(s.ruleIDs, f.RuleID)
				seen[f.RuleID] = true
			}
			if f.Severity > s.maxSev {
				s.maxSev = f.Severity
			}
		}
		s.blocked = false
		for _, f := range findings {
			if f.Severity >= rules.Critical {
				s.blocked = true
				break
			}
		}
	}

	// Taint vs Regex comparison
	type taintComparison struct {
		sample        string
		regexOnly     int
		taintOnly     int
		both          int
		taintAddsDets bool
	}

	var taintComps []taintComparison
	taintOnlyTotal := 0
	regexOnlyTotal := 0
	bothTotal := 0
	taintAddsDetections := 0

	for _, s := range allSamples {
		if s.phase != "vuln" {
			continue
		}
		code, err := os.ReadFile(s.filePath) //nolint:gosec // test code reads known fixture files
		if err != nil {
			continue
		}

		regexFindings := scanRegexOnly(string(code), s.lang)
		regexIDs := make(map[string]bool)
		for _, f := range regexFindings {
			regexIDs[f.RuleID] = true
		}

		fullIDs := make(map[string]bool)
		for _, id := range s.ruleIDs {
			fullIDs[id] = true
		}

		taintOnlyIDs := make(map[string]bool)
		regexOnlyIDs := make(map[string]bool)
		bothIDs := make(map[string]bool)

		for id := range fullIDs {
			if strings.Contains(id, "TAINT") {
				taintOnlyIDs[id] = true
			} else if regexIDs[id] {
				bothIDs[id] = true
			}
		}
		for id := range regexIDs {
			if !fullIDs[id] {
				regexOnlyIDs[id] = true
			}
		}

		tc := taintComparison{
			sample:    s.promptID + "/" + s.lang,
			regexOnly: len(regexOnlyIDs),
			taintOnly: len(taintOnlyIDs),
			both:      len(bothIDs),
		}

		if len(taintOnlyIDs) > 0 && len(regexFindings) == 0 {
			tc.taintAddsDets = true
			taintAddsDetections++
		}

		taintOnlyTotal += len(taintOnlyIDs)
		regexOnlyTotal += len(regexOnlyIDs) + len(bothIDs)
		bothTotal += len(bothIDs)

		taintComps = append(taintComps, tc)
	}

	// Render detection matrix
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                    DETECTION MATRIX\n")
	sb.WriteString("================================================================\n")
	sb.WriteString(fmt.Sprintf("%-38s | %-4s | %-5s | %-3s | %-30s | %-8s\n",
		"Sample", "Lang", "Phase", "Det", "Rules", "Sev"))
	sb.WriteString(strings.Repeat("-", 105) + "\n")

	sort.Slice(allSamples, func(i, j int) bool {
		if allSamples[i].owasp != allSamples[j].owasp {
			return allSamples[i].owasp < allSamples[j].owasp
		}
		if allSamples[i].promptID != allSamples[j].promptID {
			return allSamples[i].promptID < allSamples[j].promptID
		}
		if allSamples[i].lang != allSamples[j].lang {
			return allSamples[i].lang < allSamples[j].lang
		}
		return allSamples[i].phase < allSamples[j].phase
	})

	for _, s := range allSamples {
		det := "NO"
		if s.detected {
			det = "YES"
		}
		rulesStr := "---"
		if len(s.ruleIDs) > 0 {
			rulesStr = strings.Join(s.ruleIDs, ",")
			if len(rulesStr) > 30 {
				rulesStr = rulesStr[:27] + "..."
			}
		}
		sevStr := "---"
		if s.detected {
			sevStr = s.maxSev.String()
		}
		label := s.owasp + "/" + s.promptID + "/" + s.phase
		if len(label) > 38 {
			label = label[:38]
		}
		sb.WriteString(fmt.Sprintf("%-38s | %-4s | %-5s | %-3s | %-30s | %-8s\n",
			label, shortLang(s.lang), s.phase, det, rulesStr, sevStr))
	}

	// Summary
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                        SUMMARY\n")
	sb.WriteString("================================================================\n")

	var vulnTotal, vulnDetected, vulnMissed, vulnBlocked int
	var safeTotal, safeFlagged int
	for _, s := range allSamples {
		if s.phase == "vuln" {
			vulnTotal++
			if s.detected {
				vulnDetected++
			} else {
				vulnMissed++
			}
			if s.blocked {
				vulnBlocked++
			}
		} else if s.phase == "safe" {
			safeTotal++
			if s.detected {
				safeFlagged++
			}
		}
	}

	fpRate := 0.0
	if safeTotal > 0 {
		fpRate = float64(safeFlagged) / float64(safeTotal) * 100
	}
	detRate := 0.0
	if vulnTotal > 0 {
		detRate = float64(vulnDetected) / float64(vulnTotal) * 100
	}

	sb.WriteString(fmt.Sprintf("Vulnerable samples: %d total, %d detected (%.0f%%), %d missed\n",
		vulnTotal, vulnDetected, detRate, vulnMissed))
	sb.WriteString(fmt.Sprintf("Blocked (Critical): %d/%d (%.0f%%)\n",
		vulnBlocked, vulnTotal, auditPct(vulnBlocked, vulnTotal)))
	sb.WriteString(fmt.Sprintf("Safe samples: %d total, %d flagged (%.0f%% FP rate)\n",
		safeTotal, safeFlagged, fpRate))

	// Missed vulnerabilities
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                  MISSED VULNERABILITIES\n")
	sb.WriteString("================================================================\n")

	missedCount := 0
	for _, s := range allSamples {
		if s.phase == "vuln" && !s.detected {
			missedCount++
			code, _ := os.ReadFile(s.filePath) //nolint:gosec
			expected := extractExpectedFromHeader(string(code))
			sb.WriteString(fmt.Sprintf("  MISS: [%s] %s/%s  (expected: %s)\n",
				s.owasp, s.lang, s.promptID, expected))
		}
	}
	if missedCount == 0 {
		sb.WriteString("  (none - all vulnerable samples detected)\n")
	}

	// False positives
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                    FALSE POSITIVES\n")
	sb.WriteString("================================================================\n")

	fpCountEntries := 0
	for _, s := range allSamples {
		if s.phase == "safe" && s.detected {
			fpCountEntries++
			sb.WriteString(fmt.Sprintf("  FP: [%s] %s/%s  rules: %s  sev: %s\n",
				s.owasp, s.lang, s.promptID, strings.Join(s.ruleIDs, ","), s.maxSev.String()))
		}
	}
	if fpCountEntries == 0 {
		sb.WriteString("  (none - all safe samples passed cleanly)\n")
	}

	// Taint analysis contribution
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                TAINT ANALYSIS CONTRIBUTION\n")
	sb.WriteString("================================================================\n")
	sb.WriteString(fmt.Sprintf("Taint-only findings (unique rule IDs): %d\n", taintOnlyTotal))
	sb.WriteString(fmt.Sprintf("Regex-only findings (unique rule IDs): %d\n", regexOnlyTotal))
	sb.WriteString(fmt.Sprintf("Found by both:                         %d\n", bothTotal))
	sb.WriteString(fmt.Sprintf("Taint adds new detection (samples):    %d\n", taintAddsDetections))
	sb.WriteString("\n")

	if len(taintComps) > 0 {
		sb.WriteString("Per-sample taint contribution (non-zero only):\n")
		sb.WriteString(fmt.Sprintf("  %-42s | %-5s | %-5s | %-5s | %-5s\n",
			"Sample", "Regex", "Taint", "Both", "Adds?"))
		sb.WriteString(strings.Repeat("-", 75) + "\n")
		for _, tc := range taintComps {
			if tc.taintOnly > 0 {
				adds := "no"
				if tc.taintAddsDets {
					adds = "YES"
				}
				label := tc.sample
				if len(label) > 42 {
					label = label[:42]
				}
				sb.WriteString(fmt.Sprintf("  %-42s | %5d | %5d | %5d | %-5s\n",
					label, tc.regexOnly, tc.taintOnly, tc.both, adds))
			}
		}
	}

	// Per-OWASP detection rates
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                 PER-OWASP DETECTION RATES\n")
	sb.WriteString("================================================================\n")

	type owaspStat struct {
		total, detected, missed, blocked int
	}
	owaspStatsMap := make(map[string]*owaspStat)
	for _, s := range allSamples {
		if s.phase != "vuln" {
			continue
		}
		st, ok := owaspStatsMap[s.owasp]
		if !ok {
			st = &owaspStat{}
			owaspStatsMap[s.owasp] = st
		}
		st.total++
		if s.detected {
			st.detected++
		} else {
			st.missed++
		}
		if s.blocked {
			st.blocked++
		}
	}

	var owaspCodes []string
	for code := range owaspStatsMap {
		owaspCodes = append(owaspCodes, code)
	}
	sort.Strings(owaspCodes)

	owaspNames := map[string]string{
		"A01": "Broken Access Control",
		"A02": "Cryptographic Failures",
		"A03": "Injection",
		"A04": "Insecure Design",
		"A05": "Security Misconfiguration",
		"A06": "Vulnerable Components",
		"A07": "Auth Failures",
		"A08": "Data Integrity",
		"A09": "Logging Failures",
		"A10": "SSRF",
	}

	sb.WriteString(fmt.Sprintf("  %-6s %-25s | %5s | %5s | %5s | %7s | %5s\n",
		"OWASP", "Name", "Total", "Det", "Miss", "Blocked", "Rate"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, code := range owaspCodes {
		st := owaspStatsMap[code]
		name := owaspNames[code]
		if name == "" {
			name = "Unknown"
		}
		rate := auditPct(st.detected, st.total)
		sb.WriteString(fmt.Sprintf("  %-6s %-25s | %5d | %5d | %5d | %7d | %4.0f%%\n",
			code, name, st.total, st.detected, st.missed, st.blocked, rate))
	}

	// Per-language detection rates
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                PER-LANGUAGE DETECTION RATES\n")
	sb.WriteString("================================================================\n")

	type langStatEntry struct {
		vulnTotal, vulnDetected int
		safeTotal, safeFlagged  int
	}
	langStatsMap := make(map[string]*langStatEntry)
	for _, s := range allSamples {
		st, ok := langStatsMap[s.lang]
		if !ok {
			st = &langStatEntry{}
			langStatsMap[s.lang] = st
		}
		if s.phase == "vuln" {
			st.vulnTotal++
			if s.detected {
				st.vulnDetected++
			}
		} else if s.phase == "safe" {
			st.safeTotal++
			if s.detected {
				st.safeFlagged++
			}
		}
	}

	var langs []string
	for lang := range langStatsMap {
		langs = append(langs, lang)
	}
	sort.Strings(langs)

	sb.WriteString(fmt.Sprintf("  %-12s | %6s | %6s | %7s | %6s | %4s | %6s\n",
		"Language", "Vulns", "Det", "DetRate", "Safe", "FPs", "FPRate"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, lang := range langs {
		st := langStatsMap[lang]
		dRate := auditPct(st.vulnDetected, st.vulnTotal)
		fRate := auditPct(st.safeFlagged, st.safeTotal)
		sb.WriteString(fmt.Sprintf("  %-12s | %6d | %6d | %6.0f%% | %6d | %4d | %5.0f%%\n",
			lang, st.vulnTotal, st.vulnDetected, dRate, st.safeTotal, st.safeFlagged, fRate))
	}

	// Recommendations
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("                   RECOMMENDATIONS\n")
	sb.WriteString("================================================================\n")

	recNum := 1
	for _, s := range allSamples {
		if s.phase == "vuln" && !s.detected {
			code, _ := os.ReadFile(s.filePath) //nolint:gosec
			expected := extractExpectedFromHeader(string(code))
			rootCause := analyzeRootCause(string(code), s.lang, s.owasp)
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s/%s\n", recNum, s.owasp, s.lang, s.promptID))
			sb.WriteString(fmt.Sprintf("     Expected: %s\n", expected))
			sb.WriteString(fmt.Sprintf("     Root cause: %s\n", rootCause))
			sb.WriteString("\n")
			recNum++
		}
	}
	if recNum == 1 {
		sb.WriteString("  No missed detections - scanner coverage is complete.\n")
	}

	t.Log(sb.String())
}

func auditPct(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) / float64(denom) * 100
}

func shortLang(lang string) string {
	switch lang {
	case "javascript":
		return "js"
	case "typescript":
		return "ts"
	case "python":
		return "py"
	default:
		if len(lang) > 4 {
			return lang[:4]
		}
		return lang
	}
}

func extractExpectedFromHeader(code string) string {
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range []string{"//", "#", "/*", "*", "--"} {
			trimmed = strings.TrimPrefix(trimmed, prefix)
			trimmed = strings.TrimSpace(trimmed)
		}
		if strings.HasPrefix(trimmed, "Expected:") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "Expected:"))
		}
	}
	return "(not specified)"
}

func analyzeRootCause(code, lang, owasp string) string {
	lower := strings.ToLower(code)

	switch owasp {
	case "A08":
		if strings.Contains(lower, "objectinputstream") || strings.Contains(lower, "readobject") {
			return "No Java deserialization rule for ObjectInputStream.readObject()"
		}
		if strings.Contains(lower, "pickle") || strings.Contains(lower, "pickle.loads") {
			return "No Python pickle deserialization rule"
		}
		if strings.Contains(lower, "unserialize") {
			return "No PHP unserialize() rule"
		}
		if strings.Contains(lower, "yaml.load") || strings.Contains(lower, "marshal.load") {
			return "No YAML/Marshal unsafe deserialization rule"
		}
		return "Missing deserialization detection for " + lang
	case "A07":
		if strings.Contains(lower, "verify_signature") && strings.Contains(lower, "false") {
			return "JWT signature verification bypass not detected"
		}
		if strings.Contains(lower, "none") && strings.Contains(lower, "algorithm") {
			return "JWT none algorithm not detected"
		}
		return "Missing authentication bypass detection for " + lang
	case "A02":
		if strings.Contains(lower, "md5") || strings.Contains(lower, "sha1") {
			return "Weak hash algorithm not detected"
		}
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") {
			return "Hardcoded secret/password not detected"
		}
		return "Missing crypto weakness detection for " + lang
	case "A05":
		if strings.Contains(lower, "debug") {
			return "Debug mode enabled in production not detected"
		}
		return "Missing security misconfiguration detection for " + lang
	case "A01":
		if strings.Contains(lower, "path") || strings.Contains(lower, "file") {
			return "Path traversal not detected - missing regex pattern for " + lang
		}
		return "Missing access control detection for " + lang
	case "A03":
		if strings.Contains(lower, "exec") || strings.Contains(lower, "system") || strings.Contains(lower, "popen") {
			return "Command injection not detected for " + lang
		}
		if strings.Contains(lower, "query") || strings.Contains(lower, "sql") {
			return "SQL injection not detected for " + lang
		}
		return "Missing injection detection for " + lang
	case "A10":
		if strings.Contains(lower, "request") || strings.Contains(lower, "http") || strings.Contains(lower, "fetch") {
			return "SSRF not detected - missing URL validation check for " + lang
		}
		return "Missing SSRF detection for " + lang
	}

	return "Unknown root cause - manual investigation needed"
}
