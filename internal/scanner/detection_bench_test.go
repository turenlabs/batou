package scanner_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// fixtureMetadata holds parsed header comment metadata from a benchmark fixture.
type fixtureMetadata struct {
	source      string   // Source description
	expectedIDs []string // Expected GTSS rule ID prefixes
	owaspCode   string   // OWASP code (e.g., "A01")
	owaspFull   string   // Full OWASP string
	category    string   // Inferred rule category
	lang        string   // Language directory name
	fileName    string   // Base file name
}

// detectionResult tracks the outcome for one fixture.
type detectionResult struct {
	meta     fixtureMetadata
	detected bool
	ruleIDs  []string
}

// TestDetectionBench is the main detection benchmark harness.
// It discovers bench fixtures, scans each one, and prints a detection matrix.
func TestDetectionBench(t *testing.T) {
	if !testutil.BenchDirExists() {
		t.Skip("no bench fixtures directory found; skipping detection benchmark")
	}

	fixtures := testutil.BenchFixtures(t)
	if len(fixtures) == 0 {
		t.Skip("no bench fixtures found")
	}

	var results []detectionResult

	for _, fix := range fixtures {
		meta := parseHeader(fix.Content, fix.Lang, fix.FileName)

		t.Run(fmt.Sprintf("%s/%s/%s", meta.owaspCode, fix.Lang, fix.FileName), func(t *testing.T) {
			// Use a non-test path for scanning to avoid test-file severity reduction.
			scanPath := "/app/bench_target" + filepath.Ext(fix.FileName)
			result := testutil.ScanContent(t, scanPath, fix.Content)

			firedIDs := testutil.FindingRuleIDs(result)
			detected := matchesExpected(firedIDs, meta.expectedIDs)

			dr := detectionResult{
				meta:     meta,
				detected: detected,
				ruleIDs:  firedIDs,
			}
			results = append(results, dr)

			if !detected {
				t.Errorf("MISS: %s/%s expected one of %v but got %v",
					fix.Lang, fix.FileName, meta.expectedIDs, firedIDs)
			}
		})
	}

	// Print the detection matrix after all subtests complete.
	t.Run("DetectionMatrix", func(t *testing.T) {
		printDetectionMatrix(t, results)
	})
}

// parseHeader extracts metadata from fixture header comments.
func parseHeader(content, lang, fileName string) fixtureMetadata {
	lines := strings.Split(content, "\n")
	meta := fixtureMetadata{
		lang:     lang,
		fileName: fileName,
	}

	// Determine comment prefix based on file extension.
	commentPrefix := "//"
	ext := strings.ToLower(filepath.Ext(fileName))
	switch ext {
	case ".py", ".rb":
		commentPrefix = "#"
	}

	maxLines := 10
	if len(lines) < maxLines {
		maxLines = len(lines)
	}

	for i := 0; i < maxLines; i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, commentPrefix) {
			// Allow PHP opening tag, package declarations, and blank lines.
			if line == "" || line == "<?php" || strings.HasPrefix(line, "package ") {
				continue
			}
			break
		}

		text := strings.TrimSpace(strings.TrimPrefix(line, commentPrefix))

		if strings.HasPrefix(text, "Source:") {
			meta.source = strings.TrimSpace(strings.TrimPrefix(text, "Source:"))
		} else if strings.HasPrefix(text, "Expected:") {
			meta.expectedIDs = parseExpectedIDs(strings.TrimPrefix(text, "Expected:"))
		} else if strings.HasPrefix(text, "OWASP:") {
			owaspStr := strings.TrimSpace(strings.TrimPrefix(text, "OWASP:"))
			meta.owaspFull = owaspStr
			meta.owaspCode = parseOWASPCode(owaspStr)
		}
	}

	// Fallbacks from filename.
	if len(meta.expectedIDs) == 0 {
		meta.expectedIDs = inferExpectedFromFilename(fileName)
	}
	if meta.owaspCode == "" {
		meta.owaspCode = inferOWASPFromFilename(fileName)
	}
	if len(meta.expectedIDs) > 0 {
		meta.category = inferCategory(meta.expectedIDs[0])
	}

	return meta
}

// parseExpectedIDs extracts rule ID prefixes from the Expected: line.
func parseExpectedIDs(s string) []string {
	s = strings.TrimSpace(s)
	var ids []string

	if strings.Contains(strings.ToLower(s), "taint") {
		ids = append(ids, "TAINT")
	}

	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';'
	})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		tokens := strings.Fields(part)
		for _, tok := range tokens {
			tok = strings.Trim(tok, "(),")
			if strings.HasPrefix(tok, "GTSS-") {
				ids = append(ids, tok)
			}
		}
	}

	return ids
}

// parseOWASPCode extracts "A01" from "A01:2021 - Broken Access Control".
func parseOWASPCode(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 3 && (s[0] == 'A' || s[0] == 'a') {
		code := strings.ToUpper(s[:3])
		if code[1] >= '0' && code[1] <= '9' && code[2] >= '0' && code[2] <= '9' {
			return code
		}
	}
	return "UNK"
}

func inferOWASPFromFilename(name string) string {
	lower := strings.ToLower(name)
	if len(lower) >= 3 && lower[0] == 'a' && lower[1] >= '0' && lower[1] <= '9' && lower[2] >= '0' && lower[2] <= '9' {
		return strings.ToUpper(lower[:3])
	}
	return "UNK"
}

func inferExpectedFromFilename(name string) []string {
	lower := strings.ToLower(name)
	var ids []string

	keywordMap := map[string]string{
		"sql_injection":     "GTSS-INJ",
		"sqli":              "GTSS-INJ",
		"nosql":             "GTSS-INJ",
		"command_injection": "GTSS-INJ",
		"cmd_injection":     "GTSS-INJ",
		"code_injection":    "GTSS-INJ",
		"injection":         "GTSS-INJ",
		"xss":               "GTSS-XSS",
		"cross_site":        "GTSS-XSS",
		"traversal":         "GTSS-TRV",
		"path_traversal":    "GTSS-TRV",
		"directory":         "GTSS-TRV",
		"ssrf":              "GTSS-SSRF",
		"crypto":            "GTSS-CRY",
		"weak_hash":         "GTSS-CRY",
		"weak_cipher":       "GTSS-CRY",
		"hardcoded":         "GTSS-SEC",
		"secret":            "GTSS-SEC",
		"api_key":           "GTSS-SEC",
		"password":          "GTSS-SEC",
		"idor":              "GTSS-VAL",
		"auth":              "GTSS-AUTH",
		"buffer":            "GTSS-MEM",
		"overflow":          "GTSS-MEM",
		"memory":            "GTSS-MEM",
		"log":               "GTSS-LOG",
		"deserialization":   "GTSS-INJ",
		"template":          "GTSS-INJ",
		"graphql":           "GTSS-INJ",
		"ldap":              "GTSS-INJ",
		"xpath":             "GTSS-INJ",
		"xxe":               "GTSS-INJ",
		"eval":              "GTSS-INJ",
		"prototype":         "GTSS-INJ",
	}

	for keyword, prefix := range keywordMap {
		if strings.Contains(lower, keyword) {
			ids = append(ids, prefix)
			ids = append(ids, "TAINT")
			break
		}
	}

	return ids
}

func inferCategory(ruleID string) string {
	upper := strings.ToUpper(ruleID)
	switch {
	case strings.Contains(upper, "INJ"):
		return "injection"
	case strings.Contains(upper, "XSS"):
		return "xss"
	case strings.Contains(upper, "TRV"):
		return "traversal"
	case strings.Contains(upper, "SSRF"):
		return "ssrf"
	case strings.Contains(upper, "CRY"):
		return "crypto"
	case strings.Contains(upper, "SEC"):
		return "secrets"
	case strings.Contains(upper, "AUTH"):
		return "auth"
	case strings.Contains(upper, "MEM"):
		return "memory"
	case strings.Contains(upper, "LOG"):
		return "logging"
	case strings.Contains(upper, "VAL"):
		return "validation"
	case strings.Contains(upper, "TAINT"):
		return "taint"
	default:
		return "generic"
	}
}

// categoryPrefix extracts the category prefix from a rule ID.
// "GTSS-XSS-001" -> "GTSS-XSS", "GTSS-INJ" -> "GTSS-INJ", "TAINT" -> "TAINT".
func categoryPrefix(ruleID string) string {
	parts := strings.SplitN(ruleID, "-", 3)
	if len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	return ruleID
}

// matchesExpected returns true if any fired rule ID matches any expected ID.
// Matching is done at three levels:
//  1. Exact prefix match (GTSS-INJ-001 matches GTSS-INJ-001)
//  2. Category prefix match (GTSS-XSS-011 matches expected GTSS-XSS-001 via shared "GTSS-XSS")
//  3. TAINT keyword match
func matchesExpected(firedIDs []string, expectedIDs []string) bool {
	// Build set of expected category prefixes for level-2 matching.
	expectedCats := make(map[string]bool)
	for _, exp := range expectedIDs {
		expectedCats[strings.ToUpper(categoryPrefix(exp))] = true
	}

	for _, fired := range firedIDs {
		firedUpper := strings.ToUpper(fired)
		firedCat := strings.ToUpper(categoryPrefix(fired))

		for _, expected := range expectedIDs {
			expectedUpper := strings.ToUpper(expected)
			// Level 1: exact prefix match.
			if strings.HasPrefix(firedUpper, expectedUpper) {
				return true
			}
			// Level 3: TAINT keyword.
			if expectedUpper == "TAINT" && strings.Contains(firedUpper, "TAINT") {
				return true
			}
		}

		// Level 2: category prefix match.
		if expectedCats[firedCat] {
			return true
		}
	}
	return false
}

type matrixKey struct {
	owasp string
	lang  string
}

func printDetectionMatrix(t *testing.T, results []detectionResult) {
	t.Helper()

	if len(results) == 0 {
		t.Log("No detection results to report.")
		return
	}

	type matrixEntry struct {
		fixtures int
		detected int
		missed   int
	}
	matrix := make(map[matrixKey]*matrixEntry)

	var totalFixtures, totalDetected, totalMissed int

	for _, r := range results {
		key := matrixKey{owasp: r.meta.owaspCode, lang: r.meta.lang}
		entry, ok := matrix[key]
		if !ok {
			entry = &matrixEntry{}
			matrix[key] = entry
		}
		entry.fixtures++
		totalFixtures++
		if r.detected {
			entry.detected++
			totalDetected++
		} else {
			entry.missed++
			totalMissed++
		}
	}

	var keys []matrixKey
	for k := range matrix {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].owasp != keys[j].owasp {
			return keys[i].owasp < keys[j].owasp
		}
		return keys[i].lang < keys[j].lang
	})

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("=== GTSS Detection Benchmark Matrix ===\n")
	sb.WriteString(fmt.Sprintf("%-6s | %-12s | %8s | %8s | %6s | %5s\n",
		"OWASP", "Language", "Fixtures", "Detected", "Missed", "Rate"))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, key := range keys {
		entry := matrix[key]
		rate := 0.0
		if entry.fixtures > 0 {
			rate = float64(entry.detected) / float64(entry.fixtures) * 100
		}
		sb.WriteString(fmt.Sprintf("%-6s | %-12s | %8d | %8d | %6d | %4.0f%%\n",
			key.owasp, key.lang, entry.fixtures, entry.detected, entry.missed, rate))
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")

	totalRate := 0.0
	if totalFixtures > 0 {
		totalRate = float64(totalDetected) / float64(totalFixtures) * 100
	}
	sb.WriteString(fmt.Sprintf("%-6s | %-12s | %8d | %8d | %6d | %4.0f%%\n",
		"TOTAL", "", totalFixtures, totalDetected, totalMissed, totalRate))
	sb.WriteString("\n")

	if totalMissed > 0 {
		sb.WriteString("--- Missed Detections ---\n")
		for _, r := range results {
			if !r.detected {
				sb.WriteString(fmt.Sprintf("  MISS: %s/%s/%s\n", r.meta.owaspCode, r.meta.lang, r.meta.fileName))
				sb.WriteString(fmt.Sprintf("        Expected: %v\n", r.meta.expectedIDs))
				sb.WriteString(fmt.Sprintf("        Got:      %v\n", r.ruleIDs))
			}
		}
		sb.WriteString("\n")
	}

	t.Log(sb.String())
}
