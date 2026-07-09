package scanner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/memory"
	_ "github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
)

func TestSpringFrameworkScan(t *testing.T) {
	springDir := "/tmp/spring-framework"
	if _, err := os.Stat(springDir); os.IsNotExist(err) {
		t.Skip("Spring Framework not cloned — run: git clone --depth 1 https://github.com/spring-projects/spring-framework.git /tmp/spring-framework")
	}

	// Collect all Java files (skip test files for cleaner signal)
	var files []string
	_ = filepath.Walk(springDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".java") {
			return nil
		}
		// Skip test files
		if strings.Contains(path, "/test/") || strings.Contains(path, "/testFixtures/") {
			return nil
		}
		files = append(files, path)
		return nil
	})

	t.Logf("Scanning %d non-test Java files from Spring Framework", len(files))

	start := time.Now()

	type fileFinding struct {
		File    string
		Finding rules.Finding
	}

	var (
		mu          sync.Mutex
		allFindings []fileFinding
		scanned     int64
		errors      int64
		totalMs     int64
	)

	// Scan in parallel (bounded concurrency)
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			data, err := os.ReadFile(path)
			if err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}

			input := &hook.Input{
				HookEventName: "PostToolUse",
				ToolName:      "Write",
				ToolInput:     hook.ToolInput{FilePath: path, Content: string(data)},
			}
			result := scanner.Scan(input)
			atomic.AddInt64(&scanned, 1)
			atomic.AddInt64(&totalMs, result.ScanTimeMs)

			if len(result.Findings) > 0 {
				mu.Lock()
				for _, finding := range result.Findings {
					allFindings = append(allFindings, fileFinding{
						File:    strings.TrimPrefix(path, springDir+"/"),
						Finding: finding,
					})
				}
				mu.Unlock()
			}
		}(f)
	}
	wg.Wait()

	elapsed := time.Since(start)

	// ========== Report ==========

	t.Logf("\n=== Spring Framework Scan Report ===")
	t.Logf("Files scanned: %d", scanned)
	t.Logf("Read errors: %d", errors)
	t.Logf("Total findings: %d", len(allFindings))
	t.Logf("Wall time: %s", elapsed.Round(time.Millisecond))
	t.Logf("Avg scan time: %dms/file", totalMs/max(scanned, 1))

	// Count by rule ID
	ruleCounts := make(map[string]int)
	for _, ff := range allFindings {
		ruleCounts[ff.Finding.RuleID]++
	}

	// Sort by count descending
	type ruleCount struct {
		ID    string
		Count int
	}
	var sorted []ruleCount
	for id, count := range ruleCounts {
		sorted = append(sorted, ruleCount{id, count})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Count > sorted[j].Count })

	t.Logf("\n--- Findings by Rule ---")
	for _, rc := range sorted {
		t.Logf("  %-30s %d", rc.ID, rc.Count)
	}

	// Count by severity
	sevCounts := make(map[string]int)
	for _, ff := range allFindings {
		sevCounts[ff.Finding.SeverityLabel]++
	}
	t.Logf("\n--- Findings by Severity ---")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if c, ok := sevCounts[sev]; ok {
			t.Logf("  %-12s %d", sev, c)
		}
	}

	// Count blocking vs hint
	blocking := 0
	for _, ff := range allFindings {
		if ff.Finding.RiskScore >= 0.7 {
			blocking++
		}
	}
	t.Logf("\n--- Blocking vs Hint ---")
	t.Logf("  Would block: %d", blocking)
	t.Logf("  Hint only:   %d", len(allFindings)-blocking)

	// Top 10 files with most findings
	fileCounts := make(map[string]int)
	for _, ff := range allFindings {
		fileCounts[ff.File]++
	}
	type fileCount struct {
		File  string
		Count int
	}
	var fileSorted []fileCount
	for f, c := range fileCounts {
		fileSorted = append(fileSorted, fileCount{f, c})
	}
	sort.Slice(fileSorted, func(i, j int) bool { return fileSorted[i].Count > fileSorted[j].Count })

	t.Logf("\n--- Top 10 Files by Finding Count ---")
	for i, fc := range fileSorted {
		if i >= 10 {
			break
		}
		t.Logf("  %3d  %s", fc.Count, fc.File)
	}

	// Write JSON report
	type report struct {
		Framework    string `json:"framework"`
		Version      string `json:"version"`
		FilesScanned int64  `json:"files_scanned"`
		TotalFindings int  `json:"total_findings"`
		Blocking     int    `json:"blocking"`
		Hints        int    `json:"hints"`
		WallTimeMs   int64  `json:"wall_time_ms"`
		AvgScanMs    int64  `json:"avg_scan_ms"`
		BySeverity   map[string]int `json:"by_severity"`
		ByRule       []ruleCount    `json:"by_rule"`
	}
	r := report{
		Framework:     "spring-framework",
		Version:       "latest (HEAD)",
		FilesScanned:  scanned,
		TotalFindings: len(allFindings),
		Blocking:      blocking,
		Hints:         len(allFindings) - blocking,
		WallTimeMs:    elapsed.Milliseconds(),
		AvgScanMs:     totalMs / max(scanned, 1),
		BySeverity:    sevCounts,
		ByRule:        sorted,
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	t.Logf("\n--- JSON Report ---\n%s", string(data))
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
