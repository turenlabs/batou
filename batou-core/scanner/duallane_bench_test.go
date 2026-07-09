package scanner_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
)

// extractBlockingCWEs returns the deduped CWE set restricted to findings that
// would BLOCK a write — RiskScore = Severity.ImpactWeight × ConfidenceScore ≥ 0.7
// (rules.Finding.ShouldBlock). This is the block-lane analogue of
// extractCWEsMinConf: extractCWEsMinConf(_, 0) counts every emitted finding
// (the report lane); this counts only the ones the hook would actually
// hard-block.
//
// RiskScore is already populated on every finding by the scanner
// (ComputeRiskScore in scanner.go runs before the result is returned), so
// nothing extra is captured here — this is a pure read of an existing field
// and touches no detection source.
//
// Caveat for readers: the hook's PreSuppressBlock latch applies extra
// test-path / external-origin caps to a COPY of each finding before its block
// decision. The per-finding RiskScore left on result.Findings is the
// post-edge-case value, which already reflects test-file caps. These benches
// scan with /app/... paths (not test paths), so in-test f.ShouldBlock() equals
// the hook's per-finding block decision for these inputs.
func extractBlockingCWEs(result *testutil.ScanResult) []string {
	seen := make(map[string]bool)
	var cwes []string
	for _, f := range result.Findings {
		if !f.ShouldBlock() { // f.RiskScore >= 0.7
			continue
		}
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		if cwe != "" && !seen[cwe] {
			seen[cwe] = true
			cwes = append(cwes, cwe)
		}
	}
	return cwes
}

// blockLaneScorecard is the per-corpus block-lane summary the CVE benches emit
// as a THIRD scorecard section (alongside strict + class-aware). It counts a
// fixture as a block-lane TP only when a BLOCKING finding (RiskScore ≥ 0.7)
// fires the expected CWE in the vuln tree, and a block-lane FP only when one
// fires in the safe tree. Strict CWE match (normalizeCWE equality) is used —
// the same policy as the strict report-lane scorecard — so the only difference
// between this and the strict lane is the RiskScore ≥ 0.7 gate.
type blockLaneScorecard struct {
	TP     int     `json:"tp"`
	FP     int     `json:"fp"`
	TN     int     `json:"tn"`
	FN     int     `json:"fn"`
	TPRate float64 `json:"tp_rate"`
	FPRate float64 `json:"fp_rate"`
	Youden float64 `json:"youden"`
}

// cveBlockDetection is the minimal per-fixture pair the shared block-lane
// tally needs: whether a blocking finding fired the expected CWE in the vuln
// tree (TP candidate) and in the safe tree (FP candidate). Each CVE bench
// derives these from its own *BlockCWEs sets via strict normalizeCWE match,
// keeping the per-corpus result struct local (the corpora intentionally do not
// share a struct).
type cveBlockDetection struct {
	CVE              string
	Category         string
	CWE              string
	DetectedInVuln   bool
	DetectedInSafe   bool
	VulnBlockingCWEs []string
	SafeBlockingCWEs []string
}

// logCVEBlockLane tallies and logs the block-lane scorecard for one CVE corpus
// and returns the summary for inclusion in results.json. It mirrors the
// div-by-zero guards of the existing report-lane scorecard helper. This is
// INFORMATIONAL only — no floor, no assertion. corpus is a short label like
// "GoCVE" used in the section header.
func logCVEBlockLane(t *testing.T, corpus string, dets []cveBlockDetection) blockLaneScorecard {
	t.Helper()

	tp, fp, tn, fn := 0, 0, 0, 0
	for _, d := range dets {
		if d.DetectedInVuln {
			tp++
		} else {
			fn++
		}
		if d.DetectedInSafe {
			fp++
		} else {
			tn++
		}
	}

	var tpRate, fpRate float64
	if totalVuln := tp + fn; totalVuln > 0 {
		tpRate = float64(tp) / float64(totalVuln)
	}
	if totalSafe := fp + tn; totalSafe > 0 {
		fpRate = float64(fp) / float64(totalSafe)
	}
	youden := tpRate - fpRate

	t.Logf("")
	t.Logf("--- Block lane (RiskScore>=0.7, strict CWE) ---")
	for _, d := range dets {
		vulnLabel := "NOT BLOCKED"
		if d.DetectedInVuln {
			vulnLabel = "BLOCKED"
		}
		safeLabel := "CLEAN"
		if d.DetectedInSafe {
			safeLabel = "BLOCKED(FP)"
		}
		t.Logf("%s (%s, %s): %s on vuln, %s on safe -- vuln_block_cwes=%v safe_block_cwes=%v",
			d.CVE, d.Category, d.CWE, vulnLabel, safeLabel,
			d.VulnBlockingCWEs, d.SafeBlockingCWEs)
	}
	t.Logf("Totals: %d/%d TP, %d/%d FP", tp, tp+fn, fp, fp+tn)
	t.Logf("Overall (BLOCK lane): TPRate=%.1f%% FPRate=%.1f%% Youden=%+.1f%%",
		tpRate*100, fpRate*100, youden*100)

	return blockLaneScorecard{
		TP: tp, FP: fp, TN: tn, FN: fn,
		TPRate: tpRate, FPRate: fpRate, Youden: youden,
	}
}

// detectedBlocking reports whether any blocking CWE in blockCWEs strictly
// matches expCWE (both already normalizeCWE-stripped on the expected side).
func detectedBlocking(blockCWEs []string, expCWE string) bool {
	for _, c := range blockCWEs {
		if normalizeCWE(c) == expCWE {
			return true
		}
	}
	return false
}
