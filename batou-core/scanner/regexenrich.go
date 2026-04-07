package scanner

import (
	"strings"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-rules/rules"
)

// taintCoverableCWEs lists CWE IDs for vulnerability categories that have
// taint analysis coverage. For these CWEs, regex-only findings are treated
// as enrichment (used for multi-layer confidence boost) rather than
// standalone findings. This eliminates regex FPs for injection/flow
// categories while keeping regex findings for pattern-only categories
// (secrets, crypto, misconfig) that can't be taint-analyzed.
var taintCoverableCWEs = map[string]bool{
	// Injection
	"89":   true, // SQL injection
	"78":   true, // OS command injection
	"90":   true, // LDAP injection
	"643":  true, // XPath injection
	"943":  true, // NoSQL injection
	"94":   true, // Code injection
	"95":   true, // Eval injection
	"1336": true, // Template injection (SSTI)
	"1236": true, // CSV/formula injection

	// XSS
	"79": true, // Cross-site scripting

	// Path traversal
	"22":  true, // Path traversal
	"73":  true, // External control of file name
	"434": true, // Unrestricted upload

	// SSRF
	"918": true, // Server-side request forgery

	// Redirect
	"601": true, // Open redirect

	// Deserialization
	"502": true, // Deserialization of untrusted data

	// Header injection
	"113": true, // HTTP response splitting
	"117": true, // Log injection

	// Trust boundary
	"501": true, // Trust boundary violation
}

// SuppressRegexWhenTaintClean suppresses regex-only findings for
// taint-coverable CWEs using two complementary strategies:
//
//  1. Active taint: If taint analysis produced findings for specific CWEs
//     in this scan, regex-only findings for those same CWEs are redundant
//     and suppressed (the taint findings are higher fidelity).
//
//  2. Negative confirmation: If taint analysis ran on this file and found
//     zero flows, AND the file's content hash matches the taint cache entry
//     in the call graph, then regex-only findings for ALL taint-coverable
//     CWEs are suppressed. This is the key new behavior — taint confirmed
//     the file is clean, so regex findings are false positives.
//
// If neither condition holds (no taint findings AND no matching cache entry),
// regex findings are kept as the only signal (first scan, no data).
func SuppressRegexWhenTaintClean(findings []rules.Finding, cg *graph.CallGraph, filePath string, contentHash uint64) []rules.Finding {
	// First pass: check which taint-coverable CWEs have taint/AST findings.
	taintActiveCWEs := make(map[string]bool)
	for _, f := range findings {
		tier := findingTier(&f)
		if tier <= tierRegex {
			continue
		}
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		if cwe != "" && taintCoverableCWEs[cwe] {
			taintActiveCWEs[cwe] = true
		}
	}

	// Check for negative taint confirmation from the cache.
	// If taint ran on this file (same content hash) and found 0 flows,
	// suppress regex findings for ALL taint-coverable CWEs.
	negativeTaintClean := false
	if len(taintActiveCWEs) == 0 && cg != nil {
		if entry := cg.GetFileTaintCache(filePath); entry != nil {
			if entry.ContentHash == contentHash && entry.FlowCount == 0 {
				negativeTaintClean = true
			}
		}
	}

	// If no taint findings and no negative confirmation, keep everything.
	if len(taintActiveCWEs) == 0 && !negativeTaintClean {
		return findings
	}

	// Second pass: suppress regex-only findings for covered CWEs.
	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		tier := findingTier(&f)

		// Keep non-regex findings always.
		if tier > tierRegex {
			kept = append(kept, f)
			continue
		}

		// If negative taint confirmation, suppress ALL taint-coverable CWEs.
		if negativeTaintClean && taintCoverableCWEs[cwe] {
			continue
		}

		// If active taint findings exist for this CWE, suppress regex.
		if taintActiveCWEs[cwe] {
			continue
		}

		// Keep regex findings for CWEs not covered by either path.
		kept = append(kept, f)
	}
	return kept
}
