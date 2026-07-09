package scanner

import (
	"strings"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-rules/rules"
)

// withinScanTaintAuthoritative lists languages whose taint engine has
// mature-enough RECALL that, when it produces no flow for a taint-coverable
// CWE in a scan, a regex-only match for that CWE can be treated as unconfirmed
// noise and suppressed WITHIN the same scan (no prior cache entry needed).
// Enabling a language here is a recall claim: it must be validated that
// suppressing the regex layer does not drop genuine detections the taint
// engine misses. Java is validated (OWASP-Java TPR held ~91% with FPR→~0).
// Languages NOT listed keep the cache-based negative-confirmation path only,
// because their taint engine still misses flows that the regex layer catches
// (blanket within-scan suppression drove Python xss/trustbound and several
// JS/Ruby CVE cases to ~0% TPR). Extend ONLY after per-language validation.
var withinScanTaintAuthoritative = map[rules.Language]bool{
	rules.LangJava: true,
}

// taintUnconfirmableRules lists regex rule IDs whose vulnerability SHAPE the
// taint engine structurally cannot model, so a taint "clean" verdict for their
// CWE is meaningless for them — the regex IS the only detection path. These
// must NEVER be suppressed by the taint-clean negative-confirmation below
// (doing so silently disables the detection, and — because the taint cache's
// flow count for the shape is itself nondeterministic — does so flakily). Their
// false positives are handled by the per-language scanner FP filter, not taint.
//
//   - BATOU-NOSQL-001: Mongo object-literal `$where: ...` NoSQL injection.
//     tsflow keys its $where sink as a method call, so it stays inert for the
//     object-property form (the #1228 detection is regex-only by design);
//     jsScanHasNoSQLGuard handles its FPs.
//   - BATOU-CS-025: C# LDAP injection via the `searcher.Filter = "..." + x`
//     PROPERTY-ASSIGNMENT form. tsflow models the LDAP sink as a constructor
//     call (`new DirectorySearcher(filter)`), so a `.Filter` attribute write is
//     structurally unmodelled — once the `new DirectorySearcher(...)` taint sink
//     began firing CWE-90 in the file, the taint-clean verdict for the SEPARATE
//     `.Filter =` line would otherwise suppress this regex-only detection.
var taintUnconfirmableRules = map[string]bool{
	"BATOU-NOSQL-001": true,
	"BATOU-CS-025":    true,
}

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

// cweAliases maps near-synonym CWEs to the canonical CWE the taint engine
// reports. Eval-injection findings, for example, are tagged CWE-94 by
// SnkEval, but several regex rules use the closely related CWE-95 (Eval
// Injection) — without an alias the active-taint suppression pass misses
// the cross-tag match and a regex CWE-95 finding survives next to its
// CWE-94 taint twin.
var cweAliases = map[string]string{
	"95": "94", // Eval Injection ⇄ Code Injection (SnkEval)
}

// canonicalCWE returns the canonical CWE for taint-coverage matching.
func canonicalCWE(cwe string) string {
	if alias, ok := cweAliases[cwe]; ok {
		return alias
	}
	return cwe
}

// SuppressRegexWhenTaintClean suppresses regex-only findings for
// taint-coverable CWEs using two complementary strategies:
//
//  1. Active taint: If taint analysis produced findings for specific CWEs
//     in this scan, regex-only findings for those same CWEs are redundant
//     and suppressed (the taint findings are higher fidelity).
//
//  2. Negative confirmation: If the taint engine actually RAN on this file
//     and produced no flow for any taint-coverable CWE, regex-only findings
//     for ALL taint-coverable CWEs are suppressed — the dataflow engine is
//     the authority for these categories, so an unconfirmed regex match is
//     enrichment, not a standalone finding. The "taint ran" signal comes
//     from this scan (taintRan, set when a taint-supported language was
//     analysed and the scan was not degraded by a timeout/panic); when that
//     is unavailable it falls back to the persisted file taint cache (a
//     matching content hash with zero flows from a prior scan).
//
// If neither condition holds (no taint findings, taint did not run, and no
// matching cache entry), regex findings are kept as the only signal.
func SuppressRegexWhenTaintClean(findings []rules.Finding, cg *graph.CallGraph, filePath string, contentHash uint64, taintRan bool) []rules.Finding {
	// First pass: check which taint-coverable CWEs have taint/AST findings.
	taintActiveCWEs := make(map[string]bool)
	for _, f := range findings {
		tier := findingTier(&f)
		if tier <= tierRegex {
			continue
		}
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		if cwe != "" && taintCoverableCWEs[cwe] {
			taintActiveCWEs[canonicalCWE(cwe)] = true
		}
	}

	// Negative confirmation: taint produced no finding for any coverable CWE.
	negativeTaintClean := false
	if len(taintActiveCWEs) == 0 {
		if taintRan {
			// The taint engine executed on this file in THIS scan and found
			// no coverable-CWE flow → regex-only matches for those CWEs are
			// unconfirmed. No persisted cache entry required (a one-shot
			// scan, e.g. the OWASP harness, has none).
			negativeTaintClean = true
		} else if cg != nil {
			// Fall back to the persisted cache: a prior scan of identical
			// content ran taint and found zero flows.
			//
			// TrustedForSuppression gates this on the entry being HMAC-signed
			// by THIS machine's local key. A .batou/callgraph.json shipped in
			// a repository can carry FlowCount==0 entries with a correct
			// (attacker-computable) FNV content hash, which would otherwise
			// silence real regex detections wholesale; without the local key
			// it cannot forge a valid signature, so a poisoned entry is never
			// trusted to suppress. Legitimate same-machine incremental caches
			// (written by the user's own prior scan) verify and still suppress.
			if entry := cg.GetFileTaintCache(filePath); entry != nil {
				if entry.ContentHash == contentHash && entry.FlowCount == 0 &&
					entry.TrustedForSuppression(filePath) {
					negativeTaintClean = true
				}
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

		// Keep rules whose shape the taint engine structurally cannot model —
		// a taint-clean verdict says nothing about them, so suppressing here
		// would silently (and, given the cache's nondeterministic flow count,
		// flakily) disable the detection. Their FPs are filtered per-language.
		if taintUnconfirmableRules[f.RuleID] {
			kept = append(kept, f)
			continue
		}

		// If negative taint confirmation, suppress ALL taint-coverable CWEs.
		if negativeTaintClean && taintCoverableCWEs[cwe] {
			continue
		}

		// If active taint findings exist for this CWE, suppress regex.
		if taintActiveCWEs[canonicalCWE(cwe)] {
			continue
		}

		// Keep regex findings for CWEs not covered by either path.
		kept = append(kept, f)
	}
	return kept
}
