package scanner

import (
	"strings"

	"github.com/turenlabs/batou-core/fpfilter"
	"github.com/turenlabs/batou-rules/rules"
)

// Base confidence scores assigned by analysis tier.
const (
	ConfBaseRegexLow    = 0.3
	ConfBaseRegexMedium = 0.4
	ConfBaseRegexHigh   = 0.5
	ConfBaseAST         = 0.7
	ConfBaseInterproc   = 0.8
	ConfMultiLayerBoost = 0.1
	ConfBlockThreshold  = 0.7

	// RiskBlockThreshold is the minimum RiskScore for a finding to block a write.
	RiskBlockThreshold = 0.7
)

// ComputeRiskScore sets a finding's RiskScore from its severity and confidence.
func ComputeRiskScore(f *rules.Finding) {
	f.RiskScore = f.Severity.ImpactWeight() * f.ConfidenceScore
}

// AssignBaseConfidenceScore sets a baseline ConfidenceScore on a finding
// based on which analysis tier produced it. Taint findings already carry
// a float64 score from the taint engine, so those are preserved.
func AssignBaseConfidenceScore(f *rules.Finding) {
	switch findingTier(f) {
	case tierTaint:
		// Taint engines set a float64 flow-confidence at creation — preserve it.
		if f.ConfidenceScore == 0 {
			f.ConfidenceScore = 0.6 // fallback; should not normally reach here
		}
	case tierInterprocedural:
		if f.ConfidenceScore == 0 {
			f.ConfidenceScore = ConfBaseInterproc
		}
	case tierAST:
		// AST analyzers MAY intentionally set a higher confidence than the base
		// (e.g. phpast publicpage = 0.85); preserve a non-zero preset, else base.
		if f.ConfidenceScore == 0 {
			f.ConfidenceScore = ConfBaseAST
		}
	default: // tierRegex
		// The regex tier score is ALWAYS the tier floor, NEVER a value a regex
		// rule pre-set on itself. This is the regex-never-blocks invariant:
		// BATOU-INJ-027 pre-set ConfidenceScore=0.7/0.8 and thereby reached the
		// 0.70 block lane (verified hook exit 2); recomputing from the tier here
		// holds every regex Critical to a hint (RiskScore <= 0.5).
		switch f.Confidence {
		case "high":
			f.ConfidenceScore = ConfBaseRegexHigh
		case "medium":
			f.ConfidenceScore = ConfBaseRegexMedium
		default:
			f.ConfidenceScore = ConfBaseRegexLow
		}
	}
}

// InterprocTestInfraCap is the confidence ceiling applied to cross-file
// BATOU-INTERPROC findings whose file path is a test/fixture/script/build-
// tooling/scale-test path. 0.3 sits below ConfBlockThreshold (0.7) so these
// findings stay visible as hints but never block writes or dominate triage.
const InterprocTestInfraCap = 0.3

// CapInterprocConfidenceForTestPaths down-weights cross-file BATOU-INTERPROC
// findings when their FilePath is a test, fixture, build script, scale-test,
// or other non-production support path. Production findings are untouched.
//
// Same logic as the test-file cap applied in scanner.Scan for per-file
// findings, but specialised to BATOU-INTERPROC because cross-file findings
// emerge from the call-graph walk (graph.WalkCrossFileTaintFlows) and bypass
// the per-file pipeline that already applies fpfilter-based capping.
// Keeping it in this layer (scanner/confidence) means both code paths —
// per-file scan and dirscan's emitCrossFileFindings — can share it.
func CapInterprocConfidenceForTestPaths(f *rules.Finding) {
	if !strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") {
		return
	}
	if !fpfilter.IsInfraOrTestPath(f.FilePath) {
		return
	}
	if f.ConfidenceScore > InterprocTestInfraCap {
		f.ConfidenceScore = InterprocTestInfraCap
	}
}

// StyleHeuristicCap is the confidence ceiling applied to low-value,
// style/heuristic findings whose base tier (AST = 0.7) would otherwise float
// them into the high-confidence headline and — for High-severity ones — the
// blocking lane (RiskScore = 0.8 × 0.7 = 0.56 today; a multi-layer boost can
// push them to/over 0.7). 0.5 keeps them visible as MEDIUM-confidence hints
// (recall/coverage unchanged at minConf=0) but holds them below the 0.7
// block/headline threshold so a single style nit can never block a write or
// dominate triage on a real codebase. Real-world smoke tests (Grafana/Keycloak)
// showed these classes as the #1–#2 high-confidence finding volume despite
// being pure style or true-but-trivial signal.
const StyleHeuristicCap = 0.5

// lowValueHeuristicRules are the rule IDs whose findings are demoted to
// hint tier by CapLowValueHeuristicConfidence. These are STYLE / LOW-SIGNAL
// detections that are correct often enough to keep emitting (so coverage and
// recall benches measured at minConf=0 are unchanged) but are too noisy and
// too low-impact to ever block a write or headline a real-repo scan:
//
//   - BATOU-AST-005  Go import-level weak-crypto (md5/sha1 for fingerprints,
//     math/rand in non-security code) — CRY-001 flags the real
//     security-critical uses with full context.
//   - BATOU-AST-007  Go defer-in-loop — a resource-hygiene lint, not a vuln.
//   - BATOU-AST-008  Go goroutine-without-context — pure concurrency style.
//   - BATOU-TAINT-log_output  CWE-117 log injection — overwhelmingly logs of
//     authenticated internal values, Throwable.getMessage(), and
//     primitive DB IDs; true-but-trivial. (Medium severity, so it
//     never blocks, but at cs=1.0 it dominates the headline.)
var lowValueHeuristicRules = map[string]bool{
	"BATOU-AST-005":            true,
	"BATOU-AST-007":            true,
	"BATOU-AST-008":            true,
	"BATOU-TAINT-log_output":   true,
	"BATOU-DEPVULN-log_output": true,
}

// The per-rule AST-structural cap (formerly ASTStructuralCap /
// astStructuralBlockingRules / CapASTStructuralConfidence) was removed: the
// external-origin block invariant below (CapNonExternalOriginConfidence, case
// (A) NO-FLOW → NO-BLOCK) systematically caps every pure-AST-structural Critical
// — each carries a NULL taint path, so it has no confirming external-origin flow
// — to ExternalOriginCap (0.65, a hint). That subsumes the hand-maintained
// ~40-rule denylist with no rule IDs to enumerate or keep in sync. A genuinely
// reachable instance still blocks via its separate BATOU-TAINT-* twin, which
// wins dedup at the taint tier with a real external SourceCategory.

// ExternalOriginCap is the confidence ceiling applied by the external-origin
// block invariant. A finding that is NOT confirmed by a taint/interproc flow
// from a genuine external source is demoted to at most this value — just below
// the 0.70 block threshold — so it stays visible as a MEDIUM-confidence hint
// but can never block a write. 0.65 keeps every such finding emitting (recall
// at minConf=0 unchanged) while removing it from the block-eligible set.
const ExternalOriginCap = 0.65

// genuineExternalSourceCategories are the taint SourceCategory string values
// (mirrors of taint.SourceCategory) that represent a PROVABLY external origin:
// the data crossed a trust boundary from an attacker-influenceable channel.
// These mirror the external-allow-set: HTTP request bindings, network/socket
// reads, file reads, deserialized upstream data, database read-back
// (second-order), and any source the catalog explicitly classes "external"
// (message-queue payloads, cloud-storage objects, shared caches).
//
// DELIBERATELY EXCLUDED (ambient / operator-controlled / same-origin app
// state, not attacker-supplied request input):
//   - env_var        (SrcEnvVar)        — set by the operator at container/VM startup.
//   - cli_arg        (SrcCLIArg)        — provided by the operator at invocation.
//   - client_storage (SrcClientStorage) — window.localStorage/sessionStorage reads;
//     same-origin app state the page itself persisted, not a request channel.
//     Still emits as a hint (persisted-XSS is a real second-order class).
//
// A taint flow whose source falls outside this set does not confer
// block-eligibility: it is capped to ExternalOriginCap (hint).
var genuineExternalSourceCategories = map[string]bool{
	"user_input":   true, // SrcUserInput   — HTTP params, form data, URL query, request body
	"network":      true, // SrcNetwork     — socket reads, untrusted remote peer
	"file_read":    true, // SrcFileRead    — file contents (path may be attacker-derived)
	"database":     true, // SrcDatabase    — query read-back (second-order injection)
	"deserialized": true, // SrcDeserialized— deserialized upstream bytes (HTTP body / socket)
	"external":     true, // SrcExternal    — message queue, cloud storage, shared cache, S3, etc.
}

// weakParamSourceLabelPrefix is the marker the param-NAME-as-source fabricators
// (the conf-0.6, NON-handler, name-only seeders in astflow/tsflow) stamp onto
// their SourceDef.MethodName. It survives into the finding's
// TaintPath[0].Label (via TaintFlow.taintPath()), so the block gate can
// recognise a fabricated "external" origin that is really just a parameter
// whose NAME happened to look input-like ('data', 'path', 'query') in an
// internal helper. The genuine handler/decorator/framework param bindings
// (conf 0.9: web-handler params, NestJS @Body/@Query decorators, FastAPI
// Pydantic bodies, Gin/Echo framework entry points) use the ordinary
// "parameter:" prefix and are NOT demoted — their binding IS the external
// proof. See seedParams/seedJSParamBindings in taint/tsflow/walker.go and
// the Go param seeder in taint/astflow/walker.go.
const weakParamSourceLabelPrefix = "param-name:"

// hasExternalOrigin reports whether a finding is BLOCK-ELIGIBLE under the
// external-origin invariant: it is confirmed by a taint/interproc flow AND
// that flow's SOURCE is a genuine external source.
//
// It reads ONLY fields that survive dedup (Tags, TaintPath, SourceCategory),
// so it is correct to call post-dedup where the raw TaintFlow objects are gone.
//
//	(A) NO-FLOW → NO-BLOCK: a finding whose confirming tier is regex- or
//	    AST-structural-only (no taint/interproc tag AND no TaintPath) is NOT
//	    block-eligible. This generalizes and replaces the former hand-maintained
//	    per-rule AST-structural cap denylist: every pure-structural Critical with
//	    a null taint path is caught here by the absence of a flow, with no rule
//	    ID to enumerate.
//
//	(B) WEAK-SOURCE → NO-BLOCK: a taint-confirmed finding whose flow SOURCE is
//	    ambient (env_var / cli_arg), a param-NAME-as-source fabricator, or an
//	    unrecognised/empty category is NOT block-eligible.
//
// FAIL-SAFE: any case it cannot positively confirm as external returns false
// (cap to hint). A gate should be high-precision; the recall cost is measured
// on the CVE suite.
func hasExternalOrigin(f *rules.Finding) bool {
	// (A) Require a confirming taint or interprocedural flow. The winner
	// Finding of a dedup group retains its tier tags; recover the tier the
	// same way dedup does. A pure regex/AST winner has neither tag and an
	// empty TaintPath → no flow → not block-eligible.
	tier := findingTier(f)
	hasFlow := tier == tierTaint || tier == tierInterprocedural || len(f.TaintPath) > 0
	if !hasFlow {
		return false
	}

	// (B) The flow exists — gate on its SOURCE.
	//
	// Param-NAME-as-source fabricator: the name-only (conf-0.6) seeder marks
	// its source label, which is preserved as TaintPath[0].Label. A flow that
	// originates from a parameter merely *named* like input (in a DAO/helper
	// layer, say) is not proof of external reachability.
	if len(f.TaintPath) > 0 &&
		strings.HasPrefix(f.TaintPath[0].Label, weakParamSourceLabelPrefix) {
		return false
	}

	// Source category must be a genuine external class. Ambient sources
	// (env_var, cli_arg), unrecognised categories, and an empty category all
	// fall through to the fail-safe (not block-eligible).
	return genuineExternalSourceCategories[f.SourceCategory]
}

// CapNonExternalOriginConfidence enforces the external-origin block invariant:
// a finding that is not confirmed by a taint/interproc flow from a genuine
// external source is demoted to at most ExternalOriginCap (hint). Like the
// other caps this is a DEMOTION, not a deletion — the finding still emits, so
// recall measured at minConf=0 (OWASP, the CVE benches) is unchanged; only its
// block-eligibility is removed. The cap only lowers, never raises.
//
// This is the single invariant that retires the per-rule whack-a-mole: where
// the former CapASTStructuralConfidence enumerated ~40 AST-structural rule IDs,
// this gate asks the systematic question "is there a confirming external-origin
// flow?" and caps when the answer is no. The per-rule denylist has been removed
// entirely — every rule it listed is a null-taint structural finding that this
// gate independently caps to the same ExternalOriginCap (0.65) value.
func CapNonExternalOriginConfidence(f *rules.Finding) {
	if hasExternalOrigin(f) {
		return
	}
	if f.ConfidenceScore > ExternalOriginCap {
		f.ConfidenceScore = ExternalOriginCap
	}
}

// CapLowValueHeuristicConfidence demotes low-value style/heuristic findings
// (see lowValueHeuristicRules) to at most StyleHeuristicCap so they stay
// hints rather than blocking-tier or high-confidence-headline findings.
//
// This is a DEMOTION, not a deletion: the findings are still emitted, so any
// recall/coverage measured at minConf=0 (the OWASP and CVE bench harnesses)
// is unchanged — only their position in the confidence ordering moves. The
// cap only lowers; it never raises a score.
func CapLowValueHeuristicConfidence(f *rules.Finding) {
	if !lowValueHeuristicRules[f.RuleID] {
		return
	}
	if f.ConfidenceScore > StyleHeuristicCap {
		f.ConfidenceScore = StyleHeuristicCap
	}
}

// BoostConfidenceForMultiLayer increases a finding's confidence score
// when multiple independent analysis tiers confirmed the same issue.
// Each additional tier beyond the first adds ConfMultiLayerBoost.
// The score is capped at 1.0.
func BoostConfidenceForMultiLayer(f *rules.Finding, distinctTiers int) {
	if distinctTiers <= 1 {
		return
	}
	boost := float64(distinctTiers-1) * ConfMultiLayerBoost
	f.ConfidenceScore += boost
	if f.ConfidenceScore > 1.0 {
		f.ConfidenceScore = 1.0
	}
}
