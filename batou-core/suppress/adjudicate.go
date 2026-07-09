package suppress

// adjudicate.go — write-time adjudication of suppression rationales against the
// suppressed finding's own dataflow.
//
// When a developer (or an AI agent) writes
//
//	// batou:ignore BATOU-TAINT-sql_query -- parameterized query
//	cur.execute("SELECT * FROM t WHERE id = '" + uid + "'")
//
// the stated reason ("parameterized query") is a verifiable claim about the
// dataflow that batou already computed. If the suppressed finding is a taint
// flow whose sink argument is string-concatenated and whose path contains NO
// sanitizer node, the claim is false — the suppression hides a real bug behind
// a plausible-sounding excuse.
//
// Adjudicate machine-checks the reason against the finding's flow using a
// deterministic claim → verifiable-property table (no model calls) and emits a
// BATOU-SUPPRESS-UNJUSTIFIED finding when the reason is CONTRADICTED. The
// original finding stays suppressed; this new finding flags the *suppression*.
//
// Reasons that are not machine-verifiable (e.g. "false positive", "test
// fixture", "by design") are left alone — silence, not a flag.

import (
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// UnjustifiedRuleID is the rule emitted when a suppression's stated reason is
// contradicted by the suppressed finding's own dataflow.
const UnjustifiedRuleID = "BATOU-SUPPRESS-UNJUSTIFIED"

// claimKind classifies the family of safety claim a suppression reason makes.
type claimKind int

const (
	claimNone          claimKind = iota
	claimParameterized           // "parameterized | prepared | bound | placeholder"
	claimSanitized               // "sanitized | escaped | validated | cleaned | encoded"
	claimTrustedInput            // "not user input | hardcoded | constant | trusted | internal"
)

// classifyReason maps a free-text suppression reason onto a verifiable claim
// family. It returns claimNone for empty reasons and for reasons that are not
// machine-verifiable against dataflow (e.g. "false positive", "test fixture",
// "by design", "acceptable risk", "wont fix"). Returning claimNone means
// "do not adjudicate" — only affirmative, checkable safety claims are judged.
//
// The unverifiable list is checked FIRST so that a reason like "false positive,
// input is sanitized elsewhere" is treated as unverifiable (the author is
// asserting an out-of-band judgment, not a property of this flow).
func classifyReason(reason string) claimKind {
	r := strings.ToLower(strings.TrimSpace(reason))
	if r == "" {
		return claimNone
	}

	// Unverifiable escape hatches — never flag these. They assert an
	// out-of-band human judgment, not a property of the computed flow.
	for _, u := range unverifiablePhrases {
		if strings.Contains(r, u) {
			return claimNone
		}
	}

	// Trusted-source claims (checked before sanitized: "not user input" should
	// be judged against source_type, not treated as a sanitizer claim).
	for _, kw := range trustedInputKeywords {
		if strings.Contains(r, kw) {
			return claimTrustedInput
		}
	}

	// Parameterized / prepared-statement claims (a specific SQL sub-claim of
	// "sanitized" with its own contradiction logic).
	for _, kw := range parameterizedKeywords {
		if strings.Contains(r, kw) {
			return claimParameterized
		}
	}

	// General sanitization / validation / encoding claims.
	for _, kw := range sanitizedKeywords {
		if strings.Contains(r, kw) {
			return claimSanitized
		}
	}

	return claimNone
}

// unverifiablePhrases are reasons that assert a judgment batou cannot check
// against the flow. We never emit BATOU-SUPPRESS-UNJUSTIFIED for these.
var unverifiablePhrases = []string{
	"false positive",
	"false-positive",
	"fp ",
	"not exploitable",
	"not reachable",
	"unreachable",
	"test fixture",
	"test only",
	"test-only",
	"fixture",
	"example code",
	"demo",
	"by design",
	"intentional",
	"acceptable risk",
	"accepted risk",
	"risk accepted",
	"wont fix",
	"won't fix",
	"wontfix",
	"legacy",
	"todo",
	"will fix",
	"tracked in",
}

// trustedInputKeywords claim the source is not attacker-controlled.
// Contradicted when the suppressed flow's source_type is a user/external source.
var trustedInputKeywords = []string{
	"not user input",
	"not user-input",
	"not user controlled",
	"not user-controlled",
	"not attacker",
	"hardcoded",
	"hard-coded",
	"hard coded",
	"constant",
	"literal value",
	"trusted",
	"internal only",
	"internal-only",
	"internal source",
	"static value",
}

// parameterizedKeywords claim a SQL query is bound via placeholders.
// Contradicted when the suppressed flow reaches a query sink with no sanitizer
// node AND the sink argument is built by concatenation/interpolation.
var parameterizedKeywords = []string{
	"parameterized",
	"parameterised",
	"parametrized",
	"parametrised",
	"prepared statement",
	"prepared-statement",
	"prepared query",
	"bound parameter",
	"bound param",
	"placeholder",
	"bind variable",
	"query binding",
}

// sanitizedKeywords claim the data is neutralized before the sink.
// Contradicted when the suppressed taint flow contains no sanitizer node.
var sanitizedKeywords = []string{
	"sanitized",
	"sanitised",
	"sanitize",
	"sanitise",
	"escaped",
	"escape",
	"validated",
	"validation",
	"cleaned",
	"cleansed",
	"encoded",
	"encode",
	"filtered",
	"neutralized",
	"neutralised",
	"stripped",
	"allowlist",
	"allow-list",
	"whitelist",
}

// userExternalSources are taint source_type values that represent
// attacker-controllable / external input. Mirrors taint.SourceCategory string
// values (stored as strings on rules.Finding to avoid an import cycle).
var userExternalSources = map[string]bool{
	"user_input":   true,
	"network":      true,
	"external":     true,
	"deserialized": true,
	"cli_arg":      true,
}

// querySinks are sink_type values for which "parameterized/prepared" is a
// meaningful, checkable claim.
var querySinks = map[string]bool{
	"sql_query":   true,
	"nosql_query": true,
	"ldap_query":  true,
	"xpath_query": true,
}

// Adjudication is the verdict for one suppressed finding whose reason was
// machine-checked and found to be contradicted by the flow.
type Adjudication struct {
	Finding        rules.Finding // the new BATOU-SUPPRESS-UNJUSTIFIED finding
	OriginalRuleID string        // the rule that was suppressed
	Claim          string        // human label of the claim family
	Contradiction  string        // why the flow contradicts the claim
}

// Adjudicate inspects every suppressed finding, finds the suppression directive
// whose reason covers it, and — when the reason makes an affirmative safety
// claim that the finding's own dataflow contradicts — produces a
// BATOU-SUPPRESS-UNJUSTIFIED finding.
//
// s must be the Suppressions used to produce `suppressed` (so the directive
// reasons line up). Returns nil when nothing is contradicted.
func Adjudicate(s *Suppressions, suppressed []rules.Finding) []Adjudication {
	if s == nil || len(suppressed) == 0 {
		return nil
	}
	var out []Adjudication
	for _, f := range suppressed {
		// Never adjudicate our own meta-findings or the review nudge.
		if f.RuleID == UnjustifiedRuleID || unsuppressibleRules[f.RuleID] {
			continue
		}
		// Never adjudicate findings suppressed by a gosec/nolint annotation.
		// `#nosec G710 -- redirectURL validated by RedirectValidator` is the
		// developer's out-of-band gosec rationale, not a checkable claim about
		// Batou's computed flow. Machine-checking it (e.g. flagging "validated"
		// against a surviving taint flow) would re-flag every audited gosec
		// exception — exactly what honoring the annotation is meant to avoid.
		if s.isGosecSuppressed(f) {
			continue
		}
		reason, ok := s.reasonForFinding(f)
		if !ok || reason == "" {
			continue
		}
		kind := classifyReason(reason)
		if kind == claimNone {
			continue
		}
		contradiction, contradicted := contradicts(kind, f)
		if !contradicted {
			continue
		}
		out = append(out, Adjudication{
			Finding:        buildUnjustifiedFinding(f, reason, kind, contradiction),
			OriginalRuleID: f.RuleID,
			Claim:          claimLabel(kind),
			Contradiction:  contradiction,
		})
	}
	return out
}

// contradicts applies the deterministic claim→flow-property table. It returns a
// human-readable contradiction string and true when the suppressed finding's
// flow refutes the claim; otherwise false.
//
// The central, conservative fact this relies on: every batou taint engine cuts
// a flow when it reaches a real sanitizer, so a taint finding that SURVIVED to
// the point of being suppressed has, by construction, NO effective sanitizer in
// its path. (taint.taintPath never emits a "sanitizer-bypassed" step — see
// taint/types.go.) We therefore only judge claims against taint findings, where
// the absence of sanitization is a proven property rather than a guess.
func contradicts(kind claimKind, f rules.Finding) (string, bool) {
	// Only taint/interproc dataflow findings carry the properties we verify.
	if !isTaintFinding(f) {
		return "", false
	}

	switch kind {
	case claimTrustedInput:
		if userExternalSources[f.SourceCategory] {
			return "the suppressed flow's source is '" + f.SourceCategory +
				"' (attacker-controllable), contradicting the claim that the value is trusted / not user input", true
		}
		return "", false

	case claimParameterized:
		// Claim is only meaningful for query sinks.
		if !querySinks[f.SinkCategory] {
			return "", false
		}
		// A surviving taint flow has no sanitizer node (engine cuts at
		// sanitizers). If the sink argument is also built by concat/interp,
		// the query is demonstrably NOT parameterized.
		if !flowHasSanitizer(f) && sinkArgIsConcatenated(f) {
			return "the suppressed flow reaches " + f.SinkCategory +
				" with a concatenated/interpolated argument and NO sanitizer in its taint path — the query is not actually parameterized", true
		}
		// Even without a detectable concat, a parameterized query would not
		// produce a taint flow at all; the surviving flow refutes the binding claim.
		if !flowHasSanitizer(f) {
			return "a parameterized/prepared query breaks the taint flow, but the suppressed " +
				f.SinkCategory + " flow survived with no sanitizer node — the binding claim is not reflected in the dataflow", true
		}
		return "", false

	case claimSanitized:
		if !flowHasSanitizer(f) {
			return "the suppressed taint flow from '" + f.SourceCategory + "' to '" + f.SinkCategory +
				"' contains NO sanitizer node — the data is not actually sanitized/validated/escaped before the sink", true
		}
		return "", false
	}
	return "", false
}

// isTaintFinding reports whether f is a dataflow (taint or interprocedural)
// finding. These are the only findings whose source/sink/path properties we can
// verify a reason against.
func isTaintFinding(f rules.Finding) bool {
	for _, t := range f.Tags {
		if t == "taint-analysis" || t == "interprocedural" || t == "dataflow" {
			return true
		}
	}
	up := strings.ToUpper(f.RuleID)
	return strings.HasPrefix(up, "BATOU-TAINT-") || strings.Contains(up, "INTERPROC")
}

// flowHasSanitizer reports whether the finding's taint path contains a
// sanitizer node. In practice batou's engines never emit a sanitizer-bypassed
// step (a real sanitizer cuts the flow), so this is virtually always false for a
// surviving taint finding — but we check defensively so that a future engine
// that DOES record a bypassed sanitizer is judged correctly (the author may be
// right that a sanitizer is present even if it was bypassed).
func flowHasSanitizer(f rules.Finding) bool {
	for _, step := range f.TaintPath {
		if step.Kind == rules.TaintStepSanitizerBypassed {
			return true
		}
	}
	return false
}

// concatTokens are textual markers of string concatenation / interpolation that
// appear in a taint finding's MatchedText or sink-step label when the sink
// argument was built from untrusted pieces rather than passed as a bound param.
var concatTokens = []string{
	" + ", // a + b
	" . ", // PHP/Perl concat
	".concat(",
	"%s",  // printf-style / Python %
	"% (", // Python "..." % (
	"%(",
	".format(",
	"f'", // python f-string
	"f\"",
	"${",            // JS/Kotlin template literal, shell
	"#{",            // Ruby interpolation
	"<<",            // heredoc-ish
	"||",            // SQL concat operator
	"str(",          // common stringify-into-query
	"+uid", "+ uid", // defensive: tight concat without spaces
}

// sinkArgIsConcatenated heuristically reports whether the suppressed finding's
// sink argument was built by concatenation/interpolation, using the textual
// flow rendering (MatchedText) and the sink-step label. This is the positive
// signal for "this is NOT a parameterized query".
func sinkArgIsConcatenated(f rules.Finding) bool {
	hay := f.MatchedText
	for _, st := range f.TaintPath {
		hay += "\n" + st.Label
	}
	low := strings.ToLower(hay)
	for _, tok := range concatTokens {
		if strings.Contains(low, strings.ToLower(tok)) {
			return true
		}
	}
	// A multi-variable flow (source → var → … → sink) that lands in a query
	// sink without binding is itself evidence the value was interpolated: a
	// truly parameterized call would not have produced a taint flow.
	return false
}

// claimLabel returns a short human label for a claim family.
func claimLabel(k claimKind) string {
	switch k {
	case claimParameterized:
		return "parameterized/prepared query"
	case claimSanitized:
		return "sanitized/validated/escaped"
	case claimTrustedInput:
		return "trusted / not user input"
	}
	return "unknown"
}

// buildUnjustifiedFinding constructs the BATOU-SUPPRESS-UNJUSTIFIED finding that
// flags a contradicted suppression. It points at the suppressed finding's sink
// line and carries the claim, the contradiction, and the underlying flow so the
// reader sees exactly why the rationale does not hold.
func buildUnjustifiedFinding(orig rules.Finding, reason string, kind claimKind, contradiction string) rules.Finding {
	desc := "A `batou:ignore` directive suppressed " + orig.RuleID +
		" with the reason \"" + reason + "\", which claims the data is " + claimLabel(kind) +
		". That claim is contradicted by the suppressed finding's own dataflow: " + contradiction +
		". Either fix the underlying issue and remove the suppression, or correct the reason to one that batou cannot refute from the flow (e.g. an out-of-band mitigation)."

	f := rules.Finding{
		RuleID:        UnjustifiedRuleID,
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Suppression rationale contradicted by dataflow",
		Description:   desc,
		Suggestion:    "Remove the unjustified `batou:ignore` and fix the " + orig.SinkCategory + " sink, or replace the reason with a verifiable one.",
		FilePath:      orig.FilePath,
		LineNumber:    orig.LineNumber,
		Column:        orig.Column,
		CWEID:         orig.CWEID,
		OWASPCategory: orig.OWASPCategory,
		Language:      orig.Language,
		// Carry the suppressed flow's source/sink and path so the reader sees
		// the evidence. These also lift the finding above the regex tier in
		// dirscan's default view.
		SourceCategory: orig.SourceCategory,
		SinkCategory:   orig.SinkCategory,
		TaintPath:      orig.TaintPath,
		MatchedText:    orig.MatchedText,
		// High, deterministic confidence: the contradiction is computed, not
		// guessed. RiskScore is set by the pipeline (High × ~0.9 ≈ 0.72) so a
		// contradicted suppression of a real flow blocks.
		Confidence:      "high",
		ConfidenceScore: 0.9,
		// "taint-analysis"/"dataflow" tags keep FindingTier above TierRegex so
		// the default `batou scan` (which drops regex-tier) still emits this.
		Tags: []string{"suppress-adjudication", "taint-analysis", "dataflow", "unjustified-suppression"},
	}
	return f
}

// AdjudicationFindings extracts just the rules.Finding values from a slice of
// Adjudications — a convenience for the scanner, which only needs the findings.
func AdjudicationFindings(adj []Adjudication) []rules.Finding {
	if len(adj) == 0 {
		return nil
	}
	out := make([]rules.Finding, 0, len(adj))
	for _, a := range adj {
		out = append(out, a.Finding)
	}
	return out
}
