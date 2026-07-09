package reporter

// SARIF (Static Analysis Results Interchange Format) export — EXPERIMENTAL.
//
// SARIF export with layer/confidence/taint-path provenance.
// It converts a Batou ScanResult
// into a SARIF v2.1.0 log so Batou's findings can feed the downstream
// remediation platforms (Pixee, Aikido, Snyk, GitHub code scanning) that ingest
// SARIF from 50+ tools.
//
// What makes this worth shipping: most SAST SARIF
// output is a flat list of findings. Batou emits, per result:
//   - the source→sink taint path as a SARIF codeFlow / threadFlow (proving the
//     cross-file, multi-language dataflow chain),
//   - the ConfidenceScore and RiskScore as SARIF result properties,
//   - which analysis tier(s) confirmed the finding, inferred from the rule-ID
//     namespace (regex / AST / taint / interproc) so a downstream consumer can
//     see multi-layer confirmation,
//   - the CWE as a taxonomy reference.
//
// This file is deliberately self-contained: it reads only the already-populated
// rules.Finding / rules.TaintStep fields (TaintStep was explicitly designed as a
// superset of SARIF threadFlow needs — see rule.go) and the existing ScanResult.
// It touches NO engine internals, NO taint walker, NO shared analysis state — it
// is a pure serialization layer over data the pipeline already computes.
//
// Status: EXPERIMENTAL. Not wired into the CLI or hook output yet; gated behind
// an explicit ToSARIF call so it cannot affect the block/hint decision path.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// SARIF schema constants.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifToolURI = "https://github.com/turenlabs/batou"

	// sarifSrcRootID is the uriBaseId under which repo-relative artifact URIs
	// are emitted. "SRCROOT" is the conventional name GitHub code scanning and
	// most SARIF viewers resolve against the repository checkout root.
	sarifSrcRootID = "SRCROOT"

	// sarifFingerprintKey is the partialFingerprints key GitHub code scanning
	// uses for alert identity across analyses. When a tool supplies it, GitHub
	// uses it verbatim instead of computing its own line hash, so alert
	// identity survives unrelated edits that shift line numbers.
	sarifFingerprintKey = "primaryLocationLineHash"
)

// AnalysisTier names the Batou analysis layer that confirmed a finding. It is
// inferred from the rule-ID namespace so SARIF consumers can see multi-layer
// confirmation (Batou's structural advantage) without Batou exposing internals.
type AnalysisTier string

const (
	TierRegex     AnalysisTier = "regex"         // Layer 1: pattern rules (BATOU-XXX-NNN)
	TierAST       AnalysisTier = "ast"           // Layer 2: tree-sitter structural
	TierTaint     AnalysisTier = "taint"         // Layer 3: source→sink dataflow (BATOU-TAINT-*)
	TierInterproc AnalysisTier = "interproc"     // Layer 4: cross-file call graph (BATOU-INTERPROC-*)
	TierUnknown   AnalysisTier = "unknown"
)

// TierForFinding infers which analysis layer produced a finding from its rule
// ID and whether it carries a structured taint path. This is a heuristic over
// the rule-ID namespace, NOT a re-derivation of the pipeline — it reads the
// finding as-is.
func TierForFinding(f rules.Finding) AnalysisTier {
	switch {
	case hasPrefix(f.RuleID, "BATOU-INTERPROC"):
		return TierInterproc
	case hasPrefix(f.RuleID, "BATOU-TAINT"):
		return TierTaint
	case hasPrefix(f.RuleID, "BATOU-AST"):
		return TierAST
	case f.RuleID != "":
		// Any other BATOU-<CAT>-<N> rule is a Layer-1 regex rule. A taint path
		// on a regex-namespaced rule means the taint layer also confirmed it.
		if len(f.TaintPath) > 0 {
			return TierTaint
		}
		return TierRegex
	default:
		return TierUnknown
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// ---- SARIF v2.1.0 object model (minimal subset) ----

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool sarifTool `json:"tool"`
	// OriginalURIBaseIDs declares the base URIs that relative artifact URIs
	// resolve against (SARIF §3.14.14). Batou emits a single SRCROOT entry
	// pointing at the scan root, so consumers (GitHub code scanning, SARIF
	// viewers) can map repo-relative URIs back to absolute paths.
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult                    `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string            `json:"name"`
	InformationURI string            `json:"informationUri"`
	Rules          []sarifReportDesc `json:"rules,omitempty"`
}

type sarifReportDesc struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription *sarifMessage          `json:"shortDescription,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints carries the stable, content-based identity hash for
	// this result (SARIF §3.27.16). Without it, GitHub code scanning falls
	// back to hashing the surrounding lines itself and alerts churn whenever
	// edits elsewhere in the file shift line numbers.
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	CodeFlows           []sarifCodeFlow        `json:"codeFlows,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
	Suppressions        []sarifSuppression     `json:"suppressions,omitempty"`
}

type sarifSuppression struct {
	Kind          string       `json:"kind"`                    // "inSource" for batou:ignore
	Justification string       `json:"justification,omitempty"` // the batou:ignore reason
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
	// URIBaseID names the originalUriBaseIds entry the (relative) URI resolves
	// against — "SRCROOT" for paths under the scan root. Absent for paths that
	// could not be made root-relative (graceful fallback: URI is emitted as-is).
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int           `json:"startLine,omitempty"`
	StartColumn int           `json:"startColumn,omitempty"`
	Snippet     *sarifMessage `json:"snippet,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

// sarifLevel maps Batou severity to a SARIF result level.
func sarifLevel(sev rules.Severity) string {
	switch sev {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	case rules.Low:
		return "note"
	default:
		return "none"
	}
}

// rootRelativizer rewrites artifact paths to be relative to the scan root so
// SARIF consumers resolve them against the SRCROOT uriBaseId instead of
// receiving whatever absolute or ad-hoc path was passed on the command line.
// A zero/empty root disables rewriting (URIs pass through unchanged, no
// uriBaseId is emitted).
type rootRelativizer struct {
	absRoot string // absolute scan root; "" = relativization disabled
}

func newRootRelativizer(root string) rootRelativizer {
	if root == "" {
		return rootRelativizer{}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return rootRelativizer{}
	}
	return rootRelativizer{absRoot: abs}
}

// artifact builds the artifactLocation for path: root-relative with the
// SRCROOT uriBaseId when the path is inside the scan root, otherwise the
// path as-is (slash-normalized) with no uriBaseId — the graceful fallback
// for paths outside the root (e.g. cross-file flows into a sibling repo).
func (r rootRelativizer) artifact(path string) sarifArtifactLocation {
	if r.absRoot == "" || path == "" {
		return sarifArtifactLocation{URI: filepath.ToSlash(path)}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return sarifArtifactLocation{URI: filepath.ToSlash(path)}
	}
	rel, err := filepath.Rel(r.absRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return sarifArtifactLocation{URI: filepath.ToSlash(path)}
	}
	if rel == "." {
		rel = ""
	}
	return sarifArtifactLocation{URI: filepath.ToSlash(rel), URIBaseID: sarifSrcRootID}
}

// baseURIs returns the originalUriBaseIds map declaring SRCROOT as an
// absolute file:// URI (with the trailing slash SARIF §3.14.14 requires),
// or nil when no root was supplied.
func (r rootRelativizer) baseURIs() map[string]sarifArtifactLocation {
	if r.absRoot == "" {
		return nil
	}
	u := filepath.ToSlash(r.absRoot)
	if !strings.HasPrefix(u, "/") {
		u = "/" + u // Windows drive paths: C:/x → /C:/x per RFC 8089
	}
	return map[string]sarifArtifactLocation{
		sarifSrcRootID: {URI: "file://" + u + "/"},
	}
}

// fingerprintBase computes the stable, content-based identity hash for a
// finding. It hashes the rule ID, the (root-relative) artifact URI, and the
// normalized matched snippet — deliberately NOT line/column numbers, so the
// fingerprint survives edits elsewhere in the file that shift the finding.
// When the finding has no matched snippet, the sink-step taint snippet/label
// and finally the title anchor identity instead. Source/sink categories are
// mixed in so two different flows hitting the same line stay distinct.
func fingerprintBase(f rules.Finding, uri string) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0}) // field separator so "ab"+"c" != "a"+"bc"
	}
	write(f.RuleID)
	write(uri)
	snippet := normalizeSnippet(f.MatchedText)
	if snippet == "" && len(f.TaintPath) > 0 {
		sink := f.TaintPath[len(f.TaintPath)-1]
		snippet = normalizeSnippet(sink.Snippet)
		if snippet == "" {
			snippet = normalizeSnippet(sink.Label)
		}
	}
	if snippet == "" {
		snippet = normalizeSnippet(f.Title)
	}
	write(snippet)
	write(f.SourceCategory)
	write(f.SinkCategory)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// reLineDecoration matches the "(line N)" markers Batou's own taint engines
// embed in MatchedText / taint-step labels (taint.TaintFlow builds
// "src (line 4) → var → sink (line 6)"; the cross-file walkers use
// "caller() -> var -> sink (line N)"). These are presentation decorations,
// not code content — they must not leak line numbers into the fingerprint.
var reLineDecoration = regexp.MustCompile(`\(line \d+\)`)

// normalizeSnippet strips Batou's own "(line N)" decorations (replacing them
// with a line-free token so structure is preserved) and collapses all
// whitespace runs to a single space, so neither line shifts nor
// reindentation / line-wrapping of the same code churn the fingerprint.
func normalizeSnippet(s string) string {
	s = reLineDecoration.ReplaceAllString(s, "(line)")
	return strings.Join(strings.Fields(s), " ")
}

// assignFingerprints stamps partialFingerprints on every result. Results
// sharing the same base hash (identical rule + snippet in the same file) get
// stable ordinal suffixes in slice order — input order is deterministic
// (dirscan aggregates per-file findings in sorted file order), so the Nth
// identical occurrence keeps the Nth fingerprint even when every occurrence
// shifts lines.
func assignFingerprints(results []sarifResult, bases []string) {
	counts := make(map[string]int, len(bases))
	for i := range results {
		base := bases[i]
		ord := counts[base]
		counts[base]++
		results[i].PartialFingerprints = map[string]string{
			sarifFingerprintKey: fmt.Sprintf("%s:%d", base, ord),
		}
	}
}

// ToSARIF converts a ScanResult into a SARIF v2.1.0 log. Findings AND suppressed
// findings are emitted; suppressed ones carry a SARIF `suppressions` entry with
// the batou:ignore justification (suppression provenance). Artifact URIs are emitted as-is (no scan root known) — prefer
// ToSARIFWithRoot when the scan root is available. EXPERIMENTAL.
func ToSARIF(result *ScanResult) sarifLog {
	return ToSARIFWithRoot(result, "")
}

// ToSARIFWithRoot is ToSARIF with a known scan root: artifact URIs (primary
// locations AND taint-path codeFlow steps) under root are emitted
// root-relative against a SRCROOT uriBaseId declared in originalUriBaseIds,
// so GitHub code scanning can map them onto the repository. Paths outside
// the root fall back to pass-through URIs without a uriBaseId.
func ToSARIFWithRoot(result *ScanResult, root string) sarifLog {
	rel := newRootRelativizer(root)
	results := make([]sarifResult, 0, len(result.Findings)+len(result.SuppressedFindings))
	fingerprintBases := make([]string, 0, len(result.Findings)+len(result.SuppressedFindings))
	ruleSet := map[string]sarifReportDesc{}

	add := func(f rules.Finding, suppressed bool) {
		tier := TierForFinding(f)
		primary := primaryLocation(f, rel)
		res := sarifResult{
			RuleID:    f.RuleID,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: f.Title},
			Locations: []sarifLocation{primary},
			Properties: map[string]interface{}{
				"confidenceScore": f.ConfidenceScore,
				"riskScore":       f.RiskScore,
				"confidence":      f.Confidence,
				"analysisTier":    string(tier),
				"shouldBlock":     f.ShouldBlock(),
			},
		}
		if f.CWEID != "" {
			res.Properties["cwe"] = f.CWEID
		}
		if f.OWASPCategory != "" {
			res.Properties["owasp"] = f.OWASPCategory
		}
		if f.SourceCategory != "" {
			res.Properties["sourceCategory"] = f.SourceCategory
		}
		if f.SinkCategory != "" {
			res.Properties["sinkCategory"] = f.SinkCategory
		}
		// Cross-file taint path → SARIF codeFlow.
		if cf, ok := codeFlowFor(f, rel); ok {
			res.CodeFlows = []sarifCodeFlow{cf}
		}
		if suppressed {
			res.Suppressions = []sarifSuppression{{
				Kind:          "inSource",
				Justification: f.Suggestion, // suppression reason is captured upstream; best-effort
			}}
		}
		results = append(results, res)
		fingerprintBases = append(fingerprintBases, fingerprintBase(f, primary.PhysicalLocation.ArtifactLocation.URI))

		if _, seen := ruleSet[f.RuleID]; !seen && f.RuleID != "" {
			desc := sarifReportDesc{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: &sarifMessage{Text: f.Title},
				Properties:       map[string]interface{}{},
			}
			if f.CWEID != "" {
				desc.Properties["cwe"] = f.CWEID
			}
			ruleSet[f.RuleID] = desc
		}
	}

	for _, f := range result.Findings {
		add(f, false)
	}
	for _, f := range result.SuppressedFindings {
		add(f, true)
	}

	assignFingerprints(results, fingerprintBases)

	driverRules := make([]sarifReportDesc, 0, len(ruleSet))
	for _, d := range ruleSet {
		driverRules = append(driverRules, d)
	}

	return sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Batou",
				InformationURI: sarifToolURI,
				Rules:          driverRules,
			}},
			OriginalURIBaseIDs: rel.baseURIs(),
			Results:            results,
		}},
	}
}

// ToSARIFJSON renders a ScanResult as indented SARIF JSON bytes. EXPERIMENTAL.
func ToSARIFJSON(result *ScanResult) ([]byte, error) {
	return json.MarshalIndent(ToSARIF(result), "", "  ")
}

// ToSARIFJSONWithRoot renders a ScanResult as indented SARIF JSON bytes with
// artifact URIs relativized against the given scan root (see ToSARIFWithRoot).
func ToSARIFJSONWithRoot(result *ScanResult, root string) ([]byte, error) {
	return json.MarshalIndent(ToSARIFWithRoot(result, root), "", "  ")
}

// primaryLocation builds the SARIF location for the finding's primary site
// (the sink, for taint findings).
func primaryLocation(f rules.Finding, rel rootRelativizer) sarifLocation {
	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: rel.artifact(f.FilePath),
		},
	}
	if f.LineNumber > 0 || f.Column > 0 {
		region := &sarifRegion{StartLine: f.LineNumber, StartColumn: f.Column}
		if f.MatchedText != "" {
			region.Snippet = &sarifMessage{Text: f.MatchedText}
		}
		loc.PhysicalLocation.Region = region
	}
	return loc
}

// codeFlowFor converts a finding's structured TaintPath into a SARIF codeFlow.
// Returns ok=false when there is no path. This is the differentiating artifact:
// the full source→propagation→sink chain, with per-step file (so interprocedural
// cross-file flows render correctly).
func codeFlowFor(f rules.Finding, rel rootRelativizer) (sarifCodeFlow, bool) {
	if len(f.TaintPath) == 0 {
		return sarifCodeFlow{}, false
	}
	tfLocs := make([]sarifThreadFlowLocation, 0, len(f.TaintPath))
	for _, step := range f.TaintPath {
		region := &sarifRegion{StartLine: step.Line, StartColumn: step.Column}
		if step.Snippet != "" {
			region.Snippet = &sarifMessage{Text: step.Snippet}
		}
		tfLocs = append(tfLocs, sarifThreadFlowLocation{
			Location: sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: rel.artifact(step.File),
					Region:           region,
				},
			},
		})
	}
	return sarifCodeFlow{ThreadFlows: []sarifThreadFlow{{Locations: tfLocs}}}, true
}
