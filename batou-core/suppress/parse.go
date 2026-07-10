// Package suppress implements inline false-positive suppression for Batou.
//
// Developers and Claude can add `batou:ignore` directives in code comments
// to suppress specific findings. The directive syntax is:
//
//	batou:ignore <target> [-- reason]
//
// Where <target> is a rule ID (BATOU-INJ-001), category (injection), or "all".
//
// Block suppression uses start/end markers:
//
//	batou:ignore-start <target>
//	... suppressed code ...
//	batou:ignore-end
//
// Parsing is regex-based (no AST dependency) so it works across all 17 languages.
package suppress

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// directiveRe matches batou:ignore directives inside any comment style.
// Groups: 1=start/end (optional), 2=rest of directive (targets + optional reason).
// Uses \s* so that `batou:ignore-end` matches without trailing content.
var directiveRe = regexp.MustCompile(`(?i)batou:ignore(?:-(start|end))?\s*([^\n]*)`)

// gosecAnnotationRe matches the standard Go gosec / golangci-lint security
// suppression conventions that developers use to mark an audited exception:
//
//	x := os.ReadFile(p) // #nosec G304 -- path is operator config
//	// nolint:gosec
//	yamlFile, _ := os.ReadFile(filename)
//
// These are the gosec equivalent of Batou's own `batou:ignore` directive: a
// reviewer has examined the flagged line and signed off on it. We honor them by
// suppressing security findings on the annotated line (and, for a pure-comment
// annotation, the next code line — mirroring batou:ignore's single-line scope).
//
// Only gosec-scoped annotations are honored:
//   - `#nosec` is gosec's native directive and is always security-scoped.
//   - `nolint:gosec` (optionally with other linters in the comma list, e.g.
//     `nolint:gosec,govet`) explicitly names gosec.
//
// A bare `//nolint` (no linter list) disables every golangci-lint linter,
// including style/quality ones, and is intentionally NOT treated as a security
// suppression — it is too broad to infer a security sign-off from.
var gosecAnnotationRe = regexp.MustCompile(`(?i)#nosec\b|nolint:[a-z0-9,_-]*gosec`)

// gosecRuleTailRe matches a gosec rule code (G followed by digits) so the text
// after it can be recovered as the suppression rationale.
var gosecRuleTailRe = regexp.MustCompile(`(?i)G\d{3,}`)

// reasonFromGosecAnnotation extracts a human-readable reason from a gosec/nolint
// annotation line so the suppressed finding's audit trail records the
// developer's stated justification, e.g. `#nosec G304 -- trusted config path`
// or `#nosec G304 path is trusted`. Returns "" when the annotation carries no
// trailing explanation.
func reasonFromGosecAnnotation(line string) string {
	if idx := strings.Index(line, "--"); idx >= 0 {
		if r := strings.TrimSpace(line[idx+2:]); r != "" {
			return r
		}
	}
	// gosec convention: text after the rule code is the rationale, e.g.
	// `#nosec G304 path is trusted`.
	if loc := gosecRuleTailRe.FindStringIndex(line); loc != nil {
		if r := strings.TrimSpace(line[loc[1]:]); r != "" {
			return r
		}
	}
	return ""
}

// Directive represents a parsed suppression directive.
type Directive struct {
	Line    int      // 1-indexed line where the directive appears
	Targets []string // rule IDs, categories, or "all"
	Reason  string   // optional reason after "--"
	IsStart bool     // true for batou:ignore-start
	IsEnd   bool     // true for batou:ignore-end
}

// Suppressions holds all parsed directives and computed suppression state.
type Suppressions struct {
	Directives []Directive
	// lineTargets maps line number → targets that suppress it.
	// Covers both single-line directives and block ranges.
	lineTargets map[int][]string
	// lineReasons maps line number → the reason-bearing directives that cover
	// it. Built alongside lineTargets so that reasonForFinding can recover the
	// rationale a directive stated for a suppressed finding on that line. A line
	// can be covered by several directives; each entry preserves its own
	// targets + reason so reasonForFinding can pick the one whose target
	// actually matched the finding's rule/category.
	lineReasons map[int][]lineReason
	// gosecLines records lines suppressed by a gosec/nolint annotation
	// (#nosec, nolint:gosec) rather than a batou:ignore directive. These are
	// the developer's audited gosec exceptions; their free-text rationale is an
	// out-of-band human judgment, not a claim about Batou's computed flow, so
	// Adjudicate must NOT machine-check it (mirrors classifyReason's
	// unverifiable escape hatches).
	gosecLines map[int]bool
}

// lineReason records one directive's targets and stated reason as it applies to
// a covered line. Reasonless directives are still recorded (with Reason == "")
// so reasonForFinding can distinguish "no covering directive" from "covered but
// no reason given".
type lineReason struct {
	targets []string
	reason  string
}

// Parse scans content for batou:ignore directives and returns the
// computed suppressions. This is a single-pass line scan with no AST
// dependency.
func Parse(content string) *Suppressions {
	return ParseWithLineMap(content, nil, 0)
}

// ParseWithLineMap parses directives against content that has been through
// JoinContinuationLines, mirroring each resulting lineTargets entry from the
// preprocessed line number back across the original line range it spans.
//
// preToOrig is the slice returned by JoinContinuationLinesWithMap: index i
// (0-indexed) holds the 1-indexed original line where preprocessed line i+1
// began. totalOrigLines is the line count of the original (pre-join) content;
// callers can use strings.Count(original, "\n") + 1. Pass nil / 0 to skip
// mirroring (identity mapping — preprocessed == original).
//
// This lets IsSuppressed resolve findings regardless of which coordinate
// system the caller used: regex rules emit preprocessed line numbers, while
// AST and taint analyses emit original line numbers.
func ParseWithLineMap(content string, preToOrig []int, totalOrigLines int) *Suppressions {
	s := &Suppressions{
		lineTargets: make(map[int][]string),
		lineReasons: make(map[int][]lineReason),
		gosecLines:  make(map[int]bool),
	}

	lines := strings.Split(content, "\n")

	var openBlocks []Directive // stack of open block-start directives

	for i, line := range lines {
		lineNum := i + 1

		// Honor gosec / golangci-lint security suppressions (#nosec,
		// nolint:gosec) as developer-audited exceptions, mirroring the
		// single-line batou:ignore scope. Independent of the batou:ignore
		// path below so a line can carry both. Suppresses security findings
		// (target "all") on the annotated line and — when the annotation is on
		// its own comment line — the next code line.
		if gosecAnnotationRe.MatchString(line) {
			reason := reasonFromGosecAnnotation(line)
			gosecTargets := []string{"all"}
			s.lineTargets[lineNum] = mergeTargets(s.lineTargets[lineNum], gosecTargets)
			s.addLineReason(lineNum, gosecTargets, reason)
			s.gosecLines[lineNum] = true
			if isCommentOnlyLine(line) {
				if nextLine := nextCodeLine(lines, i); nextLine > 0 {
					s.lineTargets[nextLine] = mergeTargets(s.lineTargets[nextLine], gosecTargets)
					s.addLineReason(nextLine, gosecTargets, reason)
					s.gosecLines[nextLine] = true
				}
			}
			// Fall through: a line could carry both a gosec annotation and a
			// batou:ignore directive, so continue to the batou:ignore parse.
		}

		match := directiveRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		startEnd := strings.ToLower(match[1]) // "", "start", or "end"
		rest := strings.TrimSpace(match[2])

		if startEnd == "end" {
			d := Directive{
				Line:  lineNum,
				IsEnd: true,
			}
			s.Directives = append(s.Directives, d)

			// Close the most recent open block.
			if len(openBlocks) > 0 {
				opener := openBlocks[len(openBlocks)-1]
				openBlocks = openBlocks[:len(openBlocks)-1]

				// Expand lines between start and end.
				for ln := opener.Line; ln <= lineNum; ln++ {
					s.lineTargets[ln] = mergeTargets(s.lineTargets[ln], opener.Targets)
					s.addLineReason(ln, opener.Targets, opener.Reason)
				}
			}
			continue
		}

		// Parse targets and reason from rest.
		targets, reason := parseTargetsAndReason(rest)
		if len(targets) == 0 {
			continue
		}

		d := Directive{
			Line:    lineNum,
			Targets: targets,
			Reason:  reason,
			IsStart: startEnd == "start",
		}
		s.Directives = append(s.Directives, d)

		if d.IsStart {
			openBlocks = append(openBlocks, d)
		} else {
			// Single-line directive. Always suppress the directive's own line.
			s.lineTargets[lineNum] = mergeTargets(s.lineTargets[lineNum], targets)
			s.addLineReason(lineNum, targets, reason)
			// Extend to the next code line ONLY for pure-comment directives.
			// Trailing inline forms (e.g. `foo() // batou:ignore injection`)
			// should apply to the current line only — otherwise an unrelated
			// statement on the next line would be silently suppressed.
			if isCommentOnlyLine(line) {
				if nextLine := nextCodeLine(lines, i); nextLine > 0 {
					s.lineTargets[nextLine] = mergeTargets(s.lineTargets[nextLine], targets)
					s.addLineReason(nextLine, targets, reason)
				}
			}
		}
	}

	// Unclosed blocks: suppress from start to end of file.
	for _, opener := range openBlocks {
		for ln := opener.Line; ln <= len(lines); ln++ {
			s.lineTargets[ln] = mergeTargets(s.lineTargets[ln], opener.Targets)
			s.addLineReason(ln, opener.Targets, opener.Reason)
		}
	}

	// Mirror entries from preprocessed line numbers back to every original line
	// in the group. After JoinContinuationLines collapses a multi-line statement,
	// suppress.Parse sees a single preprocessed line; AST/taint findings still
	// report original line numbers. Without this mirror, a directive above a
	// collapsed block wouldn't suppress findings on the inner original lines.
	if len(preToOrig) > 0 && totalOrigLines > 0 {
		mirrorOriginalLines(s.lineTargets, preToOrig, totalOrigLines)
		s.mirrorOriginalReasons(preToOrig, totalOrigLines)
	}

	return s
}

// addLineReason records a directive's targets+reason against a covered line.
// Reasonless directives (reason == "") are still recorded so reasonForFinding
// can tell "covered by a directive" apart from "not covered". Duplicate
// (targets, reason) entries on the same line are de-duplicated.
func (s *Suppressions) addLineReason(line int, targets []string, reason string) {
	if s.lineReasons == nil {
		s.lineReasons = make(map[int][]lineReason)
	}
	for _, lr := range s.lineReasons[line] {
		if lr.reason == reason && sameTargets(lr.targets, targets) {
			return
		}
	}
	cp := make([]string, len(targets))
	copy(cp, targets)
	s.lineReasons[line] = append(s.lineReasons[line], lineReason{targets: cp, reason: reason})
}

// mirrorOriginalReasons mirrors lineReasons from preprocessed line numbers back
// to every original line in the group, mirroring mirrorOriginalLines so that a
// reason stated above a collapsed multi-line statement still resolves against a
// taint finding reported on an inner original line.
func (s *Suppressions) mirrorOriginalReasons(preToOrig []int, totalOrigLines int) {
	snapshot := make(map[int][]lineReason, len(s.lineReasons))
	for line, reasons := range s.lineReasons {
		snapshot[line] = reasons
	}
	for preLine, reasons := range snapshot {
		idx := preLine - 1
		if idx < 0 || idx >= len(preToOrig) {
			continue
		}
		origStart := preToOrig[idx]
		var origEnd int
		if idx+1 < len(preToOrig) {
			origEnd = preToOrig[idx+1] - 1
		} else {
			origEnd = totalOrigLines
		}
		for ol := origStart; ol <= origEnd; ol++ {
			if ol == preLine {
				continue
			}
			for _, lr := range reasons {
				s.addLineReason(ol, lr.targets, lr.reason)
			}
		}
	}
}

// ReasonForFinding returns the stated `-- reason` of the suppression directive
// that covers f. It is the exported entry point the scanner uses to stamp
// suppressed findings with the developer's justification so the audit trail
// (findings store, ledger) preserves it. ok is false when no covering
// directive matches the finding; reason may be "" when the matching directive
// carried no `-- reason`.
func (s *Suppressions) ReasonForFinding(f rules.Finding) (reason string, ok bool) {
	return s.reasonForFinding(f)
}

// reasonForFinding returns the stated reason of the suppression directive that
// covers f, choosing the directive whose target actually matched f's rule or
// category. ok is false when no covering directive matches the finding; reason
// may be "" when the matching directive carried no `-- reason`.
func (s *Suppressions) reasonForFinding(f rules.Finding) (reason string, ok bool) {
	if s == nil || s.lineReasons == nil {
		return "", false
	}
	line := f.LineNumber
	if line == 0 {
		line = 1
	}
	reasons, found := s.lineReasons[line]
	if !found {
		return "", false
	}
	// Prefer the most specific matching directive: a reason-bearing directive
	// whose target matched takes precedence over a reasonless one. Among
	// reason-bearing matches, the first wins (deterministic by parse order).
	var fallbackOK bool
	for _, lr := range reasons {
		if !matchesTargets(f, lr.targets) {
			continue
		}
		if lr.reason != "" {
			return lr.reason, true
		}
		fallbackOK = true
	}
	if fallbackOK {
		return "", true
	}
	return "", false
}

// sameTargets reports whether two target slices contain the same elements in
// the same order (they are built deterministically, so order is stable).
func sameTargets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mirrorOriginalLines expands lineTargets so each preprocessed-line entry also
// covers every original line that was folded into that preprocessed line.
func mirrorOriginalLines(lineTargets map[int][]string, preToOrig []int, totalOrigLines int) {
	// Snapshot first so we only iterate the preprocessed entries, not the
	// original-line entries we're about to add.
	snapshot := make(map[int][]string, len(lineTargets))
	for line, targets := range lineTargets {
		snapshot[line] = targets
	}

	for preLine, targets := range snapshot {
		idx := preLine - 1
		if idx < 0 || idx >= len(preToOrig) {
			continue
		}
		origStart := preToOrig[idx]
		var origEnd int
		if idx+1 < len(preToOrig) {
			origEnd = preToOrig[idx+1] - 1
		} else {
			origEnd = totalOrigLines
		}
		for ol := origStart; ol <= origEnd; ol++ {
			if ol == preLine {
				continue
			}
			lineTargets[ol] = mergeTargets(lineTargets[ol], targets)
		}
	}
}

// parseTargetsAndReason splits "BATOU-INJ-001 injection -- reason here"
// into targets and optional reason.
func parseTargetsAndReason(s string) ([]string, string) {
	var reason string
	if idx := strings.Index(s, "--"); idx >= 0 {
		reason = strings.TrimSpace(s[idx+2:])
		s = strings.TrimSpace(s[:idx])
	}

	var targets []string
	for _, t := range strings.Fields(s) {
		t = strings.TrimSpace(t)
		if t != "" {
			targets = append(targets, strings.ToLower(t))
		}
	}
	return targets, reason
}

// isCommentOnlyLine reports whether the line (once indentation is stripped)
// starts with a recognized comment prefix — i.e. the directive is on its own
// line rather than trailing a statement.
func isCommentOnlyLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	// Keep this set in sync with nextCodeLine's comment-prefix list below.
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "--") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "<!--") ||
		strings.HasPrefix(trimmed, "rem ") ||
		strings.HasPrefix(trimmed, "REM ") ||
		strings.HasPrefix(trimmed, "'")
}

// nextCodeLine returns the 1-indexed line number of the next non-blank,
// non-comment line after index idx, or 0 if there is none.
func nextCodeLine(lines []string, idx int) int {
	for i := idx + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		// Skip common comment prefixes.
		if strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "--") ||
			strings.HasPrefix(trimmed, "/*") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "<!--") ||
			strings.HasPrefix(trimmed, "rem ") ||
			strings.HasPrefix(trimmed, "REM ") {
			continue
		}
		return i + 1 // 1-indexed
	}
	return 0
}

// mergeTargets appends unique targets from src into dst.
func mergeTargets(dst, src []string) []string {
	for _, t := range src {
		found := false
		for _, d := range dst {
			if d == t {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, t)
		}
	}
	return dst
}
