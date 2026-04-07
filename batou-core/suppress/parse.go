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
)

// directiveRe matches batou:ignore directives inside any comment style.
// Groups: 1=start/end (optional), 2=rest of directive (targets + optional reason).
// Uses \s* so that `batou:ignore-end` matches without trailing content.
var directiveRe = regexp.MustCompile(`(?i)batou:ignore(?:-(start|end))?\s*([^\n]*)`)

// Directive represents a parsed suppression directive.
type Directive struct {
	Line    int      // 1-indexed line where the directive appears
	Targets []string // rule IDs, categories, or "all"
	Reason  string   // optional reason after "--"
	IsStart bool     // true for batou:ignore-start
	IsEnd   bool     // true for batou:ignore-end
}

// blockRange tracks a start/end suppression block.
type blockRange struct {
	startLine int
	endLine   int
	targets   []string
}

// Suppressions holds all parsed directives and computed suppression state.
type Suppressions struct {
	Directives []Directive
	// lineTargets maps line number → targets that suppress it.
	// Covers both single-line directives and block ranges.
	lineTargets map[int][]string
}

// Parse scans content for batou:ignore directives and returns the
// computed suppressions. This is a single-pass line scan with no AST
// dependency.
func Parse(content string) *Suppressions {
	s := &Suppressions{
		lineTargets: make(map[int][]string),
	}

	lines := strings.Split(content, "\n")

	var openBlocks []Directive // stack of open block-start directives

	for i, line := range lines {
		lineNum := i + 1

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
			// Single-line directive: suppress this line and the next
			// non-blank/non-comment line.
			s.lineTargets[lineNum] = mergeTargets(s.lineTargets[lineNum], targets)
			if nextLine := nextCodeLine(lines, i); nextLine > 0 {
				s.lineTargets[nextLine] = mergeTargets(s.lineTargets[nextLine], targets)
			}
		}
	}

	// Unclosed blocks: suppress from start to end of file.
	for _, opener := range openBlocks {
		for ln := opener.Line; ln <= len(lines); ln++ {
			s.lineTargets[ln] = mergeTargets(s.lineTargets[ln], opener.Targets)
		}
	}

	return s
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
