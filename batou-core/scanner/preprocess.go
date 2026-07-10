package scanner

import (
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// JoinContinuationLines joins lines that are split across multiple lines
// using language-specific continuation patterns. This allows regex rules
// to match patterns that span multiple lines.
//
// Supported continuations:
//   - Backslash continuation (Python, Shell, C, C++, Makefile): line ending with \
//   - Implicit continuation (Python): unclosed (), [], {} across lines
//
// The returned string has continuations joined with spaces. Callers should
// keep the original content for AST parsing and line-number reporting.
func JoinContinuationLines(content string, lang rules.Language) string {
	joined, _ := JoinContinuationLinesWithMap(content, lang)
	return joined
}

// JoinContinuationLinesWithMap joins continuation lines like JoinContinuationLines
// and additionally returns a slice mapping each preprocessed line (0-indexed) to
// the 1-indexed original line where that group started. For content that isn't
// preprocessed (Go, JS, etc.) the returned slice is nil and callers should treat
// preprocessed lines as identical to original lines.
//
// Example — Python code where original lines 2–4 are joined into one preprocessed
// line:
//
//	orig 1: x = 1          preToOrig[0] = 1   (pre line 1)
//	orig 2: y = (          preToOrig[1] = 2   (pre line 2 = joined orig 2+3+4)
//	orig 3:     a,
//	orig 4: )
//	orig 5: z = 2          preToOrig[2] = 5   (pre line 3)
func JoinContinuationLinesWithMap(content string, lang rules.Language) (string, []int) {
	switch lang {
	case rules.LangPython:
		return joinPythonContinuations(content)
	case rules.LangShell:
		return joinBackslashContinuations(content)
	case rules.LangC, rules.LangCPP:
		return joinBackslashContinuations(content)
	default:
		return content, nil
	}
}

// joinBackslashContinuations joins lines ending with a backslash (\) to the
// next line. The backslash and newline are replaced with a single space.
// Returns the joined content and a preprocessed→original line map.
func joinBackslashContinuations(content string) (string, []int) {
	lines := strings.Split(content, "\n")
	var result []string
	var preToOrig []int
	var pending string
	groupStart := 1

	for i, line := range lines {
		origLine := i + 1

		// Start of a fresh group: record where it began.
		if pending == "" {
			groupStart = origLine
		}

		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			// Remove trailing backslash and accumulate.
			pending += trimmed[:len(trimmed)-1]
		} else {
			if pending != "" {
				result = append(result, pending+line)
				preToOrig = append(preToOrig, groupStart)
				pending = ""
			} else {
				result = append(result, line)
				preToOrig = append(preToOrig, groupStart)
			}
		}
	}
	// Flush any remaining pending content.
	if pending != "" {
		result = append(result, pending)
		preToOrig = append(preToOrig, groupStart)
	}

	return strings.Join(result, "\n"), preToOrig
}

// joinPythonContinuations handles both backslash continuations and
// implicit continuations from unclosed parentheses/brackets/braces.
// Tracks multi-line triple-quoted strings so that brackets inside a
// docstring are not counted against nesting depth.
// Returns the joined content and a preprocessed→original line map.
func joinPythonContinuations(content string) (string, []int) {
	lines := strings.Split(content, "\n")
	var result []string
	var preToOrig []int
	var pending string
	groupStart := 1    // 1-indexed original line where the current group started
	depth := 0         // paren/bracket/brace nesting depth
	inTriple := false  // are we inside an unclosed triple-quoted string?
	tripleCh := byte(0) // which quote character opened the triple (' or ")

	for i, line := range lines {
		origLine := i + 1

		// Start of a fresh group: record where it began. A line that
		// continues an open triple-quote is part of the previous group.
		if pending == "" && depth == 0 && !inTriple {
			groupStart = origLine
		}

		trimmed := strings.TrimRight(line, " \t")

		// Backslash continuation only applies outside brackets AND outside
		// multi-line strings — a trailing `\` inside a docstring is just
		// text, not a line continuation.
		if strings.HasSuffix(trimmed, "\\") && depth == 0 && !inTriple {
			pending += trimmed[:len(trimmed)-1]
			continue
		}

		if pending != "" && depth == 0 && !inTriple {
			line = pending + line
			pending = ""
		}

		if depth > 0 || inTriple {
			// Inside a bracket group or multi-line string — join to pending.
			pending += " " + strings.TrimSpace(line)
		} else {
			pending = line
		}

		// Count brackets on the current line, threading triple-quote state
		// so brackets inside a docstring are ignored.
		var delta int
		delta, inTriple, tripleCh = countBracketDeltaStateful(line, inTriple, tripleCh)
		depth += delta

		if depth <= 0 && !inTriple {
			depth = 0
			result = append(result, pending)
			preToOrig = append(preToOrig, groupStart)
			pending = ""
		}
	}

	if pending != "" {
		result = append(result, pending)
		preToOrig = append(preToOrig, groupStart)
	}

	return strings.Join(result, "\n"), preToOrig
}

// countBracketDelta returns the net open bracket count (opens minus closes)
// for a single line, assuming it is NOT inside a multi-line triple-quoted
// string. Use countBracketDeltaStateful when tracking state across lines.
func countBracketDelta(line string) int {
	delta, _, _ := countBracketDeltaStateful(line, false, 0)
	return delta
}

// countBracketDeltaStateful is countBracketDelta with triple-quote state
// threaded across lines.
//
// When inTripleBefore is true, scanning starts by searching for the matching
// closing `"""` (or `'''`) — everything before the closer is string content
// and does not count. After the closer, bracket counting resumes normally.
// If no closer is found, returns (0, true, openerCh) so the caller can carry
// the state to the next line.
//
// Returns (delta, inTripleAfter, openerChar).
func countBracketDeltaStateful(line string, inTripleBefore bool, tripleChBefore byte) (int, bool, byte) {
	delta := 0
	i := 0

	// If we entered this line already inside a triple-quoted string, skip
	// ahead to the closing triple before counting anything.
	if inTripleBefore {
		closer := string([]byte{tripleChBefore, tripleChBefore, tripleChBefore})
		end := strings.Index(line, closer)
		if end < 0 {
			// Still inside the string — no bracket counting this line.
			return 0, true, tripleChBefore
		}
		i = end + 3
	}

	inString := false
	stringChar := byte(0)

	for ; i < len(line); i++ {
		ch := line[i]

		if inString {
			if ch == '\\' && i+1 < len(line) {
				i++ // skip escaped char
				continue
			}
			if ch == stringChar {
				inString = false
			}
			continue
		}

		switch ch {
		case '"', '\'':
			// Check for triple quotes.
			if i+2 < len(line) && line[i+1] == ch && line[i+2] == ch {
				// Find the closing triple on the SAME line.
				closer := string([]byte{ch, ch, ch})
				end := strings.Index(line[i+3:], closer)
				if end >= 0 {
					i = i + 3 + end + 2
				} else {
					// Unclosed triple — carry state to next line.
					return delta, true, ch
				}
				continue
			}
			inString = true
			stringChar = ch
		case '#':
			// Rest of line is a comment.
			return delta, false, 0
		case '(', '[', '{':
			delta++
		case ')', ']', '}':
			delta--
		}
	}
	return delta, false, 0
}
