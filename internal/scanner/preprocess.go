package scanner

import (
	"strings"

	"github.com/turenio/gtss/internal/rules"
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
	switch lang {
	case rules.LangPython:
		return joinPythonContinuations(content)
	case rules.LangShell:
		return joinBackslashContinuations(content)
	case rules.LangC, rules.LangCPP:
		return joinBackslashContinuations(content)
	default:
		return content
	}
}

// joinBackslashContinuations joins lines ending with a backslash (\) to the
// next line. The backslash and newline are replaced with a single space.
func joinBackslashContinuations(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var pending string

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			// Remove trailing backslash and accumulate.
			pending += trimmed[:len(trimmed)-1]
		} else {
			if pending != "" {
				result = append(result, pending+line)
				pending = ""
			} else {
				result = append(result, line)
			}
		}
	}
	// Flush any remaining pending content.
	if pending != "" {
		result = append(result, pending)
	}

	return strings.Join(result, "\n")
}

// joinPythonContinuations handles both backslash continuations and
// implicit continuations from unclosed parentheses/brackets/braces.
func joinPythonContinuations(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var pending string
	depth := 0 // paren/bracket/brace nesting depth

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")

		// Handle explicit backslash continuation.
		if strings.HasSuffix(trimmed, "\\") && depth == 0 {
			pending += trimmed[:len(trimmed)-1]
			continue
		}

		if pending != "" && depth == 0 {
			line = pending + line
			pending = ""
		}

		if depth > 0 {
			// We're inside an unclosed group — join to the pending line.
			pending += " " + strings.TrimSpace(line)
		} else {
			pending = line
		}

		// Count brackets on the current line only (not accumulated pending).
		depth += countBracketDelta(line)

		if depth <= 0 {
			depth = 0
			result = append(result, pending)
			pending = ""
		}
	}

	if pending != "" {
		result = append(result, pending)
	}

	return strings.Join(result, "\n")
}

// countBracketDelta returns the net open bracket count (opens minus closes)
// for parentheses, square brackets, and curly braces, skipping characters
// inside string literals.
func countBracketDelta(line string) int {
	delta := 0
	inString := false
	stringChar := byte(0)

	for i := 0; i < len(line); i++ {
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
				// Skip triple-quoted strings — find the closing triple.
				closer := string([]byte{ch, ch, ch})
				end := strings.Index(line[i+3:], closer)
				if end >= 0 {
					i = i + 3 + end + 2
				} else {
					// Unclosed triple quote on this line; skip rest.
					return delta
				}
				continue
			}
			inString = true
			stringChar = ch
		case '#':
			// Rest of line is a comment.
			return delta
		case '(', '[', '{':
			delta++
		case ')', ']', '}':
			delta--
		}
	}
	return delta
}
