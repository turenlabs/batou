package ast

import (
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// FilterFindings runs each finding through the AST to suppress false
// positives that originate from comments.  Findings whose matched text
// falls inside a comment node in the AST are removed.
//
// Note: string literals are NOT filtered because many security findings
// (SQL injection, XSS, etc.) legitimately match patterns inside string
// literals used as queries/templates.
//
// If tree is nil (parsing failed or unsupported language) the original
// findings are returned unchanged.
func FilterFindings(tree *Tree, findings []rules.Finding) []rules.Finding {
	if tree == nil || len(findings) == 0 {
		return findings
	}

	content := tree.Content()
	if len(content) == 0 {
		return findings
	}

	// Pre-build a line-start offset table for translating line numbers
	// to byte offsets.
	lineOffsets := buildLineOffsets(content)

	out := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if shouldSuppressFinding(tree, f, lineOffsets, content) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// shouldSuppressFinding returns true if the finding should be suppressed
// because it falls entirely within a comment.
func shouldSuppressFinding(tree *Tree, f rules.Finding, lineOffsets []int, content []byte) bool {
	offset, ok := findingOffset(f, lineOffsets, content)
	if !ok {
		return false // can't determine offset, keep the finding
	}

	return IsInComment(tree, offset)
}

// findingOffset converts a finding's line number (and optional matched text)
// into a byte offset in the source content.  Returns (offset, true) on
// success or (0, false) if the position cannot be determined.
func findingOffset(f rules.Finding, lineOffsets []int, content []byte) (uint32, bool) {
	// LineNumber is 1-based in rules.Finding.
	if f.LineNumber <= 0 || f.LineNumber > len(lineOffsets) {
		return 0, false
	}

	lineStart := lineOffsets[f.LineNumber-1]

	// If we have matched text, find its position within the line for a
	// more precise offset.
	if f.MatchedText != "" {
		// Search from line start for the matched text.
		remaining := string(content[lineStart:])
		idx := strings.Index(remaining, f.MatchedText)
		if idx >= 0 {
			return uint32(lineStart + idx), true
		}
	}

	// If we have a column, use it (1-based).
	if f.Column > 0 {
		return uint32(lineStart + f.Column - 1), true
	}

	// Fall back to the start of the line.
	return uint32(lineStart), true
}

// buildLineOffsets returns a slice where lineOffsets[i] is the byte offset
// of the start of the (i+1)-th line (0-indexed internally).
func buildLineOffsets(content []byte) []int {
	offsets := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}
