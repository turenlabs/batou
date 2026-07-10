package tsflow

// Tests for PHP regex DoS (CWE-1333) sink coverage added to round out the
// preg_* PCRE family (preg_split / preg_grep) and to cover the entirely
// uncovered mbstring/Oniguruma family (mb_ereg*). All of these take the regex
// PATTERN as their first argument, so a user-controlled pattern is the same
// catastrophic-backtracking hazard already modeled for preg_match /
// preg_replace. mb_ereg* is backed by Oniguruma, which (unlike PCRE) has no
// pcre.backtrack_limit safety net, making it an even stronger ReDoS vector.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// TestPHP_RegexDoS_Vulnerable covers each newly added pattern-taking function:
// a $_GET-derived pattern flowing into the function's first argument must fire
// a SnkRegexDoS flow.
func TestPHP_RegexDoS_Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"preg_split", `preg_split($p, $subject)`},
		{"preg_grep", `preg_grep($p, $items)`},
		{"mb_ereg", `mb_ereg($p, $subject)`},
		{"mb_eregi", `mb_eregi($p, $subject)`},
		{"mb_ereg_match", `mb_ereg_match($p, $subject)`},
		{"mb_ereg_replace", `mb_ereg_replace($p, "x", $subject)`},
		{"mb_eregi_replace", `mb_eregi_replace($p, "x", $subject)`},
		{"mb_ereg_replace_callback", `mb_ereg_replace_callback($p, function ($m) { return $m[0]; }, $subject)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `<?php
function handler($subject, $items) {
    $p = $_GET["p"];
    return ` + tc.call + `;
}
?>`
			flows := Analyze(code, "/app/handler.php", rules.LangPHP)
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("expected SnkRegexDoS flow for tainted pattern -> %s; got %d flows", tc.call, len(flows))
			}
		})
	}
}

// TestPHP_RegexDoS_StaticPattern_Silent is the negative control: a fixed
// literal pattern is the safe, overwhelmingly common form and must NOT fire.
func TestPHP_RegexDoS_StaticPattern_Silent(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"preg_split", `preg_split('/,/', $subject)`},
		{"preg_grep", `preg_grep('/^a/', $items)`},
		{"mb_ereg", `mb_ereg('[a-z]+', $subject)`},
		{"mb_ereg_replace", `mb_ereg_replace('[a-z]+', "x", $subject)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `<?php
function handler($subject, $items) {
    $unused = $_GET["p"];
    return ` + tc.call + `;
}
?>`
			flows := Analyze(code, "/app/handler.php", rules.LangPHP)
			if hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("static literal pattern must NOT fire SnkRegexDoS for %s", tc.call)
			}
		})
	}
}

// TestPHP_RegexDoS_PregQuote_Sanitized verifies preg_quote() neutralizes the
// ReDoS taint for the PCRE family (preg_quote escapes regex metacharacters).
func TestPHP_RegexDoS_PregQuote_Sanitized(t *testing.T) {
	code := `<?php
function handler($subject) {
    $p = preg_quote($_GET["p"]);
    return preg_split($p, $subject);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("preg_quote() must neutralize SnkRegexDoS for preg_split()")
	}
}
