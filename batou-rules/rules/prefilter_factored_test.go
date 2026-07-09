package rules_test

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// handWrittenAlternationPatterns are (?i) alternation-heavy regexes drawn from
// the hand-written rule files. Go's regexp/syntax prefix/suffix-factors large
// alternations (e.g. security|ssl -> Concat[S, Alt[ECURITY, SL]]), which used to
// silently disable the gate for these patterns: the factored branches yielded
// only sub-3-char fragments, so the whole alternation became "always run". The
// fold-aware prefilter now distributes the shared literal run back into the
// nested alternation (recovering {security, ssl}), so these gate again. This
// test pins the soundness of that distribution: the gate must never skip a line
// the regex actually matches, for every one of these patterns.
var handWrittenAlternationPatterns = []string{
	// generic_ext.go BATOU-GEN-019 — the dominant C/C++ regex cost on real repos.
	`(?i)(?:csrf|xss|cors|auth|security|ssl|tls|https|hsts|csp|frame|clickjack|sanitiz|escap|encrypt|verify|validat|protect|secure|defense|guard|shield|firewall|waf|rate.?limit)\w*\s*[:=]\s*(?:false|0|['"]false['"]|['"]off['"]|['"]disabled?['"]|nil|null|None)`,
	// generic_ext.go BATOU-GEN-019 skip-verify variant.
	`(?i)(?:InsecureSkipVerify|skip_?ssl|ssl_?verify|verify_?ssl|verify_?peer|check_?hostname|CURLOPT_SSL_VERIFYPEER|verify_?certs?)\s*[:=]\s*(?:true|false|0|False)`,
	// Synthetic shapes that exercise the prefix/suffix factoring distribution
	// directly (Go simplifies each of these into Concat[run, Alt[...]] forms).
	`(?i)(?:security|ssl|server)`,
	`(?i)(?:https|hsts|http2)`,
	`(?i)(?:escape|encrypt|encode)`,
	`(?i)(?:validate|validation|verify)`,
	`(?i)(?:connect|connection|context)`,
	`(?i)(?:password|passcode|passphrase)`,
	// suffix factoring (shared tail): Go factors the common suffix.
	`(?i)(?:getRequest|postRequest|putRequest)`,
	`(?i)(?:onClickHandler|onHoverHandler|onFocusHandler)`,
}

// TestPrefilterSoundness_HandWrittenAlternations fuzzes each hand-written
// alternation pattern: for thousands of generated matching strings, the
// prefilter must classify every one as a candidate (MightMatch == true). A
// single skip of a real match is a dropped finding — the absolute correctness
// failure this whole mechanism must never commit.
func TestPrefilterSoundness_HandWrittenAlternations(t *testing.T) {
	rng := rand.New(rand.NewSource(0xFAB1E5))
	totalChecked := 0
	for _, p := range handWrittenAlternationPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("pattern failed to compile: %q: %v", p, err)
		}
		parsed, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("pattern failed to parse: %q: %v", p, err)
		}
		parsed = parsed.Simplify()
		pf := rules.CompilePrefilter(p)
		for i := 0; i < 4000; i++ {
			s := genMatchCorpus(parsed, rng, 0)
			if s == "" || !re.MatchString(s) {
				continue
			}
			totalChecked++
			if !pf.MightMatch(strings.ToLower(s)) {
				t.Fatalf("GATE UNSOUND: pattern %q matched %q but prefilter skipped it\n  groups=%v",
					p, s, pf.Groups)
			}
		}
	}
	t.Logf("fuzzed %d hand-written alternation patterns, %d verified matching strings",
		len(handWrittenAlternationPatterns), totalChecked)
}

// TestPrefilter_FactoredAlternationsGate confirms the two dominant hand-written
// rules actually gate now (regression guard against the alternation factoring
// silently disabling them again). Both must derive a non-empty required-literal
// group; otherwise the gate is a no-op and the (?i) backtracking runs on every
// line.
func TestPrefilter_FactoredAlternationsGate(t *testing.T) {
	for _, p := range handWrittenAlternationPatterns {
		pf := rules.CompilePrefilter(p)
		if len(pf.Groups) == 0 {
			t.Errorf("pattern does not gate (always-run), expected a required-literal group: %q", p)
		}
	}
}
