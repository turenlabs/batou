package rules_test

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"

	// Register every rule category so rules.All() exposes the full RegexRule
	// pattern corpus to the gate-soundness fuzz below. Mirrors the blank-import
	// block in batou-core/cmd/batou/main.go.
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/container"
	_ "github.com/turenlabs/batou-rules/rules/cors"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/csharp"
	_ "github.com/turenlabs/batou-rules/rules/deser"
	_ "github.com/turenlabs/batou-rules/rules/encoding"
	_ "github.com/turenlabs/batou-rules/rules/framework"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/golang"
	_ "github.com/turenlabs/batou-rules/rules/graphql"
	_ "github.com/turenlabs/batou-rules/rules/groovy"
	_ "github.com/turenlabs/batou-rules/rules/header"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/java"
	_ "github.com/turenlabs/batou-rules/rules/jsts"
	_ "github.com/turenlabs/batou-rules/rules/jwt"
	_ "github.com/turenlabs/batou-rules/rules/kotlin"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/lua"
	_ "github.com/turenlabs/batou-rules/rules/massassign"
	_ "github.com/turenlabs/batou-rules/rules/memory"
	_ "github.com/turenlabs/batou-rules/rules/misconfig"
	_ "github.com/turenlabs/batou-rules/rules/nosql"
	_ "github.com/turenlabs/batou-rules/rules/oauth"
	_ "github.com/turenlabs/batou-rules/rules/perl"
	_ "github.com/turenlabs/batou-rules/rules/php"
	_ "github.com/turenlabs/batou-rules/rules/prototype"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/race"
	_ "github.com/turenlabs/batou-rules/rules/redirect"
	_ "github.com/turenlabs/batou-rules/rules/ruby"
	_ "github.com/turenlabs/batou-rules/rules/rust"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/session"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/ssti"
	_ "github.com/turenlabs/batou-rules/rules/swift"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/upload"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/websocket"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/xxe"
	_ "github.com/turenlabs/batou-rules/rules/zig"
)

// genMatch (corpus copy) walks a Perl-flag regexp syntax tree and produces one
// random string the simplified regexp matches. Kept independent of the package
// internals so it can live in the external _test package alongside the full
// rule registry. The caller re-verifies with the real compiled regexp.
func genMatchCorpus(r *syntax.Regexp, rng *rand.Rand, depth int) string {
	if depth > 60 {
		return ""
	}
	switch r.Op {
	case syntax.OpLiteral:
		var b strings.Builder
		for _, ru := range r.Rune {
			switch {
			case r.Flags&syntax.FoldCase != 0 && rng.Intn(2) == 0:
				b.WriteString(strings.ToUpper(string(ru)))
			case r.Flags&syntax.FoldCase != 0:
				b.WriteString(strings.ToLower(string(ru)))
			default:
				b.WriteRune(ru)
			}
		}
		return b.String()
	case syntax.OpCharClass:
		if len(r.Rune) >= 2 {
			for try := 0; try < 8; try++ {
				p := (rng.Intn(len(r.Rune) / 2)) * 2
				lo, hi := r.Rune[p], r.Rune[p+1]
				if hi < lo {
					continue
				}
				c := lo + rune(rng.Intn(int(hi-lo)+1))
				if c == '\n' || c == 0 {
					continue
				}
				return string(c)
			}
		}
		return "a"
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return string(rune('a' + rng.Intn(26)))
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range r.Sub {
			b.WriteString(genMatchCorpus(sub, rng, depth+1))
		}
		return b.String()
	case syntax.OpAlternate:
		return genMatchCorpus(r.Sub[rng.Intn(len(r.Sub))], rng, depth+1)
	case syntax.OpStar:
		var b strings.Builder
		for i := 0; i < rng.Intn(3); i++ {
			b.WriteString(genMatchCorpus(r.Sub[0], rng, depth+1))
		}
		return b.String()
	case syntax.OpPlus:
		var b strings.Builder
		b.WriteString(genMatchCorpus(r.Sub[0], rng, depth+1))
		for i := 0; i < rng.Intn(2); i++ {
			b.WriteString(genMatchCorpus(r.Sub[0], rng, depth+1))
		}
		return b.String()
	case syntax.OpQuest:
		if rng.Intn(2) == 0 {
			return genMatchCorpus(r.Sub[0], rng, depth+1)
		}
		return ""
	case syntax.OpRepeat:
		var b strings.Builder
		n := r.Min
		if r.Max > r.Min {
			n += rng.Intn(r.Max - r.Min + 1)
		} else if r.Max < 0 {
			n += rng.Intn(2)
		}
		for i := 0; i < n; i++ {
			b.WriteString(genMatchCorpus(r.Sub[0], rng, depth+1))
		}
		return b.String()
	case syntax.OpCapture:
		return genMatchCorpus(r.Sub[0], rng, depth+1)
	}
	return ""
}

// TestPrefilterSoundness_FullCorpus is the broad correctness net: for every
// registered RegexRule pattern, generate many matching strings and assert the
// fold-aware gate never skips a real match. This is what proves the per-line
// upgrade to RegexRule.Scan is finding-preserving across the whole rule corpus.
func TestPrefilterSoundness_FullCorpus(t *testing.T) {
	var patterns []string
	for _, r := range rules.All() {
		rr, ok := r.(*rules.RegexRule)
		if !ok {
			continue
		}
		for _, re := range rr.Patterns {
			patterns = append(patterns, re.String())
		}
	}
	if len(patterns) == 0 {
		t.Fatal("expected RegexRule patterns to be registered; got none")
	}

	rng := rand.New(rand.NewSource(0xC0FFEE))
	totalChecked := 0
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		parsed, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			continue
		}
		parsed = parsed.Simplify()
		pf := rules.CompilePrefilter(p)
		for i := 0; i < 800; i++ {
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
	t.Logf("fuzzed %d RegexRule patterns, %d verified matching strings", len(patterns), totalChecked)
}
