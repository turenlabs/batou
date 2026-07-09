package rules

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// The fundamental correctness invariant of the fold-aware OR-set pre-gate:
//
//	for every pattern P and every string s with P.MatchString(s) == true,
//	  CompilePrefilter(P).MightMatch(strings.ToLower(s)) MUST be true.
//
// If that ever fails, the gate would skip a line on which a rule actually
// matches — i.e. drop a finding. These tests hammer that invariant with both a
// curated table and a syntax-tree-driven random matching-string generator over
// every registered RegexRule pattern.

// genMatch walks a (Perl-flag) regexp syntax tree and produces one random
// string that the *simplified* regexp matches. The caller re-verifies with the
// compiled regexp before asserting, so any over-generation (anchors, etc.) is
// filtered out rather than causing a false test failure.
func genMatch(r *syntax.Regexp, rng *rand.Rand, depth int) string {
	if depth > 60 {
		return ""
	}
	switch r.Op {
	case syntax.OpLiteral:
		// Randomise case so folded literals are exercised in both cases.
		var b strings.Builder
		for _, ru := range r.Rune {
			if r.Flags&syntax.FoldCase != 0 && rng.Intn(2) == 0 {
				b.WriteString(strings.ToUpper(string(ru)))
			} else if r.Flags&syntax.FoldCase != 0 {
				b.WriteString(strings.ToLower(string(ru)))
			} else {
				b.WriteRune(ru)
			}
		}
		return b.String()
	case syntax.OpCharClass:
		if len(r.Rune) >= 2 {
			// Pick a random [lo,hi] pair, then a random rune in it, retrying a
			// few times to land on something printable-ish.
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
			b.WriteString(genMatch(sub, rng, depth+1))
		}
		return b.String()
	case syntax.OpAlternate:
		return genMatch(r.Sub[rng.Intn(len(r.Sub))], rng, depth+1)
	case syntax.OpStar:
		var b strings.Builder
		for i := 0; i < rng.Intn(3); i++ {
			b.WriteString(genMatch(r.Sub[0], rng, depth+1))
		}
		return b.String()
	case syntax.OpPlus:
		var b strings.Builder
		b.WriteString(genMatch(r.Sub[0], rng, depth+1))
		for i := 0; i < rng.Intn(2); i++ {
			b.WriteString(genMatch(r.Sub[0], rng, depth+1))
		}
		return b.String()
	case syntax.OpQuest:
		if rng.Intn(2) == 0 {
			return genMatch(r.Sub[0], rng, depth+1)
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
			b.WriteString(genMatch(r.Sub[0], rng, depth+1))
		}
		return b.String()
	case syntax.OpCapture:
		return genMatch(r.Sub[0], rng, depth+1)
	}
	// Zero-width assertions / empty: contribute nothing.
	return ""
}

// assertGateSound checks the never-skip-a-real-match invariant for one pattern
// over many randomly generated matching strings.
func assertGateSound(t *testing.T, pattern string, iters int) {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return // pattern itself doesn't compile as a Go regexp; not our concern
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return
	}
	parsed = parsed.Simplify()
	pf := CompilePrefilter(pattern)

	rng := rand.New(rand.NewSource(0x5eed))
	checked := 0
	for i := 0; i < iters; i++ {
		s := genMatch(parsed, rng, 0)
		if s == "" {
			continue
		}
		// Only assert on strings the *real* compiled regexp actually matches.
		if !re.MatchString(s) {
			continue
		}
		checked++
		if !pf.MightMatch(strings.ToLower(s)) {
			t.Fatalf("GATE UNSOUND: pattern %q matched %q but prefilter skipped it\n  groups=%v",
				pattern, s, pf.Groups)
		}
	}
	_ = checked
}

// TestPrefilterSoundness_Curated locks the invariant on hand-picked patterns
// that exercise every construction path (fold, concat, top-level alternation,
// alternation with a short branch, nested, plus/capture).
func TestPrefilterSoundness_Curated(t *testing.T) {
	patterns := []string{
		`(?i)\bos\.(system|popen|popen2)\s*\(`,
		`(?i)(SELECT|INSERT|UPDATE|DELETE)\s+`,
		`(?i)Runtime\.getRuntime`,
		`(?i)subprocess\.(call|run|Popen)\s*\(`,
		`(?i)\beval\s*\(`,
		`(?i)(foo|x)bar`,            // short branch "x" → alternation unusable, but "bar" forced
		`(?i)password\s*=\s*["'].+`, // forced literal "password"
		`md5|sha1`,                  // top-level alt, both usable
		`(?i)(md5|sha1|x)`,          // one short branch → whole alt unusable → always run
		`(?i)\.innerHTML\s*=`,
		`(?i)child_process\.(exec|spawn)`,
		`(?i)verify\s*=\s*(false|False)`,
		`(?i)(?:DocumentBuilderFactory|SAXParserFactory)`,
		`(?i)pickle\.(loads|load)\b`,
	}
	for _, p := range patterns {
		assertGateSound(t, p, 4000)
	}
}

// TestPrefilterSoundness_AllRegexRules walks every registered RegexRule and
// fuzzes the gate against each pattern with generator-produced matching
// strings. This is the broad net: it covers the data-driven rule corpus that
// the per-line gate upgrades for free.
func TestPrefilterSoundness_AllRegexRules(t *testing.T) {
	patterns := collectRegexRulePatterns()
	if len(patterns) == 0 {
		t.Skip("no RegexRule patterns registered (rule packages not imported in this test binary)")
	}
	for _, p := range patterns {
		assertGateSound(t, p, 600)
	}
	t.Logf("fuzzed %d RegexRule patterns", len(patterns))
}

func collectRegexRulePatterns() []string {
	var out []string
	for _, r := range All() {
		rr, ok := r.(*RegexRule)
		if !ok {
			continue
		}
		for _, re := range rr.Patterns {
			out = append(out, re.String())
		}
	}
	return out
}

// TestPrefilter_ActuallySkips proves the gate is not a no-op: lines lacking the
// required literal are skipped, lines containing it are candidates.
func TestPrefilter_ActuallySkips(t *testing.T) {
	pf := CompilePrefilter(`(?i)\bos\.system\s*\(`)
	if pf.alwaysRun() {
		t.Fatalf("expected a usable prefilter for os.system, got always-run")
	}
	if pf.MightMatch("nothing relevant on this line at all") {
		t.Errorf("expected skip on a line without 'os.system'")
	}
	if !pf.MightMatch("    result = os.system(cmd)") {
		t.Errorf("expected candidate on a line with 'os.system'")
	}
	// Fold-aware: an uppercase occurrence must gate on the lowered line.
	if !pf.MightMatch(strings.ToLower("    RESULT = OS.SYSTEM(CMD)")) {
		t.Errorf("expected candidate on lowered uppercase line")
	}
}

// TestPrefilter_TopLevelAlternation confirms an alternation with all-usable
// branches produces a single OR-group and gates correctly.
func TestPrefilter_TopLevelAlternation(t *testing.T) {
	pf := CompilePrefilter(`(?i)(SELECT|INSERT|UPDATE)\s+from`)
	if pf.alwaysRun() {
		t.Fatalf("expected usable prefilter for SELECT/INSERT/UPDATE alternation")
	}
	if pf.MightMatch("plain text line") {
		t.Errorf("line without any branch literal should be skipped")
	}
	for _, kw := range []string{"select x from", "insert into from", "update t from"} {
		if !pf.MightMatch(kw) {
			t.Errorf("line %q with a branch literal should be a candidate", kw)
		}
	}
}

// TestGHelpers_EquivalentOnMatches asserts the gated G* helpers return exactly
// what the bare regexp methods return whenever the regexp actually matches —
// i.e. the gate never suppresses a real match. (On non-matches both sides
// return the zero value, so equality there is trivial and not the risk.)
func TestGHelpers_EquivalentOnMatches(t *testing.T) {
	patterns := []string{
		`(?i)\bos\.(system|popen)\s*\(`,
		`(?i)(SELECT|INSERT|UPDATE|DELETE)\s+\w`,
		`(?i)password\s*=\s*["'][^"']+["']`,
		`(?i)Runtime\.getRuntime\(\)\.exec`,
		`md5|sha1|sha256`,
		`(?i)child_process\.(exec|spawn)\s*\(`,
		`(?i)\.innerHTML\s*=\s*\w`,
	}
	rng := rand.New(rand.NewSource(99))
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		parsed, _ := syntax.Parse(p, syntax.Perl)
		parsed = parsed.Simplify()
		for i := 0; i < 3000; i++ {
			s := genMatch(parsed, rng, 0)
			if s == "" || !re.MatchString(s) {
				continue
			}
			if GFind(re, s) != re.FindString(s) {
				t.Fatalf("GFind dropped match: pattern %q line %q", p, s)
			}
			if !GMatch(re, s) {
				t.Fatalf("GMatch dropped match: pattern %q line %q", p, s)
			}
			gi, ri := GFindIndex(re, s), re.FindStringIndex(s)
			if (gi == nil) != (ri == nil) || (gi != nil && (gi[0] != ri[0] || gi[1] != ri[1])) {
				t.Fatalf("GFindIndex disagreed: pattern %q line %q got %v want %v", p, s, gi, ri)
			}
			gs, rs := GFindSubmatch(re, s), re.FindStringSubmatch(s)
			if len(gs) != len(rs) {
				t.Fatalf("GFindSubmatch len disagreed: pattern %q line %q", p, s)
			}
			gas, ras := GFindAllSubmatch(re, s, -1), re.FindAllStringSubmatch(s, -1)
			if len(gas) != len(ras) {
				t.Fatalf("GFindAllSubmatch count disagreed: pattern %q line %q got %d want %d", p, s, len(gas), len(ras))
			}
			gai, rai := GFindAllIndex(re, s, -1), re.FindAllStringIndex(s, -1)
			if len(gai) != len(rai) {
				t.Fatalf("GFindAllIndex count disagreed: pattern %q line %q got %d want %d", p, s, len(gai), len(rai))
			}
		}
	}
}

// TestToLowerASCII_MatchesStdlibFold asserts the fast ASCII lowering used by the
// G* gate produces a string with the same lowercase substring behaviour as
// strings.ToLower for the inputs the gate sees, including non-ASCII fallback.
func TestToLowerASCII_MatchesStdlibFold(t *testing.T) {
	cases := []string{
		"", "already lower", "MiXeD CaSe Line", "ALLUPPER",
		"os.System(CMD)", "  Runtime.getRuntime()  ",
		"naïve café ünïcode MD5", "日本語 SELECT FROM", "\tTAB\tand SHA1",
	}
	for _, s := range cases {
		got := toLowerASCII(s)
		// For ASCII-only inputs, toLowerASCII must equal strings.ToLower exactly.
		ascii := true
		for i := 0; i < len(s); i++ {
			if s[i] >= utf8RuneSelf {
				ascii = false
				break
			}
		}
		if ascii && got != strings.ToLower(s) {
			t.Errorf("toLowerASCII(%q)=%q, want %q", s, got, strings.ToLower(s))
		}
		// In all cases the result must contain no ASCII uppercase letters.
		for i := 0; i < len(got); i++ {
			if 'A' <= got[i] && got[i] <= 'Z' {
				t.Errorf("toLowerASCII(%q) left ASCII uppercase: %q", s, got)
				break
			}
		}
	}
}

// TestGHelpers_NonASCIISound checks the gate never drops a match on lines with
// non-ASCII bytes (the toLowerASCII Unicode fallback path).
func TestGHelpers_NonASCIISound(t *testing.T) {
	re := regexp.MustCompile(`(?i)password\s*=\s*["'][^"']+["']`)
	lines := []string{
		`café_PASSWORD = "naïve-secret"`,
		`日本 Password = 'ünïcode'`,
		`PASSWORD = "x"  // comment with é`,
	}
	for _, l := range lines {
		if re.MatchString(l) && GFind(re, l) != re.FindString(l) {
			t.Fatalf("non-ASCII gate dropped a match on %q", l)
		}
	}
}

// TestPrefilter_UnusableAlternationAlwaysRuns confirms that an alternation with
// even one too-short / unconstrained branch degrades to always-run (so it can
// never skip a real match through that branch).
func TestPrefilter_UnusableAlternationAlwaysRuns(t *testing.T) {
	// "x" is below minGateLit, so the alternation cannot be gated.
	pf := CompilePrefilter(`(?i)(password|x)`)
	if !pf.alwaysRun() {
		t.Errorf("alternation with a short branch must degrade to always-run, got groups=%v", pf.Groups)
	}
	if !pf.MightMatch("anything") {
		t.Errorf("always-run prefilter must accept every line")
	}
}

// TestGMatchFile_EquivalentToRaw asserts the whole-file guard gate
// (GMatchFile / FileMightMatch) is finding-identical to a raw
// re.MatchString(ctx.Content) across a corpus of generated file contents: it
// must never return false when the regex actually matches somewhere in the
// content, and (the easy direction) returns true exactly when the regex matches
// for satisfiable patterns. Mirrors the whole-file early-exit guards that the
// hand-written Go rules use.
func TestGMatchFile_EquivalentToRaw(t *testing.T) {
	patterns := []string{
		`(?i)(?:sync\.(?:Mutex|RWMutex)|\.Lock\(\)|atomic\.)`,
		`(?i)(?:csrf|nosurf|gorilla/csrf|CSRFProtect)`,
		`"math/rand"`,
		`func\s+\w*\s*\(\s*w\s+http\.ResponseWriter|http\.HandlerFunc|gin\.Context`,
		`strings\.HasPrefix\s*\(`,
		`(?i)(?:validate|validator)`,
	}
	rng := rand.New(rand.NewSource(7))
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		parsed, _ := syntax.Parse(p, syntax.Perl)
		parsed = parsed.Simplify()
		for i := 0; i < 4000; i++ {
			// Build a multi-line "file" with the generated match embedded in
			// surrounding noise lines, so we exercise whole-file scanning.
			frag := genMatch(parsed, rng, 0)
			content := "package p\nfunc noise() {}\n" + frag + "\n// trailing\n"
			ctx := &ScanContext{Content: content} // ContentLower nil → LowerContent() lowers on demand
			raw := re.MatchString(ctx.Content)
			gated := GMatchFile(re, ctx)
			if raw != gated {
				t.Fatalf("GMatchFile disagreed with raw MatchString\npattern %q\nraw=%v gated=%v\ncontent=%q", p, raw, gated, content)
			}
			// With ContentLower populated (the scan-pipeline path) the result must
			// be identical too.
			ctx2 := &ScanContext{Content: content, ContentLower: strings.ToLower(content)}
			if GMatchFile(re, ctx2) != raw {
				t.Fatalf("GMatchFile with populated ContentLower disagreed\npattern %q content=%q", p, content)
			}
		}
	}
}

// TestGFindLower_EquivalentToGFind asserts the shared-lowered-line helpers
// (GFindLower / GFindIndexLower / GFindSubmatchLower / GMatchLower) are
// finding-identical to their per-call-lowering GFind* counterparts, given the
// lowered line equals strings.ToLower(line).
func TestGFindLower_EquivalentToGFind(t *testing.T) {
	patterns := []string{
		`(?i)\bos\.(system|popen)\s*\(`,
		`(?i)password\s*=\s*["'][^"']+["']`,
		`md5|sha1|sha256`,
		`\bhttp\.ListenAndServe\s*\(`,
	}
	rng := rand.New(rand.NewSource(31))
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		parsed, _ := syntax.Parse(p, syntax.Perl)
		parsed = parsed.Simplify()
		for i := 0; i < 3000; i++ {
			s := genMatch(parsed, rng, 0)
			if s == "" || !re.MatchString(s) {
				continue
			}
			lo := strings.ToLower(s)
			if GFindLower(re, s, lo) != GFind(re, s) {
				t.Fatalf("GFindLower != GFind: pattern %q line %q", p, s)
			}
			if GMatchLower(re, s, lo) != GMatch(re, s) {
				t.Fatalf("GMatchLower != GMatch: pattern %q line %q", p, s)
			}
			gi, ri := GFindIndexLower(re, s, lo), GFindIndex(re, s)
			if (gi == nil) != (ri == nil) || (gi != nil && (gi[0] != ri[0] || gi[1] != ri[1])) {
				t.Fatalf("GFindIndexLower disagreed: pattern %q line %q", p, s)
			}
			if len(GFindSubmatchLower(re, s, lo)) != len(GFindSubmatch(re, s)) {
				t.Fatalf("GFindSubmatchLower disagreed: pattern %q line %q", p, s)
			}
		}
	}
}

// TestLowerContent_FallbackAndShared confirms LowerContent reuses the populated
// field and falls back to strings.ToLower otherwise.
func TestLowerContent_FallbackAndShared(t *testing.T) {
	c := &ScanContext{Content: "Mixed CASE Content"}
	if got := c.LowerContent(); got != "mixed case content" {
		t.Errorf("on-demand LowerContent = %q", got)
	}
	c2 := &ScanContext{Content: "RAW", ContentLower: "sentinel-not-derived"}
	if got := c2.LowerContent(); got != "sentinel-not-derived" {
		t.Errorf("LowerContent ignored populated ContentLower, got %q", got)
	}
	if got := (&ScanContext{}).LowerContent(); got != "" {
		t.Errorf("empty content LowerContent = %q", got)
	}
}
