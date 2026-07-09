package ast

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/turenlabs/batou-rules/rules"
)

// pathologicalCPP returns a small (~200KB) C++ source that drives the cpp
// grammar's parser into a tight loop. tree-sitter cancellation is cooperative,
// so without the hard wall-clock timeout in Parse this input hangs the calling
// goroutine in cgo indefinitely (observed >40s against the 2s parseTimeout).
// It is the deterministic repro for the `batou scan` hang.
func pathologicalCPP() []byte {
	var b bytes.Buffer
	b.WriteString("int f(){return ")
	b.Write(bytes.Repeat([]byte("("), 200000)) // unbalanced open-parens
	b.WriteString(";}")
	return b.Bytes()
}

// hangEnvKey, when set, makes the test binary run ONLY the pathological-parse
// body and exit. The genuine hang leaks a goroutine wedged in cgo that holds
// the cpp semaphore token forever; running it in a re-exec'd subprocess keeps
// that leak (and its degraded-cpp side effect) out of the parent test binary,
// so sibling tests like ast_test.go's TestParse_CPP still get a fresh grammar.
const hangEnvKey = "BATOU_AST_HANG_SUBPROCESS"

// TestParseHardTimeoutDoesNotHang is the core regression guard: a SMALL
// pathological input must make Parse RETURN (nil tree / regex-only fallback)
// within a bounded wall-clock time, never hang. Before the hard-timeout fix
// this Parse call blocked forever in tree-sitter's external scanner despite the
// cooperative 2s parseTimeout.
//
// The actual Parse-of-pathological-input runs in a re-exec'd subprocess (see
// hangEnvKey) so the leaked cgo spinner it spawns dies with that subprocess and
// never poisons cpp for the rest of this test binary. The parent asserts the
// subprocess completes well within a wall-clock ceiling.
func TestParseHardTimeoutDoesNotHang(t *testing.T) {
	if os.Getenv(hangEnvKey) == "1" {
		// Subprocess body: this Parse must return on its own (hard timeout),
		// not hang. If the fix regressed, the subprocess hangs and the parent's
		// CommandContext deadline kills it -> the parent test fails.
		start := time.Now()
		tree := Parse(pathologicalCPP(), rules.LangCPP)
		// Print to stdout so the parent can confirm we got past Parse.
		_, _ = os.Stdout.WriteString("PARSE_RETURNED elapsed=" + time.Since(start).String() +
			" nil=" + boolStr(tree == nil) + "\n")
		os.Exit(0)
	}

	// Parent: re-exec just this test in a subprocess with a hard kill deadline.
	const ceiling = hardParseTimeout + 8*time.Second
	cmd := exec.Command(os.Args[0], "-test.run", "^TestParseHardTimeoutDoesNotHang$", "-test.v")
	cmd.Env = append(os.Environ(), hangEnvKey+"=1")
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting subprocess: %v", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	start := time.Now()
	select {
	case err := <-waitErr:
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("subprocess failed (%v) in %v; output:\n%s", err, elapsed, out.String())
		}
		if !strings.Contains(out.String(), "PARSE_RETURNED") {
			t.Fatalf("subprocess did not reach the post-Parse marker; output:\n%s", out.String())
		}
		t.Logf("pathological Parse returned (subprocess) in %v; child output: %s",
			elapsed, strings.TrimSpace(lastLine(out.String())))
	case <-time.After(ceiling):
		_ = cmd.Process.Kill()
		t.Fatalf("Parse DID NOT return within %v on a small pathological cpp input -- the hang regressed.\nSubprocess output so far:\n%s", ceiling, out.String())
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func lastLine(s string) string {
	s = strings.TrimRight(s, "\n")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// TestParseWedgedLanguageFailsFastNoDeadlock verifies blast-radius
// containment. When a language's per-language semaphore token is held (the
// state a hard-timed-out parse leaves behind: a goroutine wedged in cgo that
// never releases its token), subsequent SAME-language parses must fail-fast to
// nil within acquireTimeout instead of deadlocking — and a DIFFERENT language
// must still parse normally.
//
// We simulate the wedge by manually taking the token rather than actually
// hanging a parse, so the test (a) is fast and deterministic, and (b) does NOT
// permanently poison a real shared language for sibling tests in this package
// (ast_test.go parses cpp too). The token is restored before return.
func TestParseWedgedLanguageFailsFastNoDeadlock(t *testing.T) {
	// Use Rust here: it is NOT one of the languages other ast tests wedge, and
	// restoring the token at the end keeps it clean regardless.
	const wedged = rules.LangRust
	sem := langParseSem(wedged)
	sem <- struct{}{} // simulate a wedged parse holding the token forever
	released := false
	defer func() {
		if !released {
			<-sem // restore so the language works for any later test
		}
	}()

	// A parse of the wedged language must fail-fast (token unavailable) and
	// return nil within ~acquireTimeout, never block indefinitely.
	start := time.Now()
	done := make(chan *Tree, 1)
	go func() { done <- Parse([]byte("fn g() -> i32 { 0 }"), wedged) }()
	select {
	case tree := <-done:
		elapsed := time.Since(start)
		if tree != nil {
			t.Fatalf("expected nil from a wedged-language parse, got a tree")
		}
		if elapsed < acquireTimeout-time.Second {
			t.Fatalf("fail-fast returned suspiciously early (%v); did it actually wait on the token?", elapsed)
		}
		t.Logf("wedged-language parse failed fast in %v", elapsed)
	case <-time.After(acquireTimeout + 6*time.Second):
		t.Fatalf("wedged-language parse deadlocked -- semaphore fail-fast regressed")
	}

	// A DIFFERENT language must be completely unaffected while the first is
	// wedged.
	goTree := Parse([]byte("package main\nfunc main(){ _ = 1 }\n"), rules.LangGo)
	if goTree == nil || goTree.Root() == nil {
		t.Fatalf("a different language (go) failed to parse while another was wedged -- blast radius leaked across languages")
	}

	// Restore the token and confirm the previously-wedged language recovers.
	<-sem
	released = true
	rustTree := Parse([]byte("fn g() -> i32 { 0 }"), wedged)
	if rustTree == nil || rustTree.Root() == nil {
		t.Fatalf("language did not recover after the token was released")
	}
}

// TestParseSizeCap verifies the defense-in-depth size guard: inputs larger than
// maxParseBytes skip AST parsing and return nil immediately.
func TestParseSizeCap(t *testing.T) {
	big := bytes.Repeat([]byte("a = 1\n"), (maxParseBytes/6)+10) // > maxParseBytes
	if len(big) <= maxParseBytes {
		t.Fatalf("test setup: input not larger than cap (%d <= %d)", len(big), maxParseBytes)
	}
	start := time.Now()
	tree := Parse(big, rules.LangPython)
	if tree != nil {
		t.Fatalf("expected nil tree for oversized input, got non-nil")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("size cap should return immediately, took %v", d)
	}

	// And a normal-sized input of the same language still parses fine.
	small := Parse([]byte("x = 1\n"), rules.LangPython)
	if small == nil || small.Root() == nil {
		t.Fatalf("normal-sized python parse failed after size-cap path")
	}
}
