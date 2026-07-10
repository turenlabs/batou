package ast

import (
	"sync"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestParseConcurrencyDeterministic guards the per-language parse lock in Parse.
//
// Several tree-sitter grammars ship an external (custom C) scanner that keeps
// non-reentrant global state — lua's long-string/comment scanner is the known
// offender. Because every parser shares the singleton *sitter.Language (and thus
// its scanner), concurrent same-language parses used to corrupt each other's
// trees: the root child count came back wrong, which cascaded into different
// taint results and made `batou scan <dir>` non-deterministic run to run. The
// corruption is in C code, so the Go race detector never catches it — only a
// shape assertion like this does.
//
// Without the lock this fails (varying child counts); with it, every concurrent
// parse yields the identical tree shape.
func TestParseConcurrencyDeterministic(t *testing.T) {
	// Source that exercises lua's external scanner: a line comment, a method
	// call with a string pattern, and a [[ long string ]].
	src := []byte("-- header comment\n" +
		"local name = args.file\n" +
		"if not name:match(\"^[%w_%-%.]+$\") then return end\n" +
		"local f = io.open(\"/srv/\" .. name)\n" +
		"local blob = [[ a long\nbracketed string ]]\n" +
		"return f, blob\n")

	const N = 128
	counts := make([]int, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tr := Parse(src, rules.LangLua)
			if tr == nil || tr.Root() == nil {
				counts[idx] = -1
				return
			}
			counts[idx] = tr.Root().ChildCount()
		}(i)
	}
	wg.Wait()

	want := counts[0]
	if want <= 0 {
		t.Fatalf("expected a valid lua parse with children, got %d", want)
	}
	for i, c := range counts {
		if c != want {
			t.Fatalf("non-deterministic concurrent parse: goroutine %d produced %d root children, want %d "+
				"(per-language parse serialization regressed)", i, c, want)
		}
	}
}
