package ast

import (
	"context"
	"strings"
	"sync"
	"time"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/turenlabs/batou-rules/rules"
)

// parseTimeout is the cooperative deadline handed to tree-sitter's ParseCtx.
// Parsing is typically sub-millisecond; this cap lets a well-behaved grammar
// abort early on a large-but-tractable input. It is NOT a hard guarantee — see
// hardParseTimeout below for why.
const parseTimeout = 2 * time.Second

// hardParseTimeout is the WALL-CLOCK ceiling on a single Parse call. It exists
// because tree-sitter cancellation is COOPERATIVE: ParseCtx sets a flag the
// grammar only checks between parse steps, so a grammar whose external (custom
// C) scanner enters a tight loop on a pathological input never reaches the
// check and ParseCtx blocks its calling goroutine in cgo FOREVER — the 2s
// parseTimeout above is silently ineffective (observed: a ~100-200KB cpp file
// of unbalanced '(' / '{' spins past 40s). A goroutine stuck in a cgo call
// cannot be killed, so we run the parse on a sacrificial goroutine and abandon
// it after this deadline, returning nil (regex-only fallback) instead of
// hanging the whole `batou scan`. The abandoned goroutine keeps spinning one
// core until the process exits; acquireTimeout below bounds that blast radius
// to a single spinner per offending language.
const hardParseTimeout = 4 * time.Second

// acquireTimeout bounds how long a parse waits to enter the per-language
// critical section (see parseSem). Under normal load this is never hit —
// same-language parses are sub-millisecond and the semaphore is released
// promptly. It only fires when a PRIOR same-language parse hit
// hardParseTimeout and is wedged in cgo holding the semaphore token forever;
// rather than block (which would re-create the hang transitively), later
// same-language parses fail-fast and return nil. Net effect: a single
// pathological file degrades ONLY its own language to regex-only for the rest
// of the process, and leaks exactly ONE spinning goroutine — every other
// language and every later file keep working.
const acquireTimeout = 5 * time.Second

// maxParseBytes is a defense-in-depth size cap. A security scanner has no
// reason to build a full AST for a multi-megabyte source blob (e.g. the 18MB
// vendored tree-sitter perl parser.c, or a minified bundle): the parse is slow,
// allocation-heavy, and far more likely to wander into a pathological grammar
// path. Inputs larger than this skip AST parsing entirely and fall back to
// regex-only analysis. NOTE this is a complement, not the core fix — the
// hard-timeout machinery above handles SMALL pathological files (a 100KB cpp
// file hangs just as hard as a 10MB one), which a size cap alone cannot.
const maxParseBytes = 2 * 1024 * 1024 // 2 MiB

// parseSem serialises tree-sitter parsing PER LANGUAGE. Several grammars ship
// an external (custom C) scanner that keeps non-reentrant global/static state —
// lua's long-string/comment scanner is the worst offender. Because every parser
// shares the singleton *sitter.Language for a grammar (and therefore its
// scanner), two goroutines parsing the SAME language at once corrupt each
// other's parse trees: the root child count comes back wrong, which cascades
// into different taint results and made `batou scan <dir>` non-deterministic
// (findings varied run to run). The corruption is in C code, so Go's race
// detector never sees it.
//
// We use a buffered channel of capacity 1 (a counting semaphore) rather than a
// sync.Mutex because a Mutex cannot be acquired with a timeout: if a wedged
// parse held a Mutex, every subsequent same-language Parse would block forever
// on Lock() and the hang would spread. The channel lets later parses
// fail-fast via a select with a timeout (see acquireTimeout). A parse that
// hits hardParseTimeout deliberately NEVER releases its token — the C grammar
// is still executing and reusing its shared scanner, so releasing would let a
// concurrent parse corrupt it. Holding the token forever degrades that one
// language to regex-only, which is the correct safe behaviour.
var parseSem sync.Map // rules.Language -> chan struct{}

// poisonedLangs records languages whose grammar wedged in a non-cooperative
// external-scanner C loop (a hard-timeout fired). Once a language is poisoned,
// every later Parse of it returns nil (regex-only) INSTANTLY, instead of
// waiting acquireTimeout for the per-language token that the abandoned, still-
// spinning goroutine will never release. Without this, a single pathological
// file in a large cross-file scan makes every subsequent same-language parse
// pay acquireTimeout — turning one wedge into minutes of `5s × N` stalls. With
// it, a pathological input costs ~one hardParseTimeout plus one leaked spinner
// for the whole process, and only that one language degrades to regex-only.
var poisonedLangs sync.Map // rules.Language -> struct{}

func langParseSem(lang rules.Language) chan struct{} {
	if s, ok := parseSem.Load(lang); ok {
		return s.(chan struct{})
	}
	s, _ := parseSem.LoadOrStore(lang, make(chan struct{}, 1))
	return s.(chan struct{})
}

// Parse parses content as the given language and returns the AST tree.
// Returns nil if the language has no grammar, the input is too large, parsing
// fails, or parsing exceeds hardParseTimeout (a pathological grammar loop). In
// every nil case the caller falls back to regex-only analysis — completing the
// scan always beats hanging it.
//
// This function is safe to call concurrently; it creates a fresh parser each
// time (tree-sitter parsers are lightweight) and serialises same-language
// parses through a per-language semaphore.
func Parse(content []byte, lang rules.Language) *Tree {
	return parseCore(content, lang, lookupLanguage(lang))
}

// ParseFile is the path-aware parse entry point. It is identical to Parse
// except that it selects the typescript/tsx grammar for `.tsx` files —
// the plain typescript grammar mangles JSX into ERROR nodes, which erases
// import statements and call sites in React/Next components. The returned
// tree's language label stays "typescript" (rules / taint / resolver
// treat .ts and .tsx identically; only grammar selection differs), so
// downstream consumers need no .tsx awareness.
//
// Callers that have the file path (the scanner's Layer-2 parse, the call-
// graph builder/extractor, the cross-file walker, the JS resolver) should
// prefer ParseFile so the cached tree is JSX-aware. Path-less callers fall
// back to Parse (TS grammar), preserving prior behaviour.
func ParseFile(content []byte, lang rules.Language, filePath string) *Tree {
	tsLang := lookupLanguage(lang)
	if lang == rules.LangTypeScript && hasTSXExtension(filePath) {
		if tsx := tsxLanguage(); tsx != nil {
			tsLang = tsx
		}
	}
	return parseCore(content, lang, tsLang)
}

// hasTSXExtension reports whether filePath ends in .tsx (case-insensitive).
func hasTSXExtension(filePath string) bool {
	if len(filePath) < 4 {
		return false
	}
	return strings.EqualFold(filePath[len(filePath)-4:], ".tsx")
}

// parseCore parses content with the explicitly-provided tree-sitter
// grammar. lang governs the semaphore, poison set, and the tree's
// language label; tsLang is the actual grammar used (which may differ
// from lookupLanguage(lang) for .tsx — see ParseFile).
func parseCore(content []byte, lang rules.Language, tsLang *sitter.Language) *Tree {
	if tsLang == nil {
		return nil
	}

	// Defense in depth: never deep-parse an absurdly large blob (see
	// maxParseBytes). The hard-timeout below would still bail us out, but
	// skipping the parse outright avoids burning a goroutine and a core for
	// hardParseTimeout on a file we don't want an AST for anyway.
	if len(content) > maxParseBytes {
		return nil
	}

	// Fail-fast if this language already wedged on a pathological input: skip
	// the doomed acquireTimeout wait for a token that will never be released.
	if _, bad := poisonedLangs.Load(lang); bad {
		return nil
	}

	// Enter the per-language critical section with a timeout. A successful
	// acquire means we received the token and are responsible for releasing
	// it — UNLESS we hit the hard parse timeout below, in which case the
	// wedged goroutine keeps the token (see comment on parseSem). If a prior
	// parse already wedged this language, the acquire times out and we
	// fail-fast to regex-only rather than blocking.
	sem := langParseSem(lang)
	select {
	case sem <- struct{}{}:
		// acquired
	case <-time.After(acquireTimeout):
		// This language is wedged on a pathological input; don't hang.
		return nil
	}

	// Run the parse on a sacrificial goroutine so we can abandon it on a hard
	// wall-clock deadline (ParseCtx cancellation is cooperative and cannot
	// interrupt a tight external-scanner C loop). The goroutine owns the
	// parser's whole lifecycle: it must outlive a timed-out caller, so the
	// caller must never touch (or Close) the parser while C may still be using
	// it. On success the goroutine sends the converted tree AND releases the
	// semaphore; on hard-timeout the caller abandons it and the token is
	// intentionally never released.
	done := make(chan *Tree, 1) // buffered: a late goroutine sends without blocking
	go func() {
		// Release the semaphore ONLY on the normal completion path. If
		// ParseCtx wedges in cgo, this defer is never reached (the goroutine
		// never returns) and the token is held forever, by design.
		parser := sitter.NewParser()
		parser.SetLanguage(tsLang)

		ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)

		tsTree, err := parser.ParseCtx(ctx, nil, content)

		// We reached here, so the parse returned (success, error, or
		// cooperative-cancel). It is now safe to release the lock and tear
		// down the parser: this goroutine alone touched the shared grammar.
		cancel()
		parser.Close()
		<-sem // release the per-language token

		if err != nil || tsTree == nil {
			done <- nil
			return
		}
		root := tsTree.RootNode()
		if root == nil {
			done <- nil
			return
		}
		tree := &Tree{
			content:  content,
			language: string(lang),
		}
		tree.root = convertNode(root, content, nil)
		done <- tree
	}()

	select {
	case tree := <-done:
		return tree
	case <-time.After(hardParseTimeout):
		// The parse is wedged in a cgo loop that ignores cooperative
		// cancellation. We cannot kill the goroutine; abandon it. It still
		// holds the per-language semaphore token. Mark the language poisoned so
		// every later same-language parse fails-fast INSTANTLY (above) instead
		// of paying acquireTimeout — bounding the damage to one spinning core
		// and one degraded language for the rest of the process.
		poisonedLangs.Store(lang, struct{}{})
		return nil
	}
}

// convertNode recursively converts a tree-sitter Node into our internal
// Node type, severing the dependency on tree-sitter's C types.
func convertNode(tsNode *sitter.Node, content []byte, parent *Node) *Node {
	if tsNode == nil {
		return nil
	}

	n := &Node{
		nodeType:  tsNode.Type(),
		startByte: tsNode.StartByte(),
		endByte:   tsNode.EndByte(),
		startRow:  tsNode.StartPoint().Row,
		startCol:  tsNode.StartPoint().Column,
		endRow:    tsNode.EndPoint().Row,
		endCol:    tsNode.EndPoint().Column,
		isNamed:   tsNode.IsNamed(),
		content:   content,
		parent:    parent,
	}

	count := int(tsNode.ChildCount())
	if count > 0 {
		n.children = make([]*Node, count)
		for i := 0; i < count; i++ {
			child := tsNode.Child(i)
			n.children[i] = convertNode(child, content, n)
			n.children[i].fieldName = tsNode.FieldNameForChild(i)
		}
	}

	return n
}
