package tsflow

// Regression test for the CATjs-2 cloneMap nil-map panic.
//
// Symptom: scanning real-world JS/TS with `if`+`assign` shapes panics at
// `tm.freshLocalEmpty[lhsName] = true` because cloneMap() didn't initialize
// the freshLocalEmpty field that PR-CATjs-2 added. processIfBranchAware
// clones the taintMap for each branch, then the body assignment walker
// calls recordFreshLocalEmptyIfJS on the clone — boom.
//
// Caught by PR-RESCAN-jsts-2 (all 3 OSS repos crashed); fixed by adding
// the field to cloneMap() and a defensive nil guard in the write site.

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// TestJS_CloneMap_FreshLocalEmpty_NoPanic exercises the exact shape that
// crashed in production: an `if` branch followed by a `const x = {}`
// assignment inside the cloned branch context. Pre-fix this panics; with
// cloneMap copying freshLocalEmpty this completes cleanly.
func TestJS_CloneMap_FreshLocalEmpty_NoPanic(t *testing.T) {
	code := `
function handler(req, res) {
    if (req.method === "POST") {
        const opts = {};
        Object.assign(opts, req.body);
        return res.json(opts);
    }
    return res.status(405).end();
}
`
	// Analyze should not panic. Don't care about findings — we're proving
	// the walker completes.
	_ = Analyze(code, "/app/handler.js", rules.LangJavaScript)
}

// TestJS_CloneMap_FreshLocalEmpty_NestedIf_NoPanic verifies nested branches
// (multiple clones) also complete.
func TestJS_CloneMap_FreshLocalEmpty_NestedIf_NoPanic(t *testing.T) {
	code := `
function handler(req, res) {
    if (req.method === "POST") {
        if (req.headers.authorization) {
            const merged = {};
            Object.assign(merged, req.body);
            return res.json(merged);
        }
    }
    return res.status(400).end();
}
`
	_ = Analyze(code, "/app/handler.js", rules.LangJavaScript)
}

// TestJS_CloneMap_FreshLocalEmpty_TypeScript_NoPanic covers the TS variant.
func TestJS_CloneMap_FreshLocalEmpty_TypeScript_NoPanic(t *testing.T) {
	code := `
function handler(req: any, res: any): void {
    if (req.method === "POST") {
        const opts: Record<string, unknown> = {};
        Object.assign(opts, req.body);
        res.json(opts);
        return;
    }
    res.status(405).end();
}
`
	_ = Analyze(code, "/app/handler.ts", rules.LangTypeScript)
}
