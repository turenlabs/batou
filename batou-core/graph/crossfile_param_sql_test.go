package graph

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestCrossFile_ParameterizedSQL_NoFinding is the LOAD-BEARING regression
// test for the cross-file parameterized-SQL false positive.
//
// A tainted request value flows ACROSS A FILE/FUNCTION boundary into a repo
// method that runs a PARAMETERIZED query (`WHERE id = ?` with the value bound
// as a separate placeholder argument). A parameterized query is SAFE — the
// value is bound, not spliced into SQL text — and the single-file taint path
// already suppresses it via taint.isParameterizedQuery. The cross-file /
// interproc path must apply the SAME suppression.
//
// The bug: sqlCallIsParameterized / sqlPlaceholderRe (the interproc-side parameterization
// check) used a narrow substring-marker list that missed the common spaced
// form `WHERE id = ?` (the `?` there is followed by a quote/backtick, not
// `,`/`)`/`\n`), so the callee's SQL sink stayed in the signature's SinkCalls
// and the cross-file walk lifted it into a CWE-89 finding on the caller —
// a false positive (skills-classifier cmd/tracker/main.go:405).
//
// This test exercises the REAL signature pipeline (ComputeTaintSig on actual
// Go body content, which routes through computeTaintSigInner ->
// sqlCallIsParameterized) and the REAL cross-file walk
// (WalkCrossFileTaintFlows). It asserts:
//
//  1. the PARAMETERIZED callee produces NO SQL sink in its signature and NO
//     CWE-89 cross-file finding (the FP — fixed);
//  2. the CONCAT callee DOES produce a SQL sink and a CWE-89 cross-file
//     finding (the genuine vulnerability — must NOT be over-suppressed).
//
// Load-bearing: reverting the parameterization check to the old substring-marker
// list makes assertion (1) fail (the `= ?` FP comes back) while assertion (2)
// keeps passing.
func TestCrossFile_ParameterizedSQL_NoFinding(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")

	handlerPath := filepath.Join(root, "handler.go")
	repoPath := filepath.Join(root, "repo.go")

	handlerSrc := `package app

import "net/http"

func GetUserParam(r *Repo, req *http.Request) {
	id := req.URL.Query().Get("id")
	r.FetchParam(id)
}

func GetUserConcat(r *Repo, req *http.Request) {
	id := req.URL.Query().Get("id")
	r.FetchConcat(id)
}
`
	// repo.go: FetchParam runs a parameterized query (`= ?`, id bound);
	// FetchConcat splices id into the SQL text. Same file, different funcs.
	repoSrc := `package app

import "database/sql"

type Repo struct {
	db *sql.DB
}

func (r *Repo) FetchParam(id string) {
	r.db.QueryRow("SELECT name FROM users WHERE id = ?", id)
}

func (r *Repo) FetchConcat(id string) {
	r.db.QueryRow("SELECT name FROM users WHERE id = " + id)
}
`

	// --- Caller nodes (handler.go). Each forwards its user-input param into
	// a cross-file repo method. ---
	cg.AddNode(&FuncNode{
		ID:        handlerPath + ":GetUserParam",
		FilePath:  handlerPath,
		Name:      "GetUserParam",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 5,
		EndLine:   8,
		RawCalls:  []string{"FetchParam"},
		TaintSig: TaintSignature{
			SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput},
		},
	})
	cg.AddNode(&FuncNode{
		ID:        handlerPath + ":GetUserConcat",
		FilePath:  handlerPath,
		Name:      "GetUserConcat",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 10,
		EndLine:   13,
		RawCalls:  []string{"FetchConcat"},
		TaintSig: TaintSignature{
			SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput},
		},
	})

	// --- Callee nodes (repo.go). Their signatures are computed from REAL
	// body content below — this is what exercises sqlCallIsParameterized. ---
	paramCallee := &FuncNode{
		ID:        repoPath + ":FetchParam",
		FilePath:  repoPath,
		Name:      "FetchParam",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 9,
		EndLine:   11,
	}
	concatCallee := &FuncNode{
		ID:        repoPath + ":FetchConcat",
		FilePath:  repoPath,
		Name:      "FetchConcat",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 13,
		EndLine:   15,
	}
	cg.AddNode(paramCallee)
	cg.AddNode(concatCallee)

	// Compute the callee signatures from real Go content through the actual
	// pipeline (flows=nil -> regex fallback path, which runs the param
	// filter). This is the production code path the fix lives in.
	paramCallee.TaintSig = ComputeTaintSig(paramCallee, repoSrc, rules.LangGo, nil, nil)
	concatCallee.TaintSig = ComputeTaintSig(concatCallee, repoSrc, rules.LangGo, nil, nil)

	// --- Assertion 1 (signature level, the precise unit of the fix): the
	// parameterized callee has NO SQL sink in its signature; the concat
	// callee DOES. ---
	if hasSQLSink(paramCallee.TaintSig) {
		t.Errorf("FetchParam (parameterized `= ?`) must NOT carry a SQL sink in its signature; got SinkCalls=%+v", paramCallee.TaintSig.SinkCalls)
	}
	if !hasSQLSink(concatCallee.TaintSig) {
		t.Errorf("FetchConcat (string concat) MUST carry a SQL sink in its signature; got SinkCalls=%+v", concatCallee.TaintSig.SinkCalls)
	}

	// --- Wire the cross-file edges from real content and run the walk. ---
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	contents := map[string][]byte{
		handlerPath: []byte(handlerSrc),
		repoPath:    []byte(repoSrc),
	}
	ResolveCrossFileEdges(cg, root, contents)

	strContents := map[string]string{
		handlerPath: handlerSrc,
		repoPath:    repoSrc,
	}
	findings := WalkCrossFileTaintFlows(cg, strContents)

	// --- Assertion 2 (end-to-end): exactly the concat call yields a CWE-89
	// cross-file finding; the parameterized call yields none. ---
	paramSQL, concatSQL := 0, 0
	for _, f := range findings {
		if f.CWEID != "CWE-89" {
			continue
		}
		// The finding line is the caller call site; map it back via the
		// taint path's sink step (in repo.go) to tell the two apart.
		sinkLine := deepestSinkLine(f)
		switch sinkLine {
		case 10: // r.db.QueryRow("... WHERE id = ?", id) — parameterized
			paramSQL++
		case 14: // r.db.QueryRow("... WHERE id = " + id) — concat
			concatSQL++
		}
	}

	if paramSQL != 0 {
		t.Errorf("FALSE POSITIVE: parameterized cross-file query produced %d CWE-89 finding(s); want 0. Findings: %s", paramSQL, summarizeFindings(findings))
	}
	if concatSQL == 0 {
		t.Errorf("RECALL LOSS: concat cross-file query produced no CWE-89 finding; want >=1. Findings: %s", summarizeFindings(findings))
	}
}

// TestCrossFile_MultiLineParameterizedSQL_NoFinding guards the multi-line
// facet of the same bug: a parameterized query whose `?` placeholder sits on
// a CONTINUATION line below the `db.QueryRow(` call line — the exact shape of
// the original real-repo false positive (skills-classifier cmd/tracker/main.go
// fetchRequest, where `getRequest` forwards r.PathValue("id") across to a
// multi-line `a.db.QueryRow(\`\n ... \nWHERE id = ?\`, id)`).
//
// The sink pattern matches on the call line, which has no placeholder; the `?`
// is several lines down. Checking only the call line leaves the parameterized
// sink in the signature and the cross-file walk lifts it into a spurious
// CWE-89. sqlCallIsParameterized scans the call's continuation lines to catch
// this. A multi-line CONCAT query stays a true positive.
//
// Load-bearing: making sqlCallIsParameterized only inspect the call line (idx)
// makes the parameterized assertion fail.
func TestCrossFile_MultiLineParameterizedSQL_NoFinding(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")

	handlerPath := filepath.Join(root, "handler.go")
	repoPath := filepath.Join(root, "repo.go")

	handlerSrc := `package app

import "net/http"

func GetUserParam(r *Repo, req *http.Request) {
	id := req.URL.Query().Get("id")
	r.FetchParam(id)
}

func GetUserConcat(r *Repo, req *http.Request) {
	id := req.URL.Query().Get("id")
	r.FetchConcat(id)
}
`
	// repo.go: both queries are MULTI-LINE. FetchParam binds id via a `?`
	// placeholder on a continuation line (SAFE); FetchConcat splices id into
	// the SQL text on a continuation line (VULNERABLE).
	repoSrc := `package app

import "database/sql"

type Repo struct {
	db *sql.DB
}

func (r *Repo) FetchParam(id string) {
	row := r.db.QueryRow(` + "`" + `
SELECT id, title, body
FROM requests
WHERE id = ?` + "`" + `, id)
	_ = row
}

func (r *Repo) FetchConcat(id string) {
	row := r.db.QueryRow(` + "`" + `
SELECT id, title, body
FROM requests
WHERE id = ` + "`" + ` + id)
	_ = row
}
`

	cg.AddNode(&FuncNode{
		ID: handlerPath + ":GetUserParam", FilePath: handlerPath, Name: "GetUserParam",
		Package: "app", Language: rules.LangGo, StartLine: 5, EndLine: 8,
		RawCalls: []string{"FetchParam"},
		TaintSig: TaintSignature{SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput}},
	})
	cg.AddNode(&FuncNode{
		ID: handlerPath + ":GetUserConcat", FilePath: handlerPath, Name: "GetUserConcat",
		Package: "app", Language: rules.LangGo, StartLine: 10, EndLine: 13,
		RawCalls: []string{"FetchConcat"},
		TaintSig: TaintSignature{SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput}},
	})

	// FetchParam spans repo.go lines 9-15 (QueryRow call on line 10, `?` on 13).
	paramCallee := &FuncNode{
		ID: repoPath + ":FetchParam", FilePath: repoPath, Name: "FetchParam",
		Package: "app", Language: rules.LangGo, StartLine: 9, EndLine: 15,
	}
	// FetchConcat spans repo.go lines 17-23 (concat on continuation line 21).
	concatCallee := &FuncNode{
		ID: repoPath + ":FetchConcat", FilePath: repoPath, Name: "FetchConcat",
		Package: "app", Language: rules.LangGo, StartLine: 17, EndLine: 23,
	}
	cg.AddNode(paramCallee)
	cg.AddNode(concatCallee)

	paramCallee.TaintSig = ComputeTaintSig(paramCallee, repoSrc, rules.LangGo, nil, nil)
	concatCallee.TaintSig = ComputeTaintSig(concatCallee, repoSrc, rules.LangGo, nil, nil)

	if hasSQLSink(paramCallee.TaintSig) {
		t.Errorf("multi-line FetchParam (parameterized `?` on a continuation line) must NOT carry a SQL sink; got SinkCalls=%+v", paramCallee.TaintSig.SinkCalls)
	}
	if !hasSQLSink(concatCallee.TaintSig) {
		t.Errorf("multi-line FetchConcat (concat) MUST carry a SQL sink; got SinkCalls=%+v", concatCallee.TaintSig.SinkCalls)
	}

	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	ResolveCrossFileEdges(cg, root, map[string][]byte{
		handlerPath: []byte(handlerSrc), repoPath: []byte(repoSrc),
	})
	findings := WalkCrossFileTaintFlows(cg, map[string]string{
		handlerPath: handlerSrc, repoPath: repoSrc,
	})

	paramSQL, concatSQL := 0, 0
	for _, f := range findings {
		if f.CWEID != "CWE-89" {
			continue
		}
		switch sinkLine := deepestSinkLine(f); {
		case sinkLine >= 10 && sinkLine <= 13: // FetchParam QueryRow span
			paramSQL++
		case sinkLine >= 18 && sinkLine <= 21: // FetchConcat QueryRow span
			concatSQL++
		}
	}
	if paramSQL != 0 {
		t.Errorf("FALSE POSITIVE: multi-line parameterized query produced %d CWE-89 finding(s); want 0. Findings: %s", paramSQL, summarizeFindings(findings))
	}
	if concatSQL == 0 {
		t.Errorf("RECALL LOSS: multi-line concat query produced no CWE-89 finding; want >=1. Findings: %s", summarizeFindings(findings))
	}
}

// TestCrossFile_MixedConcatPlaceholderSQL_StillFires is the recall guard for
// the parameterization suppression: a query that BOTH binds a placeholder AND
// concatenates a fragment into the SQL text (`"... WHERE " + col + " ... ?"`)
// is NOT safe — the concatenated fragment is a genuine injection surface. The
// suppression must NOT fire here, so the cross-file CWE-89 still surfaces.
//
// Load-bearing: removing the concat guard in sqlCallIsParameterized makes this
// test fail (the mixed query gets over-suppressed and the SQL sink vanishes).
func TestCrossFile_MixedConcatPlaceholderSQL_StillFires(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	repoPath := filepath.Join(root, "repo.go")

	// ListMixed concatenates `where` into the SQL AND has a trailing `LIMIT ?`
	// placeholder. The concat is the vulnerability; the placeholder must not
	// mask it. repo.go: ListMixed spans lines 9-14 (Query call on line 10).
	repoSrc := `package app

import "database/sql"

type App struct {
	db *sql.DB
}

func (a *App) ListMixed(where string) {
	a.db.Query(` + "`" + `
SELECT id FROM reports
WHERE ` + "`" + ` + where + ` + "`" + `
LIMIT ?` + "`" + `, 50)
}
`
	callee := &FuncNode{
		ID: repoPath + ":ListMixed", FilePath: repoPath, Name: "ListMixed",
		Package: "app", Language: rules.LangGo, StartLine: 9, EndLine: 14,
	}
	cg.AddNode(callee)
	callee.TaintSig = ComputeTaintSig(callee, repoSrc, rules.LangGo, nil, nil)

	if !hasSQLSink(callee.TaintSig) {
		t.Errorf("RECALL LOSS: a query concatenating `where` into SQL must keep its SQL sink even with a trailing `LIMIT ?` placeholder; got SinkCalls=%+v", callee.TaintSig.SinkCalls)
	}
}

// hasSQLSink reports whether a computed signature carries any SQL-query sink.
func hasSQLSink(sig TaintSignature) bool {
	for _, s := range sig.SinkCalls {
		if s.SinkCategory == taint.SnkSQLQuery {
			return true
		}
	}
	return false
}

// deepestSinkLine returns the line of the last sink step in a finding's taint
// path (the actual dangerous call site), or the finding's own line if no sink
// step is present.
func deepestSinkLine(f rules.Finding) int {
	line := f.LineNumber
	for _, st := range f.TaintPath {
		if st.Kind == rules.TaintStepSink {
			line = st.Line
		}
	}
	return line
}

func summarizeFindings(fs []rules.Finding) string {
	out := ""
	for _, f := range fs {
		out += f.RuleID + "@L" + strconv.Itoa(f.LineNumber) + "(sinkL" + strconv.Itoa(deepestSinkLine(f)) + ",cwe=" + f.CWEID + ") "
	}
	if out == "" {
		return "(none)"
	}
	return out
}
