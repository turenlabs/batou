// Cross-file Lua interproc walker tests (PR-Glua).
//
// These tests exercise the full Lua cross-file pipeline:
//   1. buildLuaNodes registers FuncNodes for each .lua file.
//   2. ResolveCrossFileEdges resolves `require("mod")` to mod.lua and
//      wires up caller→callee edges between the files.
//   3. WalkCrossFileTaintFlows dispatches to AnalyzeCallerImpactLua for
//      Lua callees and emits BATOU-INTERPROC-<CAT> findings.
//
// Lua-specific notes vs. the Ruby / JS equivalents:
//   - Module imports are `local m = require("mod")`; the require result is
//     bound to the local `m`, and later `m.method()` calls reference it.
//   - The required module returns a table of named functions
//     (`function M.x() ... end ... return M`); a `m.x()` call's basename
//     is `x` and the callee is registered as `M.x`.
//   - Path B (tainted return): the canonical OpenResty getter idiom —
//     `function M.get_id() return ngx.var.arg_id end` — is auto-detected
//     by ensureLuaCalleeReturns, so no planted TaintedReturns is needed.

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// luaScanFixture builds a tiny Lua project: writes files, builds Lua
// FuncNodes, resolves cross-file edges, and returns the populated
// CallGraph plus the absolute path to each file by relative name.
//
// A minimal `.luarc.json` marker is added when none is present so the Lua
// resolver's ProjectRoot anchors cleanly.
func luaScanFixture(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	if _, present := files[".luarc.json"]; !present {
		files[".luarc.json"] = "{}\n"
	}
	if err := writeFiles(t, root, files); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	cg := NewCallGraph(root, "test")
	paths := map[string]string{}
	contents := map[string][]byte{}
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		paths[rel] = abs
		if !strings.HasSuffix(rel, ".lua") {
			continue
		}
		buildLuaNodes(cg, abs, content, nil)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// TestLuaCrossFile_TaintedReturn_SQLi is the canonical Path-B case: a
// required module exposes a getter returning request-controlled data
// (ngx.var.arg_id) and the importer forwards that return value inline
// into a SQL sink. Expected: BATOU-INTERPROC-SQL_QUERY (CWE-89) with a
// sink step in app.lua and a source step in mod.lua.
func TestLuaCrossFile_TaintedReturn_SQLi(t *testing.T) {
	cg, paths := luaScanFixture(t, map[string]string{
		"mod.lua": `local M = {}

function M.get_id()
  return ngx.var.arg_id
end

return M
`,
		"app.lua": `local m = require("mod")

local function handle(db)
  db:query(m.get_id())
end

return handle
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqli := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqli) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via require()+tainted-return; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// The flow must cross files: a source step in mod.lua and a sink step
	// in app.lua.
	srcInMod, sinkInApp := false, false
	for _, f := range sqli {
		if f.CWEID != "CWE-89" {
			t.Errorf("expected CWE-89, got %q", f.CWEID)
		}
		if f.Language != rules.LangLua {
			t.Errorf("expected Language lua, got %q", f.Language)
		}
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSource && st.File == paths["mod.lua"] {
				srcInMod = true
			}
			if st.Kind == rules.TaintStepSink && st.File == paths["app.lua"] {
				sinkInApp = true
			}
		}
	}
	if !srcInMod {
		t.Errorf("no SQLi finding had a source step in mod.lua; findings=%v", findingRuleIDs(findings))
	}
	if !sinkInApp {
		t.Errorf("no SQLi finding had a sink step in app.lua; findings=%v", findingRuleIDs(findings))
	}
}

// TestLuaCrossFile_TaintedReturn_ViaVariable covers the Path-B variant
// where the tainted return is stored in an intermediate local before
// reaching the sink (`local id = m.get_id(); db:query(id)`).
func TestLuaCrossFile_TaintedReturn_ViaVariable(t *testing.T) {
	cg, _ := luaScanFixture(t, map[string]string{
		"src.lua": `local S = {}

function S.read_body()
  return ngx.req.get_body_data()
end

return S
`,
		"router.lua": `local s = require("src")

local function route(db)
  local body = s.read_body()
  db:query(body)
end

return route
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via intermediate variable; got %v",
			findingRuleIDs(findings))
	}
}

// TestLuaCrossFile_PassTaintToCallee covers Path A: the importer reads a
// source and passes it as an argument to a module function that forwards
// it to a SQL sink. Expected BATOU-INTERPROC-SQL_QUERY.
func TestLuaCrossFile_PassTaintToCallee(t *testing.T) {
	cg, _ := luaScanFixture(t, map[string]string{
		"dao.lua": `local D = {}

function D.lookup(db, name)
  db:query("SELECT * FROM users WHERE name = " .. name)
end

return D
`,
		"handler.lua": `local d = require("dao")

local function serve(db)
  local who = ngx.var.arg_name
  d.lookup(db, who)
end

return serve
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via Path A (tainted arg); got %v",
			findingRuleIDs(findings))
	}
}

// TestLuaCrossFile_Sanitized_NoFinding is the negative control: the
// importer wraps the tainted return in ngx.quote_sql_str before the sink,
// so no cross-file finding should be produced.
func TestLuaCrossFile_Sanitized_NoFinding(t *testing.T) {
	cg, _ := luaScanFixture(t, map[string]string{
		"mod.lua": `local M = {}

function M.get_id()
  return ngx.var.arg_id
end

return M
`,
		"app.lua": `local m = require("mod")

local function handle(db)
  local id = m.get_id()
  local safe = ngx.quote_sql_str(id)
  db:query(safe)
end

return handle
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY"); len(got) != 0 {
		t.Fatalf("expected no SQLi finding when sanitized with ngx.quote_sql_str; got %d: %v",
			len(got), findingRuleIDs(findings))
	}
}

// TestLuaCrossFile_NoBleed_PureReturn ensures a module getter that
// returns a constant (no taint) produces no cross-file finding even when
// the importer forwards it to a sink — the tainted-return detector must
// not over-fire.
func TestLuaCrossFile_NoBleed_PureReturn(t *testing.T) {
	cg, _ := luaScanFixture(t, map[string]string{
		"cfg.lua": `local C = {}

function C.table_name()
  return "users"
end

return C
`,
		"app.lua": `local c = require("cfg")

local function handle(db)
  db:query(c.table_name())
end

return handle
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY"); len(got) != 0 {
		t.Fatalf("expected no finding for a pure constant return; got %d: %v",
			len(got), findingRuleIDs(findings))
	}
}
