// Cross-file Ruby interproc walker tests (PR-Gruby).
//
// These tests exercise the full Ruby cross-file pipeline:
//   1. buildRubyNodes registers FuncNodes for each .rb file.
//   2. ResolveCrossFileEdges (via per-file import resolution) wires up
//      caller→callee edges between the files.
//   3. WalkCrossFileTaintFlows dispatches to AnalyzeCallerImpactRuby for
//      Ruby callees and emits BATOU-INTERPROC-<CAT> findings.
//
// Negative tests assert that sanitized args produce zero findings.
//
// Ruby-specific notes vs. the JS / Python equivalents:
//   - Module-level requires are `require_relative './foo'` (relative to
//     the importing file's directory) — the resolver handles them.
//   - Module method calls look like `Foo.bar(x)`; the call's basename
//     is `bar` and the callee is registered as `Foo.bar`.
//   - Sinatra DSL route blocks look like `get '/x' do ... params[:y]
//     ... end` and are treated as their own FuncNodes by buildRubyNodes
//     (synthetic name `<verb>@<line>:<col>`).

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// rubyScanFixture builds a tiny project: writes files, builds Ruby
// FuncNodes, resolves cross-file edges, and returns the populated
// CallGraph plus the absolute path to each file by relative name.
//
// A minimal `Gemfile` is added when none is present so the Ruby
// resolver's ProjectRoot anchors cleanly.
func rubyScanFixture(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	if _, present := files["Gemfile"]; !present {
		files["Gemfile"] = "source 'https://rubygems.org'\n"
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
		if !strings.HasSuffix(rel, ".rb") {
			continue
		}
		buildRubyNodes(cg, abs, content, nil)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// primeRubySigs walks every Ruby FuncNode in the graph and runs
// ComputeTaintSigTyped on it so the typed Params + SourceParams are
// available before the cross-file walk. Mirrors primeJavaScriptSigs.
func primeRubySigs(t *testing.T, cg *CallGraph, paths map[string]string) {
	t.Helper()
	contents := map[string]string{}
	for _, abs := range paths {
		data, err := readTestFile(abs)
		if err != nil {
			continue
		}
		contents[abs] = data
	}
	for _, n := range cg.Nodes {
		if n.Language != rules.LangRuby {
			continue
		}
		content, ok := contents[n.FilePath]
		if !ok {
			continue
		}
		n.TaintSig = ComputeTaintSigTyped(n, content, n.Language, nil, nil, nil)
	}
}

// TestRubyCrossFile_SingleHop_Eval covers the canonical 1-hop case via
// `require_relative`: a Sinatra route reads params and calls a helper
// (defined in another file) that passes the input to eval(). Expected:
// BATOU-INTERPROC-CODE_EVAL finding.
func TestRubyCrossFile_SingleHop_Eval(t *testing.T) {
	cg, paths := rubyScanFixture(t, map[string]string{
		"helper.rb": `class Helper
  def self.run_code(code)
    eval(code)
  end
end
`,
		"app.rb": `require_relative './helper'

class App
  def handle(params)
    Helper.run_code(params[:code])
  end
end
`,
	})
	primeRubySigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	evalFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-CODE_EVAL")
	if len(evalFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-CODE_EVAL finding via require_relative shape; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// At least one finding's sink step must point at helper.rb.
	sinkSeen := false
	for _, f := range evalFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["helper.rb"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding had a sink step in helper.rb; findings=%+v", evalFindings)
	}
}

// TestRubyCrossFile_SingleHop_CommandExec covers Path A across files:
// caller forwards params[:cmd] into a helper that runs `system(...)`.
func TestRubyCrossFile_SingleHop_CommandExec(t *testing.T) {
	cg, paths := rubyScanFixture(t, map[string]string{
		"runner.rb": `class Runner
  def self.run_shell(cmd)
    system(cmd)
  end
end
`,
		"app.rb": `require_relative './runner'

class App
  def handle(params)
    Runner.run_shell(params[:cmd])
  end
end
`,
	})
	primeRubySigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC finding; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// Every emitted finding's Language must be Ruby — never Go.
	for _, f := range findings {
		if f.Language != "" && f.Language != rules.LangRuby {
			t.Errorf("finding has wrong Language %q: %+v", f.Language, f)
		}
	}
}

// TestRubyCrossFile_Sanitized_NoFinding asserts that wrapping the user
// input in `Shellwords.escape(...)` before passing it across the
// boundary suppresses the finding.
func TestRubyCrossFile_Sanitized_NoFinding(t *testing.T) {
	cg, paths := rubyScanFixture(t, map[string]string{
		"runner.rb": `class Runner
  def self.run_shell(cmd)
    system(cmd)
  end
end
`,
		"app.rb": `require_relative './runner'
require 'shellwords'

class App
  def handle(params)
    safe = Shellwords.escape(params[:cmd])
    Runner.run_shell(safe)
  end
end
`,
	})
	primeRubySigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) != 0 {
		t.Errorf("sanitized input should not produce a COMMAND_EXEC finding; got %d: %+v",
			len(cmdFindings), cmdFindings)
	}
}

// TestRubyCrossFile_TaintedReturn_SqlSink covers Path B: a callee
// returns user-controlled data (annotated via TaintedReturns); the
// caller stores the result and forwards it to a SQL sink.
//
// The Ruby extractor doesn't yet flag tainted returns automatically,
// so we plant TaintedReturns directly on the callee — equivalent to
// what a future extractor pass will set when it sees `return params[...]`.
func TestRubyCrossFile_TaintedReturn_SqlSink(t *testing.T) {
	cg, paths := rubyScanFixture(t, map[string]string{
		"input.rb": `class Input
  def self.read(params)
    params[:q]
  end
end
`,
		"app.rb": `require_relative './input'

class App
  def handle(params)
    user_input = Input.read(params)
    User.where("name = '#{user_input}'")
  end
end
`,
	})
	primeRubySigs(t, cg, paths)

	// Plant TaintedReturns on Input.read.
	for _, n := range cg.Nodes {
		if n.FilePath == paths["input.rb"] && strings.HasSuffix(n.Name, "read") {
			n.TaintSig.TaintedReturns = map[int][]taint.SourceCategory{
				0: {taint.SrcUserInput},
			}
		}
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via tainted-return Path B; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestRubyCrossFile_SinatraRoute_AsCallee pins a Sinatra route block
// acting as the caller: the route extracts params[:url] and passes it
// to a helper class method that runs Net::HTTP.get on it.
func TestRubyCrossFile_SinatraRoute_AsCaller(t *testing.T) {
	cg, paths := rubyScanFixture(t, map[string]string{
		"fetcher.rb": `require 'net/http'
require 'uri'

class Fetcher
  def self.fetch(url)
    Net::HTTP.get(URI(url))
  end
end
`,
		"app.rb": `require 'sinatra/base'
require_relative './fetcher'

class App < Sinatra::Base
  get "/fetch" do
    Fetcher.fetch(params[:url])
  end
end
`,
	})
	primeRubySigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	ssrfFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-URL_FETCH")
	if len(ssrfFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-URL_FETCH from a Sinatra route caller; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestRubyCrossFile_ModuleMethod_Extraction pins module-method form: a
// helper declared as `module Foo; def self.bar ...` is reached via
// `Foo.bar(...)` from the caller.
func TestRubyCrossFile_ModuleMethod_Extraction(t *testing.T) {
	cg, paths := rubyScanFixture(t, map[string]string{
		"shell.rb": `module Shell
  def self.exec_cmd(cmd)
    \` + "`" + `\#{cmd}` + "`" + `
  end
end
`,
		"app.rb": `require_relative './shell'

class App
  def handle(params)
    Shell.exec_cmd(params[:cmd])
  end
end
`,
	})
	primeRubySigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Logf("note: tree-sitter Ruby parses backtick-exec; expected COMMAND_EXEC, got %d findings: %v",
			len(findings), findingRuleIDs(findings))
		// Sink may be SnkCommand variant — accept any cmdi-flavoured CWE-78.
		hasCmd := false
		for _, f := range findings {
			if strings.Contains(f.CWEID, "78") {
				hasCmd = true
				break
			}
		}
		if !hasCmd {
			t.Errorf("expected a CWE-78 (command injection) finding from Shell.exec_cmd path; got %v", findingRuleIDs(findings))
		}
	}
}
