// Cross-file MODULE-GLOBAL stored-state taint tests (Task B, Python).
//
// A config module holds only top-level globals (no functions, so NO FuncNode),
// and a sink-bearing reader in a DIFFERENT file imports and uses one of those
// globals. WalkCrossFilePythonGlobals must surface the flow; the import anchor
// keeps unrelated same-named globals from joining, and param/sanitized writes
// (and never-read globals) must produce nothing.

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// pythonGlobalsWalk writes the files, builds Python FuncNodes for the files
// that have functions, resolves cross-file edges (populating FileScopes /
// FileModules), and runs the module-global walk with the full .py file list —
// mirroring the dirscan finalize pass (which passes the on-disk file list).
func pythonGlobalsWalk(t *testing.T, files map[string]string) []rules.Finding {
	t.Helper()
	root := t.TempDir()
	if _, present := files["pyproject.toml"]; !present {
		files["pyproject.toml"] = "[project]\nname = \"proj\"\n"
	}
	if err := writeFiles(t, root, files); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	cg := NewCallGraph(root, "test")
	contents := map[string][]byte{}
	var pyFiles []string
	for rel, content := range files {
		if !strings.HasSuffix(rel, ".py") {
			continue
		}
		abs := filepath.Join(root, rel)
		pyFiles = append(pyFiles, abs)
		buildPythonNodes(cg, abs, content, nil)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return WalkCrossFilePythonGlobals(cg, pyFiles)
}

// hasGlobalFinding reports whether a module-global stored-state finding for the
// given global name exists (tagged stored-state, IsGlobal => "module" join,
// global name in the title).
func hasGlobalFinding(findings []rules.Finding, nameNeedle string) bool {
	for _, f := range findings {
		isStored := false
		for _, tag := range f.Tags {
			if tag == "stored-state" {
				isStored = true
				break
			}
		}
		if isStored && strings.Contains(f.Title, nameNeedle) {
			return true
		}
	}
	return false
}

// TestStoredStateGlobals_Python_Positive: config.py defines API_TARGET from an
// external source at module top level; worker.py imports it and sinks it. The
// producer module has no FuncNode, so this fires only because the producer
// enumeration walks the on-disk file list.
func TestStoredStateGlobals_Python_Positive(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `import os

API_TARGET = os.environ["UPSTREAM"]
`,
		"worker.py": `import os
from config import API_TARGET


def run():
    os.system(API_TARGET)
`,
	})
	if !hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("expected a module-global stored-state finding for API_TARGET, got %d: %+v", len(f), f)
	}
	var found rules.Finding
	for _, fd := range f {
		if strings.Contains(fd.Title, "API_TARGET") {
			found = fd
			break
		}
	}
	if len(found.TaintPath) < 2 {
		t.Fatalf("expected a two-step taint path, got %+v", found.TaintPath)
	}
	src := found.TaintPath[0]
	sink := found.TaintPath[len(found.TaintPath)-1]
	if !strings.HasSuffix(src.File, "config.py") {
		t.Errorf("expected source step in config.py, got %s", src.File)
	}
	if !strings.HasSuffix(sink.File, "worker.py") {
		t.Errorf("expected sink step in worker.py, got %s", sink.File)
	}
	if found.ConfidenceScore != 0.8 {
		t.Errorf("expected confidence 0.8, got %v", found.ConfidenceScore)
	}
}

// TestStoredStateGlobals_Python_QualifiedImport: `import config` then
// `config.API_TARGET` (qualified access) must also join.
func TestStoredStateGlobals_Python_QualifiedImport(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `import os

API_TARGET = os.environ["UPSTREAM"]
`,
		"worker.py": `import os
import config


def run():
    os.system(config.API_TARGET)
`,
	})
	if !hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("expected a module-global finding via qualified import, got %d: %+v", len(f), f)
	}
}

// TestStoredStateGlobals_Python_NotImportedNoFinding: the global IS defined and
// IS read in a sink, but the reader file does NOT import the producer module —
// the import anchor must suppress the join (this is the config-file FP guard).
func TestStoredStateGlobals_Python_NotImportedNoFinding(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `import os

API_TARGET = os.environ["UPSTREAM"]
`,
		"worker.py": `import os


def run():
    os.system(API_TARGET)
`,
	})
	if hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("a reader that does not import the producer module must NOT join, got %+v", f)
	}
}

// TestStoredStateGlobals_Python_ParamWriteNoFinding: the "global" is actually a
// function parameter assignment inside a def (indented), not a module-level
// external source — must NOT be recorded as a producer.
func TestStoredStateGlobals_Python_ParamWriteNoFinding(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `def configure(data):
    API_TARGET = data
    return API_TARGET
`,
		"worker.py": `import os
from config import API_TARGET


def run():
    os.system(API_TARGET)
`,
	})
	if hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("an indented (in-def) assignment must NOT be a module-global producer, got %+v", f)
	}
}

// TestStoredStateGlobals_Python_SanitizedWriteNoFinding: the module-global is
// written from a sanitized source — must NOT be recorded.
func TestStoredStateGlobals_Python_SanitizedWriteNoFinding(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `import os
import shlex

API_TARGET = shlex.quote(os.environ["UPSTREAM"])
`,
		"worker.py": `import os
from config import API_TARGET


def run():
    os.system(API_TARGET)
`,
	})
	if hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("a sanitized module-global write must NOT emit, got %+v", f)
	}
}

// TestStoredStateGlobals_Python_NeverReadNoFinding: the global is a genuine
// external source and IS imported, but the reader never passes it to a sink.
func TestStoredStateGlobals_Python_NeverReadNoFinding(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `import os

API_TARGET = os.environ["UPSTREAM"]
`,
		"worker.py": `from config import API_TARGET


def run():
    return len(API_TARGET)
`,
	})
	if hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("a global that is imported but never sunk must NOT emit, got %+v", f)
	}
}

// TestStoredStateGlobals_Python_ConstantWriteNoFinding: a hardcoded constant
// global (no external source) must NOT be a producer even when imported + sunk.
func TestStoredStateGlobals_Python_ConstantWriteNoFinding(t *testing.T) {
	f := pythonGlobalsWalk(t, map[string]string{
		"config.py": `API_TARGET = "/usr/bin/safe"
`,
		"worker.py": `import os
from config import API_TARGET


def run():
    os.system(API_TARGET)
`,
	})
	if hasGlobalFinding(f, "API_TARGET") {
		t.Fatalf("a hardcoded constant global must NOT emit, got %+v", f)
	}
}
