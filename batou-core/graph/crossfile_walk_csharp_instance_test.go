// Cross-file C# INSTANCE-METHOD walker tests.
//
// These tests exercise the full C# cross-file pipeline end-to-end:
//   1. buildCSharpNodes registers FuncNodes for each .cs file (and, with the
//      receiver-type fix, rewrites an instance-call receiver to its concrete
//      class so `repo.RunQuery(...)` becomes a `Repo.RunQuery` RawCall).
//   2. ResolveCrossFileEdges (namespace + `using`) wires caller -> callee
//      edges between the files.
//   3. WalkCrossFileTaintFlows dispatches to AnalyzeCallerImpactCSharp for
//      C# callees and emits BATOU-INTERPROC-<CAT> findings.
//
// Before the fix, an INSTANCE-method call across files
// (`var repo = new Repo(); repo.RunQuery(tainted)`) produced ZERO cross-file
// pairs: the resolver received the callee text `repo.RunQuery`, split it into
// receiver class `repo` (the lowercase LOCAL VARIABLE name) and method
// `RunQuery`, looked for a class named `repo` in the caller's namespace, found
// none, and returned "no opinion". Only the STATIC form `Repo.RunQuery(...)`
// resolved. The fix recovers the receiver's declared type at build time
// (`var repo = new Repo()` / `Repo repo = ...` / a `private Repo _repo;`
// field) and rewrites the receiver to the concrete class, so the instance form
// resolves to exactly the same cross-file edge the static form already did.
//
// LOAD-BEARING: reverting walkCSharpBodyForCalls to NOT rewrite the receiver
// (i.e. dropping rewriteCSharpReceiverType / collectCSharpLocalVarTypes /
// collectCSharpFieldTypes) makes TestCSharpCrossFile_InstanceMethod_SqlSink
// and ..._FieldReceiver fail (the cross-file CWE-89 disappears), while the
// precision test keeps passing.

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// csharpScanFixture builds a tiny C# project: writes the files, builds C#
// FuncNodes for each .cs file, resolves cross-file edges, and returns the
// populated CallGraph plus the absolute path of each file by relative name.
func csharpScanFixture(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	if err := writeFiles(t, root, files); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	cg := NewCallGraph(root, "test")
	paths := map[string]string{}
	contents := map[string][]byte{}
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		paths[rel] = abs
		if !strings.HasSuffix(rel, ".cs") {
			continue
		}
		buildCSharpNodes(cg, abs, content, nil)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// TestCSharpCrossFile_InstanceMethod_SqlSink is the primary load-bearing
// test: a controller reads Request.Query into a local, constructs a Repo via
// `var repo = new Repo()`, and calls the INSTANCE method `repo.RunQuery(id)`
// — which is defined in another file and concatenates the value into
// ExecuteSqlRaw. Expected: BATOU-INTERPROC-SQL_QUERY with a sink step in the
// repo file. This produces ZERO findings without the receiver-type fix.
func TestCSharpCrossFile_InstanceMethod_SqlSink(t *testing.T) {
	cg, paths := csharpScanFixture(t, map[string]string{
		"Repo.cs": `using Microsoft.EntityFrameworkCore;
namespace App {
  public class Repo {
    private DbContext _db;
    public void RunQuery(string id) {
      _db.Database.ExecuteSqlRaw("SELECT * FROM t WHERE id = " + id);
    }
  }
}
`,
		"Controller.cs": `using System;
using Microsoft.AspNetCore.Mvc;
namespace App {
  public class HomeController : Controller {
    public void Index() {
      var id = Request.Query["id"];
      var repo = new Repo();
      repo.RunQuery(id);
    }
  }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via instance call repo.RunQuery(); got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	assertSinkInFile(t, sqlFindings, paths["Repo.cs"])
	assertAllLanguage(t, findings, rules.LangCSharp)
}

// TestCSharpCrossFile_InstanceMethod_FieldReceiver covers the dominant
// real-world ASP.NET shape: the receiver is a CLASS FIELD whose declared type
// is the in-project class (`private Repo _repo = new Repo();`), and the
// instance method is called through the field (`_repo.RunQuery(id)`).
func TestCSharpCrossFile_InstanceMethod_FieldReceiver(t *testing.T) {
	cg, paths := csharpScanFixture(t, map[string]string{
		"Repo.cs": `using Microsoft.EntityFrameworkCore;
namespace App {
  public class Repo {
    private DbContext _db;
    public void RunQuery(string id) {
      _db.Database.ExecuteSqlRaw("SELECT * FROM t WHERE id = " + id);
    }
  }
}
`,
		"Controller.cs": `using System;
using Microsoft.AspNetCore.Mvc;
namespace App {
  public class HomeController : Controller {
    private Repo _repo = new Repo();
    public void Index() {
      var id = Request.Query["id"];
      _repo.RunQuery(id);
    }
  }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via field call _repo.RunQuery(); got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	assertSinkInFile(t, sqlFindings, paths["Repo.cs"])
	assertAllLanguage(t, findings, rules.LangCSharp)
}

// TestCSharpCrossFile_InstanceMethod_NoOverLink is the precision guard: the
// receiver is bound to SafeRepo (a parameterized FromSqlInterpolated query,
// which the C# walker recognises as safe), while a DIFFERENT class VulnRepo
// in the project has an IDENTICALLY-NAMED RunQuery method that DOES splice the
// value into ExecuteSqlRaw. The receiver-type rewrite must resolve to
// App.SafeRepo.RunQuery (not bare-suffix match VulnRepo), so no finding may
// reference VulnRepo. A bare-suffix resolver would mislink and report the
// VulnRepo sink — a false positive.
func TestCSharpCrossFile_InstanceMethod_NoOverLink(t *testing.T) {
	cg, _ := csharpScanFixture(t, map[string]string{
		"SafeRepo.cs": `using Microsoft.EntityFrameworkCore;
namespace App {
  public class SafeRepo {
    private DbContext _db;
    public void RunQuery(string id) {
      _db.Set<int>().FromSqlInterpolated($"SELECT * FROM t WHERE id = {id}");
    }
  }
}
`,
		"VulnRepo.cs": `using Microsoft.EntityFrameworkCore;
namespace App {
  public class VulnRepo {
    private DbContext _db;
    public void RunQuery(string id) {
      _db.Database.ExecuteSqlRaw("SELECT * FROM t WHERE id = " + id);
    }
  }
}
`,
		"Controller.cs": `using System;
using Microsoft.AspNetCore.Mvc;
namespace App {
  public class HomeController : Controller {
    public void Index() {
      var id = Request.Query["id"];
      var repo = new SafeRepo();
      repo.RunQuery(id);
    }
  }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	for _, f := range findings {
		for _, st := range f.TaintPath {
			if strings.Contains(st.File, "VulnRepo.cs") {
				t.Fatalf("receiver bound to SafeRepo mislinked to VulnRepo (over-link / bare-suffix bug); finding=%+v", f)
			}
		}
		if strings.Contains(f.MatchedText, "VulnRepo") {
			t.Fatalf("finding mis-attributed to VulnRepo: %q", f.MatchedText)
		}
	}
}

// assertSinkInFile fails unless at least one finding has a sink taint step in
// wantFile.
func assertSinkInFile(t *testing.T, findings []rules.Finding, wantFile string) {
	t.Helper()
	for _, f := range findings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == wantFile {
				return
			}
		}
	}
	t.Errorf("no finding had a sink step in %s; findings=%+v", wantFile, findings)
}

// assertAllLanguage fails if any finding carries a non-empty Language other
// than want (guards against routing a C# callee through the Go walker).
func assertAllLanguage(t *testing.T, findings []rules.Finding, want rules.Language) {
	t.Helper()
	for _, f := range findings {
		if f.Language != "" && f.Language != want {
			t.Errorf("finding has wrong Language %q (want %q): %+v", f.Language, want, f)
		}
	}
}
