package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# CWE-22 path-traversal confinement sanitizers
//
// Two shapes of the standard .NET path-confinement guard, both of which must
// suppress the file_read flow into File.OpenRead(path):
//
//  1. Inline:  if (!Path.GetFullPath(p).StartsWith(Path.GetFullPath(base))) throw
//  2. Helper:  EnsurePathWithinBaseDir(path);   // wraps shape (1), throws on escape
//
// Shape (2) is the bitwarden LocalOrganizationReportStorageService pattern:
// the guard is a void method called on its own statement line before the sink,
// leaving the same `path` variable to flow into File.OpenRead.
// =========================================================================

// Helper-method shape — bitwarden's EnsurePathWithinBaseDir(path) guard.
func TestCSharp_PathConfinement_HelperGuard_Suppressed(t *testing.T) {
	code := `
using System;
using System.IO;

public class Svc {
    private readonly string _baseDirPath;

    public Stream GetReadStream(Report report, ReportFile fileData) {
        var path = Path.Combine(_baseDirPath, RelativePath(report, fileData.Id, fileData.FileName));
        EnsurePathWithinBaseDir(path);
        return File.OpenRead(path);
    }

    private void EnsurePathWithinBaseDir(string path) {
        var fullPath = Path.GetFullPath(path);
        var fullBaseDir = Path.GetFullPath(_baseDirPath + Path.DirectorySeparatorChar);
        if (!fullPath.StartsWith(fullBaseDir, StringComparison.OrdinalIgnoreCase)) {
            throw new Exception("path escapes base directory");
        }
    }
}
`
	flows := Analyze(code, "/app/Svc.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Sink.MethodName == "File.OpenRead" {
			t.Errorf("expected File.OpenRead(path) file_read flow to be suppressed by the "+
				"EnsurePathWithinBaseDir confinement guard, got conf %.2f", f.Confidence)
		}
	}
}

// Inline shape — Path.GetFullPath(p).StartsWith(...) directly in scope.
func TestCSharp_PathConfinement_InlineStartsWith_Suppressed(t *testing.T) {
	code := `
using System;
using System.IO;

public class Svc {
    public Stream Read(string userPath, string baseDir) {
        var path = Path.Combine(baseDir, userPath);
        var full = Path.GetFullPath(path);
        if (!Path.GetFullPath(path).StartsWith(Path.GetFullPath(baseDir), StringComparison.Ordinal)) {
            throw new Exception("path escapes base directory");
        }
        return File.OpenRead(full);
    }
}
`
	flows := Analyze(code, "/app/Svc.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Errorf("expected file_read flow to be suppressed by the inline "+
				"Path.GetFullPath().StartsWith() confinement check, got conf %.2f", f.Confidence)
		}
	}
}

// RECALL GUARD: an UNGUARDED file read of a tainted path must still fire. The
// sanitizer is anchored on the confinement-guard call, so removing the guard
// re-exposes the flow (proves the sanitizer is fp-only, not a blanket mute on
// File.OpenRead).
func TestCSharp_PathConfinement_NoGuard_StillFires(t *testing.T) {
	code := `
using System;
using System.IO;

public class Svc {
    private readonly string _baseDirPath;

    public Stream GetReadStream(Report report, ReportFile fileData) {
        var path = Path.Combine(_baseDirPath, RelativePath(report, fileData.Id, fileData.FileName));
        return File.OpenRead(path);
    }
}
`
	flows := Analyze(code, "/app/Svc.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected unguarded File.OpenRead(path) to still produce a file_read flow " +
			"(sanitizer must be confinement-guard-anchored, not a blanket File.OpenRead mute)")
	}
}

// RECALL GUARD: a similarly-named but NON-confinement guard (`EnsureNotNull`)
// must NOT suppress — the @argpattern requires a base/root/dir confinement
// token in the helper name, so an unrelated Ensure* call leaves the flow live.
func TestCSharp_PathConfinement_UnrelatedEnsure_StillFires(t *testing.T) {
	code := `
using System;
using System.IO;

public class Svc {
    private readonly string _baseDirPath;

    public Stream GetReadStream(Report report, ReportFile fileData) {
        var path = Path.Combine(_baseDirPath, RelativePath(report, fileData.Id, fileData.FileName));
        EnsureNotNull(path);
        return File.OpenRead(path);
    }

    private void EnsureNotNull(string path) {
        if (path == null) { throw new Exception("null"); }
    }
}
`
	flows := Analyze(code, "/app/Svc.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected File.OpenRead(path) to still fire when guarded only by an unrelated " +
			"EnsureNotNull (no base/root/dir confinement token in the name)")
	}
}
