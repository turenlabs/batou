package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// External control of file name or path (CWE-73) — path-construction file
// sinks (rename / move / copy / hard-link).
//
// Untrusted data used as the source/destination path of a file rename, move,
// copy, or link operation. Distinct from classic path traversal (CWE-22):
// the attacker controls the *file name* an operation acts on, so even a
// non-"../" value can clobber, exfiltrate, or expose unrelated files. These
// flow through the existing SnkFileWrite category but report CWE-73; the
// same path-traversal sanitizers (os.path.basename, secure_filename,
// path.basename, FilenameUtils.getName) neutralize them.
// =========================================================================

// hasFileNameControlFlow reports whether any flow is a SnkFileWrite/SnkFileRead
// sink stamped with CWE-73.
func hasFileNameControlFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if (f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead) && f.Sink.CWEID == "CWE-73" {
			return true
		}
	}
	return false
}

// --- Python: os.rename(src, tainted_dst) ---

func TestPython_FileNameControl_OsRename(t *testing.T) {
	code := `
import os
from flask import request

def move_upload():
    dest = request.args.get("name")
    os.rename("/tmp/upload.bin", dest)
`
	flows := Analyze(code, "/app/files.py", rules.LangPython)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for request.args.get -> os.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestPython_FileNameControl_ShutilMove(t *testing.T) {
	code := `
import shutil
from flask import request

def archive():
    dest = request.form["target"]
    shutil.move("/tmp/data.csv", dest)
`
	flows := Analyze(code, "/app/files.py", rules.LangPython)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for request.form -> shutil.move")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Python: sanitized with os.path.basename — must NOT flag ---

func TestPython_FileNameControl_OsRename_Sanitized(t *testing.T) {
	code := `
import os
from flask import request

def move_upload():
    raw = request.args.get("name")
    dest = os.path.basename(raw)
    os.rename("/tmp/upload.bin", dest)
`
	flows := Analyze(code, "/app/files.py", rules.LangPython)
	if hasFileNameControlFlow(flows) {
		t.Error("expected NO CWE-73 flow when destination is sanitized via os.path.basename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Python: hardcoded literal — must NOT flag ---

func TestPython_FileNameControl_OsRename_Hardcoded(t *testing.T) {
	code := `
import os

def move_upload():
    os.rename("/tmp/upload.bin", "/var/data/final.bin")
`
	flows := Analyze(code, "/app/files.py", rules.LangPython)
	if hasFileNameControlFlow(flows) {
		t.Error("expected NO CWE-73 flow when both paths are hardcoded literals")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- JavaScript: fs.rename(old, tainted_new) ---

func TestJS_FileNameControl_FsRename(t *testing.T) {
	code := `
const fs = require("fs");

app.post("/move", (req, res) => {
    const dest = req.query.name;
    fs.rename("/tmp/upload.bin", dest, (err) => {});
});
`
	flows := Analyze(code, "/app/routes/files.js", rules.LangJavaScript)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for req.query -> fs.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestJS_FileNameControl_FsCopyFile(t *testing.T) {
	code := `
const fs = require("fs");

app.post("/copy", (req, res) => {
    const dest = req.body.target;
    fs.copyFileSync("/tmp/source.bin", dest);
});
`
	flows := Analyze(code, "/app/routes/files.js", rules.LangJavaScript)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for req.body -> fs.copyFileSync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- JavaScript: sanitized with path.basename — must NOT flag ---

func TestJS_FileNameControl_FsRename_Sanitized(t *testing.T) {
	code := `
const fs = require("fs");
const path = require("path");

app.post("/move", (req, res) => {
    const raw = req.query.name;
    const dest = path.basename(raw);
    fs.rename("/tmp/upload.bin", dest, (err) => {});
});
`
	flows := Analyze(code, "/app/routes/files.js", rules.LangJavaScript)
	if hasFileNameControlFlow(flows) {
		t.Error("expected NO CWE-73 flow when destination is sanitized via path.basename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Java: Files.move(src, Paths.get(tainted)) ---

func TestJava_FileNameControl_FilesMove(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        Files.move(Paths.get("/tmp/upload.bin"), Paths.get(name));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for getParameter -> Files.move")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestJava_FileNameControl_FileRenameTo(t *testing.T) {
	// The dangerous arg of renameTo is the destination File; pass the
	// tainted path directly so the flow reaches java.file.renameto rather
	// than first being intercepted by the new File(...) path sink.
	code := `
import javax.servlet.http.*;
import java.io.File;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response, File dest) throws Exception {
        String name = request.getParameter("name");
        File src = new File("/tmp/upload.bin");
        src.renameTo(name);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for getParameter -> File.renameTo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Java: sanitized with FilenameUtils.getName — must NOT flag ---

func TestJava_FileNameControl_FilesMove_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.commons.io.FilenameUtils;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String raw = request.getParameter("name");
        String name = FilenameUtils.getName(raw);
        Files.move(Paths.get("/tmp/upload.bin"), Paths.get(name));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasFileNameControlFlow(flows) {
		t.Error("expected NO CWE-73 flow when destination is sanitized via FilenameUtils.getName")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- PHP: rename($old, $tainted) ---

func TestPHP_FileNameControl_Rename(t *testing.T) {
	code := `<?php
function move_upload() {
    $dest = $_GET["name"];
    rename("/tmp/upload.bin", $dest);
}
?>`
	flows := Analyze(code, "/app/files.php", rules.LangPHP)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for $_GET -> rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Ruby: File.rename(old, tainted) ---

func TestRuby_FileNameControl_FileRename(t *testing.T) {
	code := `
def move_upload(params)
  dest = params[:name]
  File.rename("/tmp/upload.bin", dest)
end
`
	flows := Analyze(code, "/app/files.rb", rules.LangRuby)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for params -> File.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestRuby_FileNameControl_FileUtilsMv(t *testing.T) {
	code := `
def archive(params)
  dest = params[:target]
  FileUtils.mv("/tmp/data.csv", dest)
end
`
	flows := Analyze(code, "/app/files.rb", rules.LangRuby)
	if !hasFileNameControlFlow(flows) {
		t.Error("expected CWE-73 file-name-control flow for params -> FileUtils.mv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}
