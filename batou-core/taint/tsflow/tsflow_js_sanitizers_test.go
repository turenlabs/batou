package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- SnkFileRead sanitizer tests (path traversal prevention) ---

// path.normalize() alone is NOT a sanitizer: normalize("../../etc/passwd")
// is still "../../etc/passwd" — it only collapses redundant segments
// lexically and does not reject escapes. The taint flow must survive.
// (This test previously asserted the opposite, which was unsound — see the
// filepath.Clean note in go_sanitizers.go and the os.path.normpath note in
// python_sanitizers.go; only canonicalize + containment is a defence.)
func TestJS_FileRead_PathNormalize_NotASanitizer(t *testing.T) {
	code := `
const fs = require('fs');
const path = require('path');

function handler(req, res) {
    const userPath = req.query.file;
    const normalized = path.normalize(userPath);
    const data = fs.readFileSync(normalized, 'utf8');
    res.send(data);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Source.Category == taint.SrcUserInput {
			found = true
		}
	}
	if !found {
		t.Error("path.normalize alone must NOT neutralize FileRead taint — expected the traversal flow to still fire")
	}
}

// path.resolve() alone is NOT a sanitizer: resolve("../../etc/passwd")
// returns a real absolute path OUTSIDE the safe base. The taint flow must
// survive. (Previously asserted the opposite — unsound; see the notes cited
// in TestJS_FileRead_PathNormalize_NotASanitizer.)
func TestJS_FileRead_PathResolve_NotASanitizer(t *testing.T) {
	code := `
const fs = require('fs');
const path = require('path');

function handler(req, res) {
    const userPath = req.query.file;
    const resolved = path.resolve(userPath);
    const data = fs.readFileSync(resolved, 'utf8');
    res.send(data);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Source.Category == taint.SrcUserInput {
			found = true
		}
	}
	if !found {
		t.Error("path.resolve alone must NOT neutralize FileRead taint — expected the traversal flow to still fire")
	}
}

func TestJS_FileRead_Sanitized_ExpressStatic(t *testing.T) {
	code := `
const express = require('express');
const app = express();

function setup(uploadDir) {
    app.use('/files', express.static(uploadDir));
}
`
	flows := Analyze(code, "/app/server.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("express.static should neutralize FileRead taint (serves files safely)")
		}
	}
}

func TestJS_FileRead_Sanitized_ServeStatic(t *testing.T) {
	code := `
const serveStatic = require('serve-static');
const http = require('http');

function createServer(publicDir) {
    const serve = serveStatic(publicDir);
    return http.createServer(function(req, res) {
        serve(req, res, function() { res.end('Not found'); });
    });
}
`
	flows := Analyze(code, "/app/server.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("serveStatic should neutralize FileRead taint (serves files safely)")
		}
	}
}

func TestJS_FileRead_Sanitized_SendFileRoot(t *testing.T) {
	code := `
const express = require('express');
const app = express();

app.get('/download', function(req, res) {
    const filename = req.query.file;
    res.sendFile(filename, { root: __dirname + '/public' });
});
`
	flows := Analyze(code, "/app/server.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Source.Category == taint.SrcUserInput {
			t.Error("sendFile with root option should neutralize FileRead taint")
		}
	}
}

// Verify that unsanitized path still produces a finding
func TestJS_FileRead_Unsanitized_StillDetected(t *testing.T) {
	code := `
const fs = require('fs');

function handler(req, res) {
    const userPath = req.query.file;
    const data = fs.readFileSync(userPath, 'utf8');
    res.send(data);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for unsanitized req.query -> fs.readFileSync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_FileRead_Sanitized_RegexReplace(t *testing.T) {
	code := `
const fs = require('fs');

function handler(req, res) {
    const userPath = req.query.file;
    const safe = userPath.replace(/[^a-zA-Z0-9._-]/g, '');
    const data = fs.readFileSync(safe, 'utf8');
    res.send(data);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Source.Category == taint.SrcUserInput && f.Sink.MethodName == "readFileSync" {
			t.Error("regex replace stripping dangerous chars should neutralize FileRead taint")
		}
	}
}
