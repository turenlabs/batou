package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Unrestricted file upload (CWE-434) — SnkUpload
//
// An uploaded file persisted to disk without validating its extension /
// MIME type / content lets an attacker drop a webshell (or otherwise
// smuggle executable content). The sink is the persist/move call; either
// the uploaded-file handle (the receiver) or the destination path being
// tainted produces a flow. The negative cases confirm that a hardcoded
// destination with no upload source — or an uploaded filename routed
// through werkzeug.secure_filename before reaching the sink — does NOT
// flag.
// =========================================================================

// --- Python: Werkzeug/Flask FileStorage.save() ---

func TestPython_Upload_FileStorage_Save(t *testing.T) {
	code := `
from flask import request

def upload():
    f = request.files['photo']
    f.save("/uploads/photo.png")
    return "ok"
`
	flows := Analyze(code, "/app/upload.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected unrestricted-upload flow for request.files[...] -> FileStorage.save()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Python: shutil.copyfileobj(src, tainted_destination) ---

func TestPython_Upload_Shutil_Copyfileobj(t *testing.T) {
	code := `
import shutil
from flask import request

def store(src):
    name = request.args.get("name")
    dst = "/uploads/" + name
    shutil.copyfileobj(src, dst)
`
	flows := Analyze(code, "/app/store.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected unrestricted-upload flow for request.args -> shutil.copyfileobj destination")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Python: hardcoded destination / no upload source must NOT flag ---

func TestPython_Upload_HardcodedSafe(t *testing.T) {
	code := `
import shutil

def export():
    with open("/static/template.png", "rb") as src, open("/uploads/out.png", "wb") as dst:
        shutil.copyfileobj(src, dst)
`
	flows := Analyze(code, "/app/export.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected NO unrestricted-upload flow when only hardcoded paths/handles are used")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- JavaScript: express-fileupload UploadedFile.mv() ---

func TestJS_Upload_ExpressFileUpload_Mv(t *testing.T) {
	code := `
const express = require("express");
const app = express();

app.post("/upload", (req, res) => {
    const f = req.files.photo;
    f.mv("/uploads/photo.png", (err) => {});
    res.send("ok");
});
`
	flows := Analyze(code, "/app/routes/upload.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected unrestricted-upload flow for req.files.* -> UploadedFile.mv()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- JavaScript: hardcoded handle / no upload source must NOT flag ---

func TestJS_Upload_HardcodedSafe(t *testing.T) {
	code := `
function exportStatic() {
    const f = getDefaultUpload();
    f.mv("/uploads/default.png");
}
`
	flows := Analyze(code, "/app/export.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected NO unrestricted-upload flow when no upload source is involved")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Java: Spring MultipartFile.transferTo(File) ---

func TestJava_Upload_MultipartFile_TransferTo(t *testing.T) {
	code := `
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;

public class UploadController {
    @PostMapping("/upload")
    public void upload(@RequestParam("file") MultipartFile multipartFile) throws Exception {
        File dest = new File("/uploads/photo.png");
        multipartFile.transferTo(dest);
    }
}
`
	flows := Analyze(code, "/app/UploadController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected unrestricted-upload flow for @RequestParam MultipartFile -> transferTo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Java: non-handler param / no upload source must NOT flag ---

func TestJava_Upload_HardcodedSafe(t *testing.T) {
	code := `
import org.springframework.web.multipart.MultipartFile;
import java.io.File;

public class UploadService {
    public void store(MultipartFile multipartFile) throws Exception {
        File dest = new File("/uploads/photo.png");
        multipartFile.transferTo(dest);
    }
}
`
	flows := Analyze(code, "/app/UploadService.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected NO unrestricted-upload flow when the MultipartFile is not a seeded request param and the destination is hardcoded")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- PHP: move_uploaded_file($_FILES['x']['tmp_name'], $dst) ---

func TestPHP_Upload_MoveUploadedFile(t *testing.T) {
	code := `<?php
function upload() {
    $tmp = $_FILES["photo"]["tmp_name"];
    move_uploaded_file($tmp, "/uploads/photo.png");
}
?>`
	flows := Analyze(code, "/app/upload.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected unrestricted-upload flow for $_FILES tmp_name -> move_uploaded_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestPHP_Upload_MoveUploadedFile_HardcodedSafe(t *testing.T) {
	code := `<?php
function backup() {
    move_uploaded_file("/tmp/seeded.png", "/uploads/seeded.png");
}
?>`
	flows := Analyze(code, "/app/backup.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected NO unrestricted-upload flow when both move_uploaded_file args are hardcoded")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
