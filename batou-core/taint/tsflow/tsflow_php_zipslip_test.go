package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP — archive-extraction sinks (Zip Slip / Tar Slip, CWE-22).
//
// Extracting an archive into a user-controlled destination directory writes
// files to an attacker-chosen path (path traversal / arbitrary write). PHP
// exposes this via ZipArchive::extractTo() and Phar/PharData::extractTo(),
// whose first argument is the destination directory. This is the same flaw
// class already modeled for Ruby (rubyzip), Python (zipfile/tarfile) and
// JavaScript (adm-zip / node-tar) — PHP was the only top-priority language
// missing it.
// =========================================================================

func TestPHP_ZipArchive_ExtractTo_PathTraversal(t *testing.T) {
	code := `<?php
function unpackUpload() {
    $dir = $_GET['dir'];
    $zip = new ZipArchive();
    $zip->open('/tmp/upload.zip');
    $zip->extractTo($dir);
}
?>`
	flows := Analyze(code, "/app/src/unpack.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow for $_GET -> $zip->extractTo()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_PharData_ExtractTo_TarSlip(t *testing.T) {
	code := `<?php
function unpackTar() {
    $target = $_POST['target'];
    $phar = new PharData('/tmp/upload.tar');
    $phar->extractTo($target);
}
?>`
	flows := Analyze(code, "/app/src/tar.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected tar-slip flow for $_POST -> $phar->extractTo()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phar_ExtractTo_PathTraversal(t *testing.T) {
	code := `<?php
function unpackPhar() {
    $dest = $_REQUEST['dest'];
    $phar = new Phar('/tmp/app.phar');
    $phar->extractTo($dest);
}
?>`
	flows := Analyze(code, "/app/src/phar.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow for $_REQUEST -> $phar->extractTo()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Negative control: a hardcoded, constant destination directory must NOT
// produce a path-traversal flow (no tainted input reaches extractTo()).
func TestPHP_ZipArchive_ExtractTo_ConstantDest_NoFlow(t *testing.T) {
	code := `<?php
function unpackFixed() {
    $zip = new ZipArchive();
    $zip->open('/tmp/upload.zip');
    $zip->extractTo('/var/app/extracted');
}
?>`
	flows := Analyze(code, "/app/src/fixed.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("did not expect a flow for a constant extractTo() destination")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
