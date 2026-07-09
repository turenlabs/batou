package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// phpseclib3 (phpseclib\Net\SSH2 / phpseclib\Net\SFTP) — the dominant
// pure-PHP SSH/SFTP library. SSH2 connecting to a tainted host = SSH SSRF;
// SFTP path arguments reaching remote filesystem ops = path traversal.
// =========================================================================

// hasPHPSinkID reports whether any flow's sink has the given catalog ID.
func hasPHPSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}

func TestPHP_Phpseclib_SSH2_Connect_TaintedHost(t *testing.T) {
	code := `<?php
use phpseclib3\Net\SSH2;

function handler() {
    $host = $_GET["host"];
    $ssh = new SSH2($host);
    $ssh->login("user", "pass");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.ssh2.connect") {
		t.Error("expected php.phpseclib.ssh2.connect (SnkURLFetch) for $_GET -> new SSH2($host)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Get_TaintedRemotePath(t *testing.T) {
	code := `<?php
use phpseclib3\Net\SFTP;

function handler() {
    $path = $_GET["file"];
    $sftp = new SFTP("ssh.example.com");
    $sftp->login("user", "pass");
    return $sftp->get($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.get") {
		t.Error("expected php.phpseclib.sftp.get (SnkFileRead) for $_GET -> $sftp->get($path)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Put_TaintedRemotePath(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $remote = $_POST["dest"];
    $sftp->put($remote, "payload");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.put") {
		t.Error("expected php.phpseclib.sftp.put (SnkFileWrite) for $_POST -> $sftp->put($remote, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Delete_TaintedPath(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $target = $_REQUEST["path"];
    $sftp->delete($target);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.delete") {
		t.Error("expected php.phpseclib.sftp.delete (SnkFileWrite) for $_REQUEST -> $sftp->delete($target)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Rmdir_TaintedPath(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $dir = $_GET["dir"];
    $sftp->rmdir($dir);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.rmdir") {
		t.Error("expected php.phpseclib.sftp.rmdir (SnkFileWrite) for $_GET -> $sftp->rmdir($dir)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Chmod_TaintedFilename(t *testing.T) {
	// chmod($mode, $filename) — the tainted value is at argument index 1.
	code := `<?php
function handler($sftp) {
    $file = $_GET["f"];
    $sftp->chmod(0644, $file);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.chmod") {
		t.Error("expected php.phpseclib.sftp.chmod (SnkFileWrite) for $_GET -> $sftp->chmod(0644, $file)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Chown_TaintedFilename(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $file = $_GET["f"];
    $sftp->chown($file, 1000);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.chown") {
		t.Error("expected php.phpseclib.sftp.chown (SnkFileWrite) for $_GET -> $sftp->chown($file, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Chgrp_TaintedFilename(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $file = $_GET["f"];
    $sftp->chgrp($file, 1000);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.chgrp") {
		t.Error("expected php.phpseclib.sftp.chgrp (SnkFileWrite) for $_GET -> $sftp->chgrp($file, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Touch_TaintedFilename(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $file = $_GET["f"];
    $sftp->touch($file);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.touch") {
		t.Error("expected php.phpseclib.sftp.touch (SnkFileWrite) for $_GET -> $sftp->touch($file)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Truncate_TaintedFilename(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $file = $_GET["f"];
    $sftp->truncate($file, 0);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.truncate") {
		t.Error("expected php.phpseclib.sftp.truncate (SnkFileWrite) for $_GET -> $sftp->truncate($file, 0)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Nlist_TaintedDir(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $dir = $_GET["dir"];
    return $sftp->nlist($dir);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.nlist") {
		t.Error("expected php.phpseclib.sftp.nlist (SnkFileRead) for $_GET -> $sftp->nlist($dir)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Phpseclib_SFTP_Rawlist_TaintedDir(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $dir = $_GET["dir"];
    return $sftp->rawlist($dir);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasPHPSinkID(flows, "php.phpseclib.sftp.rawlist") {
		t.Error("expected php.phpseclib.sftp.rawlist (SnkFileRead) for $_GET -> $sftp->rawlist($dir)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Negative: hardcoded constant remote paths — must NOT produce phpseclib flows.
func TestPHP_Phpseclib_SFTP_HardcodedSafe(t *testing.T) {
	code := `<?php
function handler($sftp) {
    $sftp->get("/var/exports/report.csv");
    $sftp->put("/var/incoming/data.bin", "payload");
    $sftp->delete("/tmp/stale.lock");
    $sftp->nlist("/var/exports");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		switch f.Sink.ID {
		case "php.phpseclib.sftp.get", "php.phpseclib.sftp.put",
			"php.phpseclib.sftp.delete", "php.phpseclib.sftp.nlist":
			t.Errorf("hardcoded path must not fire %s; got flow from %s", f.Sink.ID, f.Source.Category)
		}
	}
}

// Registration sanity check: every new phpseclib sink ID must be in the PHP catalog.
func TestPHP_Phpseclib_SinkRegistration(t *testing.T) {
	want := []string{
		"php.phpseclib.ssh2.connect",
		"php.phpseclib.sftp.get",
		"php.phpseclib.sftp.put",
		"php.phpseclib.sftp.delete",
		"php.phpseclib.sftp.rmdir",
		"php.phpseclib.sftp.chmod",
		"php.phpseclib.sftp.chown",
		"php.phpseclib.sftp.chgrp",
		"php.phpseclib.sftp.touch",
		"php.phpseclib.sftp.truncate",
		"php.phpseclib.sftp.nlist",
		"php.phpseclib.sftp.rawlist",
	}
	cat := taint.GetCatalog(rules.LangPHP)
	if cat == nil {
		t.Fatal("no PHP catalog registered")
	}
	have := map[string]bool{}
	for _, s := range cat.Sinks() {
		have[s.ID] = true
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("missing sink registration: %s", id)
		}
	}
}
