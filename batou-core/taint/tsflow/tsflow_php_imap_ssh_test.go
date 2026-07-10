package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP IMAP injection tests — CVE-2018-19518 class
// imap_open / imap_createmailbox / imap_renamemailbox parse
// {host:port/options}folder; tainted input enables option-string injection
// (and rsh-helper RCE on PHP < 7.3 with imap.enable_insecure_rsh).
// imap_mail() shares mail()'s SMTP/sendmail header-injection class.
// =========================================================================

func TestPHP_IMAP_ImapOpen_TaintedMailbox(t *testing.T) {
	code := `<?php
function handler() {
    $folder = $_GET["folder"];
    $stream = imap_open($folder, "user", "pass");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand for $_GET -> imap_open mailbox")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_IMAP_ImapMail_TaintedHeaders(t *testing.T) {
	code := `<?php
function handler() {
    $headers = $_POST["extra_headers"];
    imap_mail("admin@example.com", "Subject", "Body", $headers);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected SnkHeader for $_POST -> imap_mail additional_headers")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_IMAP_CreateMailbox_TaintedName(t *testing.T) {
	code := `<?php
function handler($stream) {
    $mailbox = $_GET["new_folder"];
    imap_createmailbox($stream, $mailbox);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand for $_GET -> imap_createmailbox")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_IMAP_RenameMailbox_TaintedName(t *testing.T) {
	code := `<?php
function handler($stream) {
    $newName = $_REQUEST["target"];
    imap_renamemailbox($stream, "{imap.example.com}OLD", $newName);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand for $_REQUEST -> imap_renamemailbox new_name")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative: hardcoded mailbox literal — must NOT fire.
func TestPHP_IMAP_ImapOpen_HardcodedSafe(t *testing.T) {
	code := `<?php
function handler() {
    $stream = imap_open("{imap.example.com:143}INBOX", "user", "pass");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("hardcoded mailbox must not fire SnkCommand; got flow from %s", f.Source.Category)
		}
	}
}

// =========================================================================
// PHP SSH2 (ext/ssh2) tests — remote command injection, SCP path traversal,
// SSH SSRF/pivot via ssh2_connect.
// =========================================================================

func TestPHP_SSH2_Exec_TaintedCommand(t *testing.T) {
	code := `<?php
function handler($session) {
    $cmd = $_GET["cmd"];
    $stream = ssh2_exec($session, $cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand for $_GET -> ssh2_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSH2_Connect_TaintedHost(t *testing.T) {
	code := `<?php
function handler() {
    $host = $_GET["host"];
    $session = ssh2_connect($host, 22);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch for $_GET -> ssh2_connect host")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSH2_Shell_TaintedTermType(t *testing.T) {
	code := `<?php
function handler($session) {
    $term = $_POST["term"];
    $shell = ssh2_shell($session, $term);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand for $_POST -> ssh2_shell term_type")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSH2_ScpSend_TaintedRemotePath(t *testing.T) {
	code := `<?php
function handler($session) {
    $remote = $_GET["dest"];
    ssh2_scp_send($session, "/tmp/local.txt", $remote, 0644);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite for $_GET -> ssh2_scp_send remote_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSH2_ScpRecv_TaintedRemotePath(t *testing.T) {
	code := `<?php
function handler($session) {
    $remote = $_GET["src"];
    ssh2_scp_recv($session, $remote, "/tmp/local.txt");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead for $_GET -> ssh2_scp_recv remote_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative: hardcoded constants in ssh2_exec — must NOT fire.
func TestPHP_SSH2_Exec_HardcodedSafe(t *testing.T) {
	code := `<?php
function handler($session) {
    ssh2_exec($session, "/usr/bin/uptime");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("hardcoded ssh2_exec command must not fire SnkCommand; got flow from %s", f.Source.Category)
		}
	}
}

// Negative: escapeshellarg-sanitized command must not flow through.
func TestPHP_SSH2_Exec_Escaped(t *testing.T) {
	code := `<?php
function handler($session) {
    $cmd = escapeshellarg($_GET["cmd"]);
    ssh2_exec($session, "/bin/echo " . $cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Sink.ID == "php.ssh2.exec" {
			t.Errorf("escapeshellarg-sanitized argument must not reach ssh2_exec sink; got flow from %s", f.Source.Category)
		}
	}
}
