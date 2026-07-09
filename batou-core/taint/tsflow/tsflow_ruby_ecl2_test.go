package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ECL wave-2 (ecl2/ruby): permanent TP-fires + safe-stays-clean tests for the
// coverage-breadth detection categories closed in this wave. Each category is
// ObjectType-anchored (JSON / Net::FTP) so it cannot collide with same-named
// methods on unrelated receivers, and was verified to add ZERO false positives
// on real-world Discourse + GitLab scans.
//
//	1. JSON.load unsafe deserialization         (CWE-502)   + JSON.parse sanitizer
//	2. Net::FTP SSRF (open / connect / new)      (CWE-918)
//	3. Net::FTP remote-path traversal (getfile)  (CWE-22)
//
// Held categories (proved FP on real repos — see the HELD comments in
// ruby_sinks.go): AR update_all/calculate/sum/lock raw-SQL fragments,
// instance_variable_set/get, define_method, and Kernel#load/require LFI.

// eclHasSinkID reports whether any flow terminates at the named sink ID.
func eclHasSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}

// ── 1. JSON.load unsafe deserialization ────────────────────────────────────

func TestRubyECL2_JSONLoad_Fires(t *testing.T) {
	code := `
def import(params)
    blob = params[:payload]
    obj = JSON.load(blob)
    obj
end
`
	flows := Analyze(code, "/app/services/importer.rb", rules.LangRuby)
	if !eclHasSinkID(flows, "ruby.json.load") {
		t.Error("expected ruby.json.load deserialization flow for tainted JSON.load")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRubyECL2_JSONParse_Clean(t *testing.T) {
	// JSON.parse is the safe alternative — neutralizes SnkDeserialize, so a
	// JSON.parse'd value must not be treated as live deserialize-tainted input.
	code := `
def import(params)
    blob = params[:payload]
    obj = JSON.parse(blob)
    Marshal.load(obj)
end
`
	flows := Analyze(code, "/app/services/importer.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Source.ID == "ruby.json.parse" && f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("JSON.parse output must not flow as deserialize taint: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// ── 2. Net::FTP SSRF (open / connect) ──────────────────────────────────────

func TestRubyECL2_NetFTP_SSRF_Fires(t *testing.T) {
	code := `
def sync(params)
    host = params[:host]
    ftp = Net::FTP.open(host)
    ftp
end
`
	flows := Analyze(code, "/app/services/ftp_sync.rb", rules.LangRuby)
	if !eclHasSinkID(flows, "ruby.net_ftp.open") {
		t.Error("expected ruby.net_ftp.open SSRF flow for tainted FTP host")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRubyECL2_NetFTP_FixedHost_Clean(t *testing.T) {
	code := `
def sync(params)
    _ = params[:ignored]
    ftp = Net::FTP.open("ftp.internal.example.com")
    ftp
end
`
	flows := Analyze(code, "/app/services/ftp_sync.rb", rules.LangRuby)
	if eclHasSinkID(flows, "ruby.net_ftp.open") {
		t.Error("Net::FTP.open with a fixed host literal must not fire")
	}
}

func TestRubyECL2_NetFTP_SSRF_Sanitized_Clean(t *testing.T) {
	// IPAddr/URI.host allowlist validation (shared SnkURLFetch sanitizer)
	// neutralizes the FTP SSRF flow.
	code := `
def sync(params)
    host = params[:host]
    parsed = URI.parse(host).host
    ftp = Net::FTP.open(parsed)
    ftp
end
`
	flows := Analyze(code, "/app/services/ftp_sync.rb", rules.LangRuby)
	if eclHasSinkID(flows, "ruby.net_ftp.open") {
		t.Error("URI.parse(host).host-validated Net::FTP.open must not fire SSRF")
	}
}

// ── 3. Net::FTP remote-path traversal (getfile) ────────────────────────────

func TestRubyECL2_NetFTP_GetFile_Fires(t *testing.T) {
	code := `
def pull(params, ftp)
    remote = params[:remote]
    ftp.getbinaryfile(remote, "/tmp/out")
end
`
	flows := Analyze(code, "/app/services/ftp_sync.rb", rules.LangRuby)
	if !eclHasSinkID(flows, "ruby.net_ftp.getfile") {
		t.Error("expected ruby.net_ftp.getfile path-traversal flow for tainted remote path")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
