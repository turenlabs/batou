package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// File::create / File::open / fs::hard_link are the missing write/read sinks
// that close the zip/tar-slip detection loop alongside the existing
// ZipFile::mangled_name, ZipArchive::file_names and Entry::path_bytes sources.
// (CWE-22 path traversal, CWE-59 link-following)

func TestRust_FileCreate_ZipSlip_FileWrite(t *testing.T) {
	code := `
use zip::ZipArchive;
use std::fs::File;

fn extract(archive: &mut ZipArchive<std::fs::File>) {
    let entry = archive.by_index(0).unwrap();
    let name = entry.mangled_name();
    let mut out = File::create(&name).unwrap();
    out.write_all(b"payload").unwrap();
}
`
	flows := Analyze(code, "/app/extract.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: ZipFile::mangled_name -> File::create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_FileCreateQualified_FileWrite(t *testing.T) {
	code := `
use zip::ZipArchive;

fn extract(archive: &mut ZipArchive<std::fs::File>) {
    let entry = archive.by_index(0).unwrap();
    let name = entry.mangled_name();
    let mut out = std::fs::File::create(&name).unwrap();
    out.write_all(b"payload").unwrap();
}
`
	flows := Analyze(code, "/app/extract.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected flow with fully-qualified std::fs::File::create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_FileCreateNew_TarSlip_FileWrite(t *testing.T) {
	code := `
use tar::Archive;
use std::fs::File;

fn extract(archive: &mut Archive<std::fs::File>) {
    for entry_result in archive.entries().unwrap() {
        let mut entry = entry_result.unwrap();
        let path = entry.path_bytes();
        let _ = File::create_new(path.as_ref());
    }
}
`
	flows := Analyze(code, "/app/tarextract.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Tar Slip flow: Entry::path_bytes -> File::create_new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_TokioFileCreate_ZipSlip_FileWrite(t *testing.T) {
	code := `
use zip::ZipArchive;

async fn extract(archive: &mut ZipArchive<std::fs::File>) {
    let entry = archive.by_index(0).unwrap();
    let name = entry.mangled_name();
    let _file = tokio::fs::File::create(&name).await.unwrap();
}
`
	flows := Analyze(code, "/app/extract_async.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: ZipFile::mangled_name -> tokio::fs::File::create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_FileOpen_LFI_FileRead(t *testing.T) {
	code := `
use axum::extract::Query;
use std::fs::File;

async fn handler(Query(params): Query<std::collections::HashMap<String, String>>) {
    let name = params.get("path").unwrap().clone();
    let _file = File::open(&name).unwrap();
}
`
	flows := Analyze(code, "/app/download.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected LFI flow: axum Query -> File::open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_TokioFileOpen_LFI_FileRead(t *testing.T) {
	code := `
use axum::extract::Query;

async fn handler(Query(params): Query<std::collections::HashMap<String, String>>) {
    let name = params.get("path").unwrap().clone();
    let _file = tokio::fs::File::open(&name).await.unwrap();
}
`
	flows := Analyze(code, "/app/download_async.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected LFI flow: axum Query -> tokio::fs::File::open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_FsHardLink_TaintedDst_FileWrite(t *testing.T) {
	code := `
use zip::ZipArchive;
use std::fs;

fn extract(archive: &mut ZipArchive<std::fs::File>) {
    let entry = archive.by_index(0).unwrap();
    let name = entry.mangled_name();
    fs::hard_link("/etc/shadow", &name).unwrap();
}
`
	flows := Analyze(code, "/app/hardlink.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected hard_link flow: ZipFile::mangled_name -> fs::hard_link dst")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: hard-coded constant path — File::create should not fire.
// (Exercises the sink pattern without a taint source; proves the sink only
// fires when fed from a user-controlled value.)
func TestRust_FileCreate_ConstantPath_Safe(t *testing.T) {
	code := `
use std::fs::File;

fn write_log() {
    let _out = File::create("/var/log/app.log").unwrap();
}
`
	flows := Analyze(code, "/app/log.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.fs.file.create" {
			t.Errorf("expected no File::create flow with a constant path, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}
