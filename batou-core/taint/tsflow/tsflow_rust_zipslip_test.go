package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Zip Slip / Tar Slip sources: archive entry names are fully attacker-controlled
// and must not flow directly into file I/O sinks. (CWE-22)

func TestRust_ZipFile_MangledName_FileWrite(t *testing.T) {
	code := `
use std::fs;
use zip::ZipArchive;

fn extract(archive: &mut ZipArchive<std::fs::File>) {
    let entry = archive.by_index(0).unwrap();
    let name = entry.mangled_name();
    fs::write(&name, b"payload").unwrap();
}
`
	flows := Analyze(code, "/app/extract.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: ZipFile::mangled_name -> fs::write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_ZipArchive_FileNames_FileRead(t *testing.T) {
	code := `
use std::fs;
use zip::ZipArchive;

fn list(archive: &ZipArchive<std::fs::File>) {
    let names = archive.file_names();
    let first = names.next().unwrap();
    let data = fs::read(first).unwrap();
    println!("{:?}", data.len());
}
`
	flows := Analyze(code, "/app/list.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected Zip Slip flow: ZipArchive::file_names -> fs::read")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_TarEntry_PathBytes_FileWrite(t *testing.T) {
	code := `
use std::fs;
use tar::Archive;

fn extract(archive: &mut Archive<std::fs::File>) {
    for entry_result in archive.entries().unwrap() {
        let mut entry = entry_result.unwrap();
        let path = entry.path_bytes();
        fs::write(path.as_ref(), b"x").unwrap();
    }
}
`
	flows := Analyze(code, "/app/tarextract.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Tar Slip flow: Entry::path_bytes -> fs::write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: enclosed_name validates path components — no flow should fire.
func TestRust_ZipFile_EnclosedName_Safe(t *testing.T) {
	code := `
use std::fs;
use zip::ZipArchive;

fn extract(archive: &mut ZipArchive<std::fs::File>) {
    let entry = archive.by_index(0).unwrap();
    if let Some(safe) = entry.enclosed_name() {
        fs::write(&safe, b"payload").unwrap();
    }
}
`
	flows := Analyze(code, "/app/safe_extract.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected no file-write flow when using enclosed_name, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}
