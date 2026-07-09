package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — ZIPFoundation Zip Slip / Tar Slip tests (CWE-22)
//
// Canonical vulnerable pattern: a ZIP archive is opened from an untrusted
// URL or Data blob, entries are iterated, and per-entry paths flow into
// a file-write operation without path-traversal validation. The `.path`
// on a ZIPFoundation Entry carries an attacker-controlled string that
// can contain `../` sequences.
//
// Refs: Snyk "Zip Slip" disclosure (2018), CVE-2018-1000544 class.
// =========================================================================

func TestSwift_ZipFoundation_ArchiveURL_Extract_ZipSlip(t *testing.T) {
	code := `
import ZIPFoundation
import Foundation

func handler(zipURL: URL, destDir: URL) throws {
    let archive = Archive(url: zipURL, accessMode: .read)
    let entry = archive["malicious.txt"]
    let destURL = destDir.appendingPathComponent(entry.path)
    try archive.extract(entry, to: destURL)
}
`
	flows := Analyze(code, "/app/extract.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: Archive(url:) -> entry -> extract(_:to:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_ZipFoundation_ArchiveData_Unzip_ZipSlip(t *testing.T) {
	code := `
import ZIPFoundation
import Foundation

func handler(zipData: Data, destDir: URL) throws {
    let archive = Archive(data: zipData, accessMode: .read)
    let badURL = destDir.appendingPathComponent(String(describing: archive))
    try FileManager.default.unzipItem(at: badURL, to: destDir)
}
`
	flows := Analyze(code, "/app/unzip.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: Archive(data:) -> unzipItem(at:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_SSZipArchive_Unzip_ZipSlip(t *testing.T) {
	code := `
import SSZipArchive
import Vapor

func handler(req: Request) throws {
    let uploadedPath = req.query["path"]
    SSZipArchive.unzipFile(atPath: uploadedPath, toDestination: "/tmp/out")
}
`
	flows := Analyze(code, "/app/sszip.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: req.query -> SSZipArchive.unzipFile(atPath:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_SSZipArchive_Unzip_Safe_HasPrefixBaseDir(t *testing.T) {
	// Negative test: containment check against a named base directory is
	// the existing `swift.path.hasprefix.check` sanitizer. Confirms that
	// sanitizer also neutralises the new SSZipArchive sink.
	code := `
import SSZipArchive
import Vapor

func handler(req: Request) throws {
    let uploadedPath = req.query["path"]
    if uploadedPath.hasPrefix(baseDir) {
        SSZipArchive.unzipFile(atPath: uploadedPath, toDestination: "/tmp/out")
    }
}
`
	flows := Analyze(code, "/app/sszip_safe.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected NO file-write flow after .hasPrefix(baseDir) sanitization, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
