package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// JavaScript/TypeScript — Zip Slip / Tar Slip (CWE-22)
// =========================================================================
//
// Archive entry pathname fields (yauzl Entry.fileName, adm-zip IZipEntry.entryName)
// come from the archive header and are fully attacker-controlled. When
// concatenated into a target directory via path.join / fs.createWriteStream
// without basename / path.resolve + startsWith containment, a crafted zip
// containing "../" or absolute paths writes outside the extraction root.
//
// Library-level extraction helpers (adm-zip extractAllTo/extractEntryTo,
// node-tar tar.x / tar.extract) do the extraction themselves and inherit the
// same risk when the archive arrives from a user upload.
//
// References:
//   - Snyk "Zip Slip" 2018
//   - CVE-2018-1002204 (adm-zip)
//   - CVE-2021-32803, CVE-2021-37701 (node-tar)
//   - CVE-2022-48285 (jszip)

// yauzl: entry.fileName → fs.createWriteStream via path.join.
// Matches testdata/fixtures/javascript/vulnerable/zip_slip.ts shape.
func TestJS_ZipSlip_Yauzl_FileName_CreateWriteStream(t *testing.T) {
	code := `
const fs = require('fs');
const path = require('path');
const yauzl = require('yauzl');

function extractZip(zipPath, destDir) {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        zipfile.on('entry', (entry) => {
            const name = entry.fileName;
            const destPath = path.join(destDir, name);
            const writeStream = fs.createWriteStream(destPath);
            writeStream.end();
        });
    });
}
`
	flows := Analyze(code, "/app/extract.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: yauzl entry.fileName -> fs.createWriteStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// adm-zip: entry.entryName property — attacker-controlled path used as
// destination directly.
func TestJS_ZipSlip_AdmZip_EntryName_WriteFileSync(t *testing.T) {
	code := `
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

function extract(zipBuf, target) {
    const zip = new AdmZip(zipBuf);
    const entries = zip.getEntries();
    entries.forEach((entry) => {
        const name = entry.entryName;
        const dest = path.join(target, name);
        fs.writeFileSync(dest, entry.getData());
    });
}
`
	flows := Analyze(code, "/app/unzip.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: adm-zip entry.entryName -> fs.writeFileSync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// adm-zip's own extractAllTo() sink: when the target directory is derived
// from a user-controlled request, path traversal via the target alone escapes
// the intended root, independent of archive-entry Zip Slip.
func TestJS_ZipSlip_AdmZip_ExtractAllTo_TaintedTarget(t *testing.T) {
	code := `
const AdmZip = require('adm-zip');

app.post('/upload', (req, res) => {
    const target = req.body.dest;
    const zip = new AdmZip('/uploads/a.zip');
    zip.extractAllTo(target, true);
    res.send('ok');
});
`
	flows := Analyze(code, "/app/routes/upload.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected flow: req.body.dest -> AdmZip.extractAllTo target")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: path.basename on the tainted entry name strips directory
// components, so no file-write flow should fire.
func TestJS_ZipSlip_Yauzl_PathBasename_Safe(t *testing.T) {
	code := `
const fs = require('fs');
const path = require('path');
const yauzl = require('yauzl');

function extractSafe(zipPath, destDir) {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        zipfile.on('entry', (entry) => {
            const safeName = path.basename(entry.fileName);
            const destPath = path.join(destDir, safeName);
            const writeStream = fs.createWriteStream(destPath);
            writeStream.end();
        });
    });
}
`
	flows := Analyze(code, "/app/safe_extract.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected no file-write flow after path.basename sanitizer, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// node-tar: tar.x extracts an archive originating from a user upload.
func TestJS_TarSlip_Tar_X_UploadedArchive(t *testing.T) {
	code := `
const tar = require('tar');

app.post('/upload', (req, res) => {
    const file = req.body.filePath;
    tar.x({ file: file, cwd: '/tmp/out' });
    res.send('ok');
});
`
	flows := Analyze(code, "/app/routes/tarupload.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Tar Slip flow: req.body.filePath -> tar.x")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
