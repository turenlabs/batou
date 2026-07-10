package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// =========================================================================
// C++ — Zip Slip / Tar Slip archive extraction (CWE-22)
// =========================================================================
// An archive entry's pathname comes straight from the archive header and is
// attacker-controlled. Passing it to fopen / ofstream::open / remove / rename
// without normalization (basename, realpath, std::filesystem::canonical)
// lets a crafted archive write outside the extraction directory.
// References: Snyk "Zip Slip" (2018), CVE-2018-1000877 (libarchive),
// CVE-2018-20482 (GNU tar hardlink), libzip CVE-2019-12819.

func TestCPP_ZipSlip_LibarchivePathname_Fopen(t *testing.T) {
	code := `
#include <archive.h>
#include <archive_entry.h>
#include <cstdio>

void extract(struct archive *a) {
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == 0) {
        const char *name = archive_entry_pathname(entry);
        FILE *fp = fopen(name, "wb");
        fclose(fp);
    }
}
`
	flows := Analyze(code, "/app/extract.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: archive_entry_pathname -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZipSlip_LibarchivePathnameUtf8_Fopen(t *testing.T) {
	code := `
#include <archive.h>
#include <archive_entry.h>
#include <cstdio>

void extract(struct archive *a) {
    struct archive_entry *entry;
    archive_read_next_header(a, &entry);
    const char *name = archive_entry_pathname_utf8(entry);
    FILE *fp = fopen(name, "wb");
    fclose(fp);
}
`
	flows := Analyze(code, "/app/extract2.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: archive_entry_pathname_utf8 -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_TarSlip_LibarchiveHardlink_Remove(t *testing.T) {
	code := `
#include <archive.h>
#include <archive_entry.h>
#include <cstdio>

void apply(struct archive *a) {
    struct archive_entry *entry;
    archive_read_next_header(a, &entry);
    const char *target = archive_entry_hardlink(entry);
    remove(target);
}
`
	flows := Analyze(code, "/app/hardlink.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Tar Slip flow: archive_entry_hardlink -> remove")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZipSlip_LibarchiveSymlink_Unlink(t *testing.T) {
	code := `
#include <archive.h>
#include <archive_entry.h>
#include <unistd.h>

void apply(struct archive *a) {
    struct archive_entry *entry;
    archive_read_next_header(a, &entry);
    const char *target = archive_entry_symlink(entry);
    unlink(target);
}
`
	flows := Analyze(code, "/app/symlink.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: archive_entry_symlink -> unlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZipSlip_LibzipGetName_Fopen(t *testing.T) {
	code := `
#include <zip.h>
#include <cstdio>

void extract(zip_t *za) {
    zip_int64_t n = zip_get_num_entries(za, 0);
    for (zip_int64_t i = 0; i < n; i++) {
        const char *name = zip_get_name(za, i, 0);
        FILE *fp = fopen(name, "wb");
        fclose(fp);
    }
}
`
	flows := Analyze(code, "/app/libzip_extract.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: zip_get_name -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: archive entry path routed through basename() before fopen — the
// existing cpp.basename sanitizer should neutralize the Zip Slip flow.
func TestCPP_ZipSlip_LibarchivePathname_Basename_Safe(t *testing.T) {
	code := `
#include <archive.h>
#include <archive_entry.h>
#include <libgen.h>
#include <cstdio>
#include <cstring>

void extract(struct archive *a) {
    struct archive_entry *entry;
    archive_read_next_header(a, &entry);
    const char *name = archive_entry_pathname(entry);
    char buf[256];
    strncpy(buf, name, sizeof(buf));
    char *safe = basename(buf);
    FILE *fp = fopen(safe, "wb");
    fclose(fp);
}
`
	flows := Analyze(code, "/app/safe_extract.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("unexpected Zip Slip flow: basename() should neutralize archive_entry_pathname")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
