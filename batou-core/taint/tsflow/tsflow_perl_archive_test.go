package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl Archive::Tar / Archive::Zip — Zip Slip / Tar Slip (CWE-22)
//
// Entry paths inside attacker-supplied archives are attacker-controlled;
// using them as a destination path enables directory traversal that
// escapes the intended extraction root.
// =========================================================================

func TestPerl_ArchiveTar_ExtractFile_TaintedDest_FlagsTarSlip(t *testing.T) {
	code := `
use Archive::Tar;
sub handler {
    my $tar = Archive::Tar->new;
    $tar->read("upload.tar");
    foreach my $entry ($tar->get_files) {
        my $name = $entry->full_path;
        $tar->extract_file($entry, "/var/data/$name");
    }
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Tar Slip flow: $entry->full_path -> extract_file dest path; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s -> snk=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestPerl_ArchiveZip_ExtractMember_TaintedDest_FlagsZipSlip(t *testing.T) {
	code := `
use Archive::Zip;
sub handler {
    my $zip = Archive::Zip->new;
    $zip->read("upload.zip");
    foreach my $member ($zip->members) {
        my $name = $member->fileName;
        $zip->extractMember($member, "/var/data/$name");
    }
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Zip Slip flow: $member->fileName -> extractMember dest path; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s -> snk=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestPerl_ArchiveZip_ExtractToFileNamed_TaintedName_FlagsZipSlip(t *testing.T) {
	code := `
use Archive::Zip;
sub handler {
    my $zip = Archive::Zip->new;
    $zip->read("upload.zip");
    foreach my $member ($zip->members) {
        my $name = $member->fileName;
        $member->extractToFileNamed("/var/data/$name");
    }
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Zip Slip flow: $member->fileName -> extractToFileNamed; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s -> snk=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Sanitized counterpart — File::Basename strips directory traversal so the
// extracted name is safe to use as the destination.
func TestPerl_ArchiveZip_FileBasename_SanitizesZipSlip(t *testing.T) {
	code := `
use Archive::Zip;
use File::Basename;
sub handler {
    my $zip = Archive::Zip->new;
    $zip->read("upload.zip");
    foreach my $member ($zip->members) {
        my $unsafe = $member->fileName;
        my $safe = basename($unsafe);
        $member->extractToFileNamed("/var/data/$safe");
    }
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Confidence > 0.7 {
			t.Errorf("expected basename() to sanitize Zip Slip flow; got flow src=%s -> snk=%s conf=%.2f",
				f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
