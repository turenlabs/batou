package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Archive extraction sinks (Zip Slip / Tar Slip, CWE-22)
// =========================================================================

// Rubyzip Zip::Entry#extract with tainted destination path (CVE-2019-16892).
func TestRuby_Archive_RubyzipEntryExtract(t *testing.T) {
	code := `
def unzip(params)
  dest = params[:dest]
  Zip::File.open(params[:archive]) do |zip|
    zip.each do |entry|
      entry.extract(dest)
    end
  end
end
`
	flows := Analyze(code, "/app/controllers/upload_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Zip::Entry#extract")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Archive::Tar::Minitar.unpack with tainted destination directory.
func TestRuby_Archive_MinitarUnpack(t *testing.T) {
	code := `
def untar(params)
  dest_dir = params[:dest]
  File.open(params[:archive], "rb") do |io|
    Archive::Tar::Minitar.unpack(io, dest_dir)
  end
end
`
	flows := Analyze(code, "/app/controllers/upload_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Minitar.unpack")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Zip::InputStream.open with tainted archive path (path traversal on read).
func TestRuby_Archive_ZipInputStreamOpen(t *testing.T) {
	code := `
def read_archive(params)
  archive_path = params[:file]
  Zip::InputStream.open(archive_path) do |io|
    while (entry = io.get_next_entry)
      puts entry.name
    end
  end
end
`
	flows := Analyze(code, "/app/controllers/archive_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for params -> Zip::InputStream.open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// File.expand_path alone is NOT a sanitizer: expand_path("../../etc")
// resolves to a real path OUTSIDE the safe base, and this fixture has no
// containment check (start_with?) — it is a genuine Zip Slip vulnerability,
// so the taint flow must survive. (This test previously asserted the
// opposite, which was unsound — see the filepath.Clean note in
// go_sanitizers.go and the os.path.normpath/realpath note in
// python_sanitizers.go. The combined expand_path + start_with? idiom IS
// still recognised via the ruby.file.expand_path_guard sanitizer entry.)
func TestRuby_Archive_ExpandPathAlone_NotASanitizer(t *testing.T) {
	code := `
def unzip_unsafe(params)
  raw_dest = params[:dest]
  dest = File.expand_path(raw_dest)
  Zip::File.open(params[:archive]) do |zip|
    zip.each do |entry|
      entry.extract(dest)
    end
  end
end
`
	flows := Analyze(code, "/app/controllers/safe_upload_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("File.expand_path alone must NOT neutralize FileWrite taint — expected the Zip Slip flow to still fire")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: File.basename strips directory traversal before Minitar.unpack.
// Uses a hard-coded archive path so the only tainted path is the destination.
func TestRuby_Archive_SafeBasename(t *testing.T) {
	code := `
def untar_safe(params)
  dest_dir = File.basename(params[:dest])
  io = StringIO.new("tar-data")
  Archive::Tar::Minitar.unpack(io, dest_dir)
end
`
	flows := Analyze(code, "/app/controllers/safe_upload_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("did not expect FileWrite flow after File.basename sanitization")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
