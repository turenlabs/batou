package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Image::Magick / Graphics::Magick (PerlMagick) ImageTragick sinks
// =========================================================================
//
// Image::Magick (a.k.a. PerlMagick, shipped with ImageMagick) and
// Graphics::Magick (an API-compatible fork) hand attacker-controlled
// filenames and blob bytes to ImageMagick's coder/delegate chain. Tainted
// input reaching Read/ReadImage/BlobToImage/WriteImage/ImageToBlob/Mogrify
// is CWE-78 in the ImageTragick family (CVE-2016-3714 and successors).
//
// Mirrors the Ruby MiniMagick/RMagick catalog (ruby.rmagick.*,
// ruby.minimagick.*) and the C++ Magick++ coverage.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// Image::Magick->new with a tainted magick=> attribute — the coder prefix
// is attacker-chosen, so msl:/mvg:/ephemeral: selects a coder that shells
// out (ImageTragick, CVE-2016-3714).
func TestPerl_ImageMagick_New_TaintedCoder(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $fmt   = $cgi->param("fmt");
    my $image = Image::Magick->new(magick => $fmt);
    return $image;
}
`
	flows := Analyze(code, "/app/img.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> Image::Magick->new(magick=>...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Graphics::Magick->new — GraphicsMagick inherits the same coder surface.
func TestPerl_GraphicsMagick_New_TaintedCoder(t *testing.T) {
	code := `
use CGI;
use Graphics::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $fmt   = $cgi->param("fmt");
    my $image = Graphics::Magick->new(magick => $fmt);
    return $image;
}
`
	flows := Analyze(code, "/app/gmimg.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> Graphics::Magick->new(magick=>...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// $image->ReadImage($path) — primary ImageTragick vector. Tainted path is
// passed to ImageMagick's coder chain; msl:/mvg: prefixes run commands.
func TestPerl_ImageMagick_ReadImage_TaintedPath(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $path  = $cgi->param("avatar");
    my $image = Image::Magick->new;
    $image->ReadImage($path);
    return $image;
}
`
	flows := Analyze(code, "/app/read.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> $image->ReadImage (ImageTragick)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// $image->BlobToImage($bytes) — uploaded bytes parsed by the coder chain.
// Same ImageTragick exposure: magic bytes can dispatch SVG/MVG/PDF coders.
func TestPerl_ImageMagick_BlobToImage_TaintedBlob(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $blob  = $cgi->param("upload");
    my $image = Image::Magick->new;
    $image->BlobToImage($blob);
    return $image;
}
`
	flows := Analyze(code, "/app/blob.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> $image->BlobToImage (ImageTragick)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// $image->WriteImage($path) — tainted filename can include coder prefixes
// like `ephemeral:` or `info:|cmd` that exec delegates on the write path.
func TestPerl_ImageMagick_WriteImage_TaintedPath(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $out   = $cgi->param("dest");
    my $image = Image::Magick->new;
    $image->WriteImage($out);
    return 1;
}
`
	flows := Analyze(code, "/app/write.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> $image->WriteImage")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// $image->ImageToBlob(magick => $fmt) — encoder-side coder selection also
// drives external delegates for MVG/MSL/info:.
func TestPerl_ImageMagick_ImageToBlob_TaintedFormat(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $fmt   = $cgi->param("format");
    my $image = Image::Magick->new;
    my $blob  = $image->ImageToBlob(magick => $fmt);
    return $blob;
}
`
	flows := Analyze(code, "/app/tobytes.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> $image->ImageToBlob(magick=>...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// $image->Mogrify(...) — the PerlMagick facade for the `mogrify` CLI.
// Tainted args flow straight into -draw/-format/-process operators, which
// are documented command directives in ImageMagick.
func TestPerl_ImageMagick_Mogrify_TaintedArg(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $arg   = $cgi->param("transform");
    my $image = Image::Magick->new;
    $image->Mogrify("draw", $arg);
    return 1;
}
`
	flows := Analyze(code, "/app/mogrify.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> $image->Mogrify")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// --- Safe-path fixture — must NOT trigger flows ---

// Hardcoded coder + hardcoded path: no taint flows, no ImageTragick finding.
func TestPerl_ImageMagick_SafeHardcoded(t *testing.T) {
	code := `
use CGI;
use Image::Magick;
sub handler {
    my $cgi   = CGI->new;
    my $_     = $cgi->param("ignored");
    my $image = Image::Magick->new(magick => "png");
    $image->ReadImage("/usr/share/pixmaps/logo.png");
    return $image;
}
`
	flows := Analyze(code, "/app/safe.pl", rules.LangPerl)
	for _, f := range flows {
		switch f.Sink.ID {
		case "perl.imagemagick.new",
			"perl.imagemagick.readimage",
			"perl.imagemagick.blobtoimage",
			"perl.imagemagick.writeimage",
			"perl.imagemagick.imagetoblob",
			"perl.imagemagick.mogrify",
			"perl.graphicsmagick.new":
			t.Errorf("unexpected Image::Magick flow on hardcoded values: %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}
