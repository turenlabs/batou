package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — MiniMagick / RMagick image-processing command-injection sinks
// =========================================================================
//
// MiniMagick wraps the ImageMagick CLI (convert, mogrify, identify). Tainted
// filenames/URLs reach Kernel#open and the shell. CVE-2019-13574 demonstrates
// the classic "|command" trick for RCE. RMagick uses the C bindings but still
// processes attacker-controlled image data — historically exploitable via the
// SVG/MVG/PDF delegate coders (ImageTragick, CVE-2016-3714 family).

func TestRuby_MiniMagick_ImageOpen_CommandInjection(t *testing.T) {
	code := `
require "mini_magick"

def process(params)
  url = params[:avatar_url]
  MiniMagick::Image.open(url)
end
`
	flows := Analyze(code, "/app/avatar.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> MiniMagick::Image.open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_MiniMagick_ImageNew_CommandInjection(t *testing.T) {
	code := `
require "mini_magick"

def thumbnail(params)
  path = params[:upload]
  image = MiniMagick::Image.new(path)
  image
end
`
	flows := Analyze(code, "/app/thumb.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> MiniMagick::Image.new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_MiniMagick_ImageRead_CommandInjection(t *testing.T) {
	code := `
require "mini_magick"

def import(params)
  blob = params[:image_data]
  MiniMagick::Image.read(blob)
end
`
	flows := Analyze(code, "/app/import.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> MiniMagick::Image.read")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RMagick_ImageRead_ImageTragick(t *testing.T) {
	code := `
require "rmagick"

def render(params)
  filename = params[:file]
  Magick::Image.read(filename)
end
`
	flows := Analyze(code, "/app/render.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> Magick::Image.read (ImageTragick)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RMagick_ImagePing_ImageTragick(t *testing.T) {
	code := `
require "rmagick"

def probe(params)
  filename = params[:path]
  Magick::Image.ping(filename)
end
`
	flows := Analyze(code, "/app/probe.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> Magick::Image.ping")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RMagick_ImageFromBlob_ImageTragick(t *testing.T) {
	code := `
require "rmagick"

def upload(params)
  data = params[:payload]
  Magick::Image.from_blob(data)
end
`
	flows := Analyze(code, "/app/upload.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> Magick::Image.from_blob")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RMagick_ImageReadInline_ImageTragick(t *testing.T) {
	code := `
require "rmagick"

def decode(params)
  b64 = params[:inline]
  Magick::Image.read_inline(b64)
end
`
	flows := Analyze(code, "/app/decode.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> Magick::Image.read_inline")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RMagick_ImageListNew_ImageTragick(t *testing.T) {
	code := `
require "rmagick"

def batch(params)
  first = params[:left]
  Magick::ImageList.new(first)
end
`
	flows := Analyze(code, "/app/batch.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from params -> Magick::ImageList.new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// --- Safe-path (sanitized) fixtures — must NOT trigger flows ---

func TestRuby_MiniMagick_SafeHardcodedPath(t *testing.T) {
	code := `
require "mini_magick"

def avatar(params)
  _ = params[:anything]
  MiniMagick::Image.open("/usr/share/pixmaps/logo.png")
end
`
	flows := Analyze(code, "/app/safe_avatar.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.minimagick.image.open" {
			t.Errorf("unexpected flow on hardcoded path: %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}

func TestRuby_MiniMagick_ShellwordsSanitized(t *testing.T) {
	code := `
require "mini_magick"
require "shellwords"

def process(params)
  url = Shellwords.escape(params[:avatar_url])
  MiniMagick::Image.open(url)
end
`
	flows := Analyze(code, "/app/safe.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.minimagick.image.open" {
			t.Errorf("unexpected flow after Shellwords.escape: %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}
