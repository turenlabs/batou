package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — async image-loading SSRF sinks (CWE-918)
// =========================================================================
//
// Three new image-loading SSRF sinks extending Swift's existing
// Kingfisher/SDWebImage coverage:
//
//   1. swift.swiftui.asyncimage   — SwiftUI's built-in AsyncImage(url:)
//   2. swift.nuke.loadimage       — Nuke.loadImage(with:into:)
//   3. swift.nukeui.lazyimage     — NukeUI's LazyImage(url:)
//
// All three fetch the URL they are given; a user-controlled URL reaching
// any of them causes an arbitrary outbound request (image SSRF), the same
// class of issue already modeled for Kingfisher and SDWebImage.
//
// Matching:
//   - AsyncImage / LazyImage are constructor calls (receiver empty,
//     callMethod == ObjectType) — matched via the matcher's constructor path.
//   - Nuke.loadImage has receiver literally `Nuke`, matched by ObjectType
//     "Nuke" (so it never fires on unrelated `.loadImage` methods).
//
// Tests pass the tainted value through a local variable to the sink (the
// canonical pattern used by the existing Swift SSRF tests — inline nested
// constructors reduce taint propagation in the Swift walker).

// ---------- SwiftUI AsyncImage --------------------------------------------

func TestSwift_AsyncImage_TaintedURL_SSRF(t *testing.T) {
	code := `
import SwiftUI
import Vapor

func render(req: Request) -> AsyncImage {
    let target = req.query["img"]
    return AsyncImage(url: target)
}
`
	flows := Analyze(code, "/app/Gallery.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> AsyncImage(url:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// ---------- Nuke.loadImage ------------------------------------------------

func TestSwift_NukeLoadImage_TaintedURL_SSRF(t *testing.T) {
	code := `
import Nuke
import Vapor

func show(req: Request, into imageView: UIImageView) {
    let target = req.query["avatar"]
    Nuke.loadImage(with: target, into: imageView)
}
`
	flows := Analyze(code, "/app/Avatar.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> Nuke.loadImage(with:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// ---------- NukeUI LazyImage ----------------------------------------------

func TestSwift_LazyImage_TaintedURL_SSRF(t *testing.T) {
	code := `
import NukeUI
import Vapor

func render(req: Request) -> LazyImage {
    let target = req.query["src"]
    return LazyImage(url: target)
}
`
	flows := Analyze(code, "/app/Feed.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> LazyImage(url:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// ---------- Negative control: hardcoded URLs, no taint --------------------

func TestSwift_ImageLoaders_HardcodedURL_NoFlow(t *testing.T) {
	code := `
import SwiftUI
import NukeUI
import Nuke

func render(into imageView: UIImageView) -> AsyncImage {
    let safe = URL(string: "https://cdn.example.com/logo.png")
    Nuke.loadImage(with: safe, into: imageView)
    _ = LazyImage(url: safe)
    return AsyncImage(url: safe)
}
`
	flows := Analyze(code, "/app/Static.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("did not expect SSRF flow for hardcoded image URLs")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
