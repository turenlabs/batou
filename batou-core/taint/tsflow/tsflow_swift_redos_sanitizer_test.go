package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — ReDoS sanitizer test: NSRegularExpression.escapedPattern(for:)
// neutralizes SnkRegexDoS for the runtime Regex(_:) initializer.
//
// The sole Swift ReDoS sink is `swift.regex.init.runtime` (CWE-1333):
//
//     let re = try Regex(userPattern)   // catastrophic backtracking on an
//                                       // attacker-controlled pattern
//
// The sink's own remediation guidance names the canonical fix:
//
//     "escape user input with NSRegularExpression.escapedPattern(for:) or
//      validate it before compiling a dynamic pattern."
//
// escapedPattern(for:) escapes every regex metacharacter so the user's bytes
// are matched literally — a literal pattern cannot trigger catastrophic
// backtracking, so it is a true ReDoS sanitizer. The existing
// `swift.nsregularexpression.escapedpattern` entry already documents this in
// its Description ("prevents ReDoS and regex injection"), but its Neutralizes
// list previously omitted SnkRegexDoS, so escaping a pattern still produced a
// false-positive ReDoS finding. These tests pin the corrected behaviour.
// =========================================================================

// -------------------------------------------------------------------------
// Registration check — escapedPattern must neutralize SnkRegexDoS.
// -------------------------------------------------------------------------

func TestSwift_RedosSanitizer_Registered(t *testing.T) {
	var found *taint.SanitizerDef
	for _, s := range taint.SanitizersForLanguage(rules.LangSwift) {
		s := s
		if s.ID == "swift.nsregularexpression.escapedpattern" {
			found = &s
			break
		}
	}
	if found == nil {
		t.Fatal("sanitizer swift.nsregularexpression.escapedpattern not registered for Swift")
	}
	neutralizesRedos := false
	for _, c := range found.Neutralizes {
		if c == taint.SnkRegexDoS {
			neutralizesRedos = true
			break
		}
	}
	if !neutralizesRedos {
		t.Errorf("swift.nsregularexpression.escapedpattern must neutralize SnkRegexDoS; got %v", found.Neutralizes)
	}
}

// -------------------------------------------------------------------------
// Vulnerable control — baseline must produce the ReDoS flow, otherwise the
// "safe" tests below are not actually exercising the sanitizer.
// -------------------------------------------------------------------------

func TestSwift_Redos_Baseline_Unsanitized(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) throws {
    let userPattern = req.query["p"]
    let re = try Regex(userPattern)
    _ = re
}
`
	flows := Analyze(code, "/app/RedosBaseline.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected SnkRegexDoS flow for req.query -> try Regex(userPattern) baseline")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f, id: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Safe: escapedPattern(for: tainted) assigned, then compiled — neutralizes
// SnkRegexDoS (the common assign-then-use shape).
// -------------------------------------------------------------------------

func TestSwift_Redos_EscapedPattern_AssignThenUse_Sanitized(t *testing.T) {
	code := `
import Foundation

func handler(req: Request) throws {
    let userPattern = req.query["p"]
    let safe = NSRegularExpression.escapedPattern(for: userPattern)
    let re = try Regex(safe)
    _ = re
}
`
	flows := Analyze(code, "/app/RedosSafeAssign.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRegexDoS {
			t.Errorf("expected NO SnkRegexDoS flow when NSRegularExpression.escapedPattern(for:) is in the path: %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Safe: escapedPattern wrapped inline at the sink — neutralizes SnkRegexDoS.
// -------------------------------------------------------------------------

func TestSwift_Redos_EscapedPattern_Inline_Sanitized(t *testing.T) {
	code := `
import Foundation

func handler(req: Request) throws {
    let userPattern = req.query["p"]
    let re = try Regex(NSRegularExpression.escapedPattern(for: userPattern))
    _ = re
}
`
	flows := Analyze(code, "/app/RedosSafeInline.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRegexDoS {
			t.Errorf("expected NO SnkRegexDoS flow when escapedPattern(for:) wraps the pattern inline: %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
