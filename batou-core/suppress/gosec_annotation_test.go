package suppress

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// gosec / golangci-lint security-suppression annotations
//
// Real-world smoke test (Grafana/Redis/Keycloak) surfaced false positives on
// lines the developer had already audited with the standard Go conventions:
//
//	http.Redirect(w, r, u, 302) // #nosec G710 -- validated by RedirectValidator
//	// nolint:gosec
//	yamlFile, _ := os.ReadFile(filename)
//
// These are the gosec equivalent of Batou's own batou:ignore directive — an
// audited sign-off — and are honored as such (security findings suppressed on
// the annotated line, and the next code line for a pure-comment annotation).
//
// A bare //nolint (no gosec) is NOT honored: it disables every golangci-lint
// linter including style ones, so a security sign-off cannot be inferred.
// =========================================================================

func TestGosec_InlineNosec_SuppressesOwnLine(t *testing.T) {
	s := Parse("http.Redirect(w, r, u, 302) // #nosec G710 -- validated upstream")
	f := rules.Finding{RuleID: "BATOU-TAINT-redirect", LineNumber: 1}
	if !s.IsSuppressed(f) {
		t.Error("expected #nosec on the same line to suppress the finding")
	}
}

func TestGosec_NolintGosec_PureCommentSuppressesNextCodeLine(t *testing.T) {
	// The config_reader.go shape: annotation on its own line, two comment lines,
	// then the flagged statement.
	src := "// nolint:gosec\n" +
		"// comes from ps.Cfg.ProvisioningPath\n" +
		"yamlFile, _ := os.ReadFile(filename)"
	s := Parse(src)
	f := rules.Finding{RuleID: "BATOU-TAINT-deserialize", LineNumber: 3}
	if !s.IsSuppressed(f) {
		t.Error("expected // nolint:gosec comment line to suppress the next code line (os.ReadFile)")
	}
}

func TestGosec_NolintGosec_InCommaList(t *testing.T) {
	s := Parse("x := os.Open(p) //nolint:govet,gosec,errcheck")
	f := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 1}
	if !s.IsSuppressed(f) {
		t.Error("expected nolint:gosec inside a comma list to be honored")
	}
}

func TestGosec_BareNolint_NotHonored(t *testing.T) {
	// A bare //nolint with no gosec in the linter list must NOT be treated as a
	// security suppression.
	s := Parse("x := os.Open(p) //nolint:errcheck")
	f := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 1}
	if s.IsSuppressed(f) {
		t.Error("bare //nolint:errcheck (no gosec) must NOT suppress a security finding")
	}
}

func TestGosec_BareNolint_NoLinterList_NotHonored(t *testing.T) {
	s := Parse("x := os.Open(p) //nolint")
	f := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 1}
	if s.IsSuppressed(f) {
		t.Error("bare //nolint (no linter list) must NOT suppress a security finding")
	}
}

func TestGosec_UnrelatedLine_NotSuppressed(t *testing.T) {
	// The annotation suppresses only its own line (inline form), not later lines.
	src := "x := os.Open(p) // #nosec G304\n" +
		"y := os.Open(q)"
	s := Parse(src)
	f := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 2}
	if s.IsSuppressed(f) {
		t.Error("an inline #nosec on line 1 must NOT suppress an unrelated statement on line 2")
	}
}

// --- Adjudication interplay ------------------------------------------------

// A gosec annotation's free-text rationale is the developer's out-of-band gosec
// judgment, not a claim about Batou's computed flow. Adjudicate must NOT
// machine-check it (otherwise every audited #nosec with a word like "validated"
// would be re-flagged as BATOU-SUPPRESS-UNJUSTIFIED).
func TestGosec_AnnotationReason_NotAdjudicated(t *testing.T) {
	s := Parse("http.Redirect(w, r, u, 302) // #nosec G710 -- redirectURL validated by RedirectValidator")
	// A surviving taint flow (no sanitizer node) from an external source — the
	// exact shape that, under a batou:ignore "validated" reason, would be flagged.
	suppressed := []rules.Finding{{
		RuleID:         "BATOU-INTERPROC-REDIRECT",
		LineNumber:     1,
		SourceCategory: "user_input",
		SinkCategory:   "redirect",
		Tags:           []string{"interprocedural", "dataflow"},
	}}
	adj := Adjudicate(s, suppressed)
	if len(adj) != 0 {
		t.Errorf("gosec-annotation reason must not be adjudicated, got %d adjudication(s)", len(adj))
		for _, a := range adj {
			t.Logf("  unexpected adjudication: %s -> %s", a.OriginalRuleID, a.Contradiction)
		}
	}
}

// A genuine batou:ignore directive with a contradicted "validated" reason is
// still adjudicated — proving the skip is scoped to gosec lines only.
func TestGosec_BatouIgnoreReason_StillAdjudicated(t *testing.T) {
	s := Parse("// batou:ignore BATOU-INTERPROC-REDIRECT -- input is validated\nhttp.Redirect(w, r, u, 302)")
	suppressed := []rules.Finding{{
		RuleID:         "BATOU-INTERPROC-REDIRECT",
		LineNumber:     2,
		SourceCategory: "user_input",
		SinkCategory:   "redirect",
		Tags:           []string{"interprocedural", "dataflow"},
	}}
	adj := Adjudicate(s, suppressed)
	if len(adj) != 1 {
		t.Fatalf("a batou:ignore 'validated' reason contradicted by an unsanitized flow must be adjudicated, got %d", len(adj))
	}
}

func TestReasonFromGosecAnnotation(t *testing.T) {
	cases := map[string]string{
		"x := f() // #nosec G304 -- path is trusted config": "path is trusted config",
		"// #nosec G101 not a hardcoded credential":         "not a hardcoded credential",
		"x := f() //nolint:gosec":                           "",
		"// nolint:gosec":                                   "",
	}
	for line, want := range cases {
		if got := reasonFromGosecAnnotation(line); got != want {
			t.Errorf("reasonFromGosecAnnotation(%q) = %q, want %q", line, got, want)
		}
	}
}
