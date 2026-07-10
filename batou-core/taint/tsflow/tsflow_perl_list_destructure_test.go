package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl — list-assignment destructuring recall (walker fix)
//
// Perl declares no varDeclTypes, so a `my (...) = (...)` declaration reaches
// processAssignInterproc as an assignment_expression whose LHS is a
// multi-variable variable_declaration. extractAssignLHS only yields the FIRST
// scalar, so every subsequent target silently lost taint:
//
//   my ($a, $b) = ($cgi->param('id'), 'safe');
//   $dbh->do($a);   # <-- previously ZERO flows
//
// processPerlListAssign seeds each destructured target from the corresponding
// RHS element (element-wise on matching arity, conservative whole-RHS
// distribution otherwise). These tests pin both the recall fix and its
// element-wise precision (the safe sibling stays clean).
// =========================================================================

// my ($a, $b) = ($source, 'safe'); — first target reaches a SQL sink.
func TestPerl_ListDestructure_ElementWise_InlineSource(t *testing.T) {
	code := `sub handler {
    my $cgi = CGI->new;
    my ($id, $safe) = ($cgi->param('id'), 'constant');
    $dbh->do("SELECT * FROM users WHERE id = " . $id);
}`
	flows := Analyze(code, "/app/lib/Handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for CGI param -> $dbh->do via my ($id, $safe) = (...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Element-wise precision: the SAFE sibling target must NOT carry taint. The
// literal 'constant' bound to $safe stays clean, so a sink on $safe is silent.
func TestPerl_ListDestructure_ElementWise_SafeSiblingSilent(t *testing.T) {
	code := `sub handler {
    my $cgi = CGI->new;
    my ($id, $safe) = ($cgi->param('id'), 'constant');
    $dbh->do("SELECT * FROM users WHERE name = " . $safe);
}`
	flows := Analyze(code, "/app/lib/Handler.pl", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("FALSE POSITIVE: safe literal sibling $safe must not produce a SQL flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (%.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// my ($a, $b) = ($tracked, $tracked); — element-wise binding from an
// already-tracked tainted scalar (not just an inline source call).
func TestPerl_ListDestructure_TrackedScalar(t *testing.T) {
	code := `sub handler {
    my $cgi = CGI->new;
    my $tainted = $cgi->param('cmd');
    my ($a, $b) = ($tainted, 'safe');
    system($a);
}`
	flows := Analyze(code, "/app/lib/Handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for tracked tainted scalar -> system via destructuring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Slurpy: my ($first, @rest) = (source, ...). Arity mismatch falls to the
// conservative whole-RHS distribution; $first must still be tainted.
func TestPerl_ListDestructure_Slurpy(t *testing.T) {
	code := `sub handler {
    my $cgi = CGI->new;
    my ($first, @rest) = ($cgi->param('cmd'), 'a', 'b');
    system($first);
}`
	flows := Analyze(code, "/app/lib/Handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for slurpy destructuring source -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: an all-literal list assignment must produce no flow.
func TestPerl_ListDestructure_AllLiterals_Silent(t *testing.T) {
	code := `sub handler {
    my ($a, $b) = ('alice', 'bob');
    $dbh->do("SELECT * FROM users WHERE id = " . $a);
}`
	flows := Analyze(code, "/app/lib/Handler.pl", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("FALSE POSITIVE: all-literal destructuring must not produce a SQL flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (%.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Regression guard: the single-variable `my $x = ...` path is untouched by the
// list-assignment branch (it returns false for <2 targets).
func TestPerl_ListDestructure_SingleVarUnaffected(t *testing.T) {
	code := `sub handler {
    my $cgi = CGI->new;
    my $id = $cgi->param('id');
    $dbh->do("SELECT * FROM users WHERE id = " . $id);
}`
	flows := Analyze(code, "/app/lib/Handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("regression: single-variable my $x = source -> sink must still flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
