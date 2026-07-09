package shellast

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

func scanShell(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangShell)
	ctx := &rules.ScanContext{
		FilePath: "/app/deploy.sh",
		Content:  code,
		Language: rules.LangShell,
		Tree:     tree,
	}
	a := &ShellASTAnalyzer{}
	return a.Scan(ctx)
}

func hasRule(findings []rules.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func hasRuleCWE(findings []rules.Finding, id, cwe string) bool {
	for _, f := range findings {
		if f.RuleID == id && f.CWEID == cwe {
			return true
		}
	}
	return false
}

// --- 001: unquoted word-splitting / glob injection ---
//
// Rule 001 is GATED on external origin: it fires only when the unquoted
// expansion references a variable that intra-file analysis traced to external
// (user/attacker-controlled) input. Local/constant/positional operands — the
// overwhelming majority on real build scripts — must NOT fire.

func TestUnquotedExternalVarInFileCommand(t *testing.T) {
	// Externally-derived: userpath read from stdin → cp $userpath is a genuine
	// word-split risk. This is the probe target with an established source.
	code := "read userpath\ncp $userpath /dest\n"
	findings := scanShell(t, code)
	if !hasRuleCWE(findings, "BATOU-SH-AST-001", "CWE-78") {
		t.Errorf("expected BATOU-SH-AST-001 (CWE-78) for unquoted external cp arg, got %+v", findings)
	}
	for _, f := range findings {
		if f.RuleID == "BATOU-SH-AST-001" && f.Severity != rules.High {
			t.Errorf("expected High, got %s", f.Severity)
		}
	}
}

func TestUnquotedEnvVarInFileCommand(t *testing.T) {
	// A CGI/web request env var consumed directly is external.
	code := "cp $QUERY_STRING /dest\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("expected BATOU-SH-AST-001 for unquoted CGI env var arg, got %+v", findings)
	}
}

func TestUnquotedExternalBracedConcatenation(t *testing.T) {
	// ${archive}/payload is an unquoted concatenation; gated on the variable
	// being external (here: derived from a request env var by assignment).
	code := "archive=$REQUEST_URI\ntar -xf ${archive}/payload\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-001") {
		t.Error("expected BATOU-SH-AST-001 for unquoted braced concatenation of an external var")
	}
}

func TestUnquotedPositionalNotFlagged(t *testing.T) {
	// Bare positional params ($1) are AMBIGUOUS — build scripts pass safe build
	// arguments positionally — so word-splitting them does NOT fire.
	code := "f=$1\ncp $userpath /dest\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("unquoted non-external (positional/unknown) var must NOT trigger 001, got %+v", findings)
	}
}

func TestUnquotedLocalLiteralNotFlagged(t *testing.T) {
	// PID_FILE / TMP_FILE assigned to a literal or $(mktemp) are local — the
	// real-repo flood shape. Must NOT fire.
	code := "PID_FILE=/var/run/x.pid\nkill $(cat ${PID_FILE})\n" +
		"TMP=$(mktemp)\ncp $TMP /dest\nTAG=v1.0\ngit archive $TAG\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("local literal / mktemp / constant operands must NOT trigger 001, got %+v", findings)
	}
}

func TestQuotedVarNotFlagged(t *testing.T) {
	// Double-quoting defeats word-splitting → no finding, even when external.
	code := "read src\nread dst\ncp \"$src\" \"$dst\"\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("quoted expansion must not trigger word-split finding, got %+v", findings)
	}
}

func TestEchoNotFlagged(t *testing.T) {
	// echo is not in the consequential-command allow-list → low-value, no finding.
	code := "read harmless\necho $harmless\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-001") {
		t.Error("echo with unquoted var should not trigger 001 (out of allow-list)")
	}
}

// --- 002: eval of dynamic data ---

func TestEvalDynamic(t *testing.T) {
	code := "f=$1\neval \"$f\"\n"
	findings := scanShell(t, code)
	if !hasRuleCWE(findings, "BATOU-SH-AST-002", "CWE-78") {
		t.Errorf("expected BATOU-SH-AST-002 (CWE-78) for eval of variable, got %+v", findings)
	}
	for _, f := range findings {
		if f.RuleID == "BATOU-SH-AST-002" && f.Severity != rules.Critical {
			t.Errorf("expected Critical, got %s", f.Severity)
		}
	}
}

func TestEvalDynamicUnknownSource(t *testing.T) {
	// Variable does NOT come from a known taint source — taint walker would be
	// inert, but structural detection still fires.
	code := "cfg=$RANDOM_ENV\neval $cfg\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-002") {
		t.Error("expected BATOU-SH-AST-002 for eval of an unknown-origin variable")
	}
}

func TestEvalStaticNotFlagged(t *testing.T) {
	code := "eval \"echo hello\"\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-002") {
		t.Error("eval of a static string must not trigger 002")
	}
}

// --- 003: source / . of dynamic path ---

func TestSourceDynamic(t *testing.T) {
	code := "source \"$config\"\n"
	findings := scanShell(t, code)
	if !hasRuleCWE(findings, "BATOU-SH-AST-003", "CWE-95") {
		t.Errorf("expected BATOU-SH-AST-003 (CWE-95) for source of variable, got %+v", findings)
	}
}

func TestDotSourceDynamic(t *testing.T) {
	code := ". $config\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-003") {
		t.Error("expected BATOU-SH-AST-003 for . (dot) source of variable")
	}
}

func TestSourceStaticNotFlagged(t *testing.T) {
	code := "source /etc/profile\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-003") {
		t.Error("source of a literal path must not trigger 003")
	}
}

// --- 004: sh -c / bash -c with dynamic inline code ---

func TestBashDashCDynamic(t *testing.T) {
	code := "cmd=$1\nbash -c \"echo $cmd\"\n"
	findings := scanShell(t, code)
	if !hasRuleCWE(findings, "BATOU-SH-AST-004", "CWE-78") {
		t.Errorf("expected BATOU-SH-AST-004 (CWE-78) for bash -c dynamic, got %+v", findings)
	}
}

func TestShDashCStaticNotFlagged(t *testing.T) {
	code := "sh -c \"echo static\"\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-004") {
		t.Error("sh -c with a static program must not trigger 004")
	}
}

// --- 005: command name from a variable (GATED on external origin) ---

func TestVariableCommandNameExternal(t *testing.T) {
	// Command name from a variable derived from stdin → arbitrary command exec.
	code := "read action\n$action --flag\n"
	findings := scanShell(t, code)
	if !hasRuleCWE(findings, "BATOU-SH-AST-005", "CWE-78") {
		t.Errorf("expected BATOU-SH-AST-005 (CWE-78) for external variable command name, got %+v", findings)
	}
	for _, f := range findings {
		if f.RuleID == "BATOU-SH-AST-005" && f.Severity != rules.Critical {
			t.Errorf("expected Critical, got %s", f.Severity)
		}
	}
}

func TestVariableCommandNameExternalEnv(t *testing.T) {
	// Command name pulled from a request-derived env var assignment.
	code := "cmd=$HTTP_X_CMD\n$cmd run\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-005") {
		t.Errorf("expected BATOU-SH-AST-005 for env-derived command name, got %+v", findings)
	}
}

func TestVariableCommandNameLocalNotFlagged(t *testing.T) {
	// $CLANG_FORMAT / $msys_shell_cmd / a positional build target are the
	// real-repo flood shape for 005 — local dispatch, NOT external. Must NOT fire.
	code := "CLANG_FORMAT=clang-format-8\n$CLANG_FORMAT -version\n" +
		"action=$1\n$action --do-it\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-005") {
		t.Errorf("local/positional command-name dispatch must NOT trigger 005, got %+v", findings)
	}
}

// --- external-origin gating mechanics (001/005) ---

func TestFetchSubstitutionIsExternal(t *testing.T) {
	// var=$(curl ...) is remotely controlled → word-split into a file command fires.
	code := "data=$(curl -s http://x/list)\nrm $data\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("expected 001 for word-split of a $(curl ...) value, got %+v", findings)
	}
}

func TestWgetSubstitutionCommandNameExternal(t *testing.T) {
	code := "prog=$(wget -qO- http://x/name)\n$prog --go\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-005") {
		t.Errorf("expected 005 for command name from a $(wget ...) value, got %+v", findings)
	}
}

func TestTransitiveExternalPropagation(t *testing.T) {
	// b derived from an external a (concatenation) is itself external.
	code := "a=$QUERY_STRING\nb=\"${a}/sub\"\nrm $b\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("expected 001 for word-split of a transitively-external var, got %+v", findings)
	}
}

func TestWhileReadIsExternal(t *testing.T) {
	// `while read line` reads each iteration's value from stdin.
	code := "while read line; do rm $line; done\n"
	findings := scanShell(t, code)
	if !hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("expected 001 for word-split of a `while read` var, got %+v", findings)
	}
}

func TestMktempSubstitutionNotExternal(t *testing.T) {
	// $(mktemp) is a LOCAL temp path, not external — must NOT fire.
	code := "tmp=$(mktemp)\ncp $tmp /dest\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("$(mktemp) is local; must NOT trigger 001, got %+v", findings)
	}
}

func TestCommandSubstitutionOfLocalNotExternal(t *testing.T) {
	// kill $(cat ${PID_FILE}) where PID_FILE is a literal — the redis flood
	// shape. The cat-substitution is not a fetch and PID_FILE is local.
	code := "PID_FILE=/var/run/x.pid\nkill $(cat ${PID_FILE})\n"
	findings := scanShell(t, code)
	if hasRule(findings, "BATOU-SH-AST-001") {
		t.Errorf("local PID_FILE via cat-substitution must NOT trigger 001, got %+v", findings)
	}
}

// --- infrastructure / guards ---

func TestSafeScript(t *testing.T) {
	code := "set -euo pipefail\nname=\"world\"\necho \"hello $name\"\ncp \"$src\" \"$dst\"\nls -la /tmp\n"
	findings := scanShell(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe script, got %d: %+v", len(findings), findings)
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/main.go",
		Content:  "package main",
		Language: rules.LangGo,
	}
	a := &ShellASTAnalyzer{}
	if findings := a.Scan(ctx); len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/deploy.sh",
		Content:  "eval $x",
		Language: rules.LangShell,
		Tree:     nil,
	}
	a := &ShellASTAnalyzer{}
	if findings := a.Scan(ctx); len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestAllRuleIDsContainAST(t *testing.T) {
	// Tier classification (scanner/dedup.go) keys AST tier off "AST" in the
	// rule ID; every rule this analyzer emits must contain it.
	code := "f=$1\neval $f\ncp $p /d\nsource $c\nbash -c \"$f\"\n$f go\n"
	for _, f := range scanShell(t, code) {
		if !strings.Contains(f.RuleID, "AST") {
			t.Errorf("rule ID %q must contain \"AST\" for correct tier classification", f.RuleID)
		}
	}
}
