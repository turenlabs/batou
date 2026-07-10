package javaast

import "testing"

// TestProcessBuilderConstructorCommandInjection covers the construction-side
// command-injection sink that the javaast analyzer previously left uncovered:
// `new ProcessBuilder(...)` whose command list contains a string concatenation
// embedding a non-literal value. Before the fix, only Runtime.exec() was wired,
// so the idiomatic ping helper pattern (controller @RequestParam -> private
// helper -> ProcessBuilder over a concatenated argument, as in
// SasanLabs/VulnerableApp CommandInjection.java) produced no AST-tier finding.
//
// The check is deliberately scoped to the in-constructor concatenation form.
// A bare variable / List argument is NOT flagged structurally (the OWASP
// Benchmark cmdi corpus uses `pb.command(argList)` / `new ProcessBuilder(list)`
// for BOTH its vulnerable and its safe cases, so firing on the bare-list shape
// floods false positives) — those are left to the dataflow tier. The negative
// assertions below pin that scope so it cannot silently widen.
func TestProcessBuilderConstructorCommandInjection(t *testing.T) {
	// POSITIVE — VulnerableApp idiom: a concatenation inside the String[] passed
	// to the ProcessBuilder constructor, in a helper whose argument is tainted.
	vulnArray := `
class Handler {
    StringBuilder run(String ipAddress) throws Exception {
        Process process =
                new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 " + ipAddress})
                        .redirectErrorStream(true)
                        .start();
        return new StringBuilder();
    }
}
`
	if f := findByRule(scanJava(vulnArray), "BATOU-JAVAAST-002"); f == nil {
		t.Fatalf("expected BATOU-JAVAAST-002 for ProcessBuilder over String[] concat, got none")
	} else if f.CWEID != "CWE-78" {
		t.Fatalf("expected CWE-78, got %q", f.CWEID)
	}

	// POSITIVE — varargs form with a concatenated argument.
	vulnVarargs := `
class Handler {
    void run(String ip) throws Exception {
        new ProcessBuilder("sh", "-c", "ping " + ip).start();
    }
}
`
	if findByRule(scanJava(vulnVarargs), "BATOU-JAVAAST-002") == nil {
		t.Fatalf("expected BATOU-JAVAAST-002 for ProcessBuilder varargs concat, got none")
	}

	// NEGATIVE — an all-literal command list has no injection vector and must NOT
	// fire. This is what keeps the construction check from flooding on benign
	// fixed-command ProcessBuilder usage.
	safeLiterals := `
class Handler {
    void run() throws Exception {
        new ProcessBuilder("ls", "-l").start();
    }
}
`
	if f := findByRule(scanJava(safeLiterals), "BATOU-JAVAAST-002"); f != nil {
		t.Fatalf("did not expect BATOU-JAVAAST-002 for an all-literal ProcessBuilder, got line %d", f.LineNumber)
	}

	// NEGATIVE — array of only string literals — also safe.
	safeArray := `
class Handler {
    void run() throws Exception {
        new ProcessBuilder(new String[] {"ls", "-l", "/tmp"}).start();
    }
}
`
	if f := findByRule(scanJava(safeArray), "BATOU-JAVAAST-002"); f != nil {
		t.Fatalf("did not expect BATOU-JAVAAST-002 for an all-literal String[] ProcessBuilder, got line %d", f.LineNumber)
	}

	// NEGATIVE (scope pin) — a bare List variable passed to the constructor is
	// intentionally NOT flagged structurally; whether the list is tainted is a
	// dataflow question. This mirrors the OWASP cmdi safe-case idiom and must
	// stay out of the AST tier to avoid a false-positive flood.
	bareList := `
class Handler {
    void run(java.util.List<String> argList) throws Exception {
        new ProcessBuilder(argList).start();
    }
}
`
	if f := findByRule(scanJava(bareList), "BATOU-JAVAAST-002"); f != nil {
		t.Fatalf("did not expect BATOU-JAVAAST-002 for a bare-List ProcessBuilder (dataflow-tier concern), got line %d", f.LineNumber)
	}

	// NEGATIVE (scope pin) — pb.command(list) re-set is likewise left to dataflow.
	commandList := `
class Handler {
    void run(java.util.List<String> argList) throws Exception {
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        pb.start();
    }
}
`
	if f := findByRule(scanJava(commandList), "BATOU-JAVAAST-002"); f != nil {
		t.Fatalf("did not expect BATOU-JAVAAST-002 for pb.command(list) (dataflow-tier concern), got line %d", f.LineNumber)
	}
}
