package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// PHP unsafe-reflection (CWE-470) sinks: ReflectionClass::newInstance and
// ReflectionMethod/ReflectionFunction::invoke fire only when the reflected
// class/method name traces to a request source, and never when the name is a
// fixed literal (the safe idiom).

func TestPHP_ReflectionClass_TaintedName_Fires(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_GET["class"];
    $ref = new ReflectionClass($name);
    $obj = $ref->newInstance();
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-470") {
		t.Error("expected CWE-470 flow: $_GET -> ReflectionClass -> newInstance")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_ReflectionClass_LiteralName_NoFire(t *testing.T) {
	code := `<?php
function handler() {
    $ref = new ReflectionClass(UserService::class);
    $obj = $ref->newInstance();
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-470") {
		t.Error("unexpected CWE-470 flow on a fixed literal class name (safe idiom)")
	}
}

func TestPHP_ReflectionMethod_FixedName_NoFire(t *testing.T) {
	code := `<?php
function handler() {
    $rm = new ReflectionMethod('App\\Service', 'run');
    $rm->invoke($svc);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-470") {
		t.Error("unexpected CWE-470 flow on a fixed method name (safe idiom)")
	}
}
