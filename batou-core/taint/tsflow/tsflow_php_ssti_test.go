package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP SSTI tests — Twig createTemplate/display, Blade compileString,
// View::make, Nette Latte renderToString.
// =========================================================================

func TestPHP_SSTI_Twig_CreateTemplate_Tainted(t *testing.T) {
	code := `<?php
function handler() {
    $tpl = $_POST["tpl"];
    $twig = new Twig\Environment($loader);
    $template = $twig->createTemplate($tpl);
    echo $template->render([]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for $_POST -> Twig Environment::createTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSTI_Twig_CreateTemplate_StaticString_Safe(t *testing.T) {
	code := `<?php
function handler() {
    $twig = new Twig\Environment($loader);
    $template = $twig->createTemplate("Hello {{ name }}");
    echo $template->render(["name" => "world"]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("static template string should not trigger SSTI")
	}
}

func TestPHP_SSTI_Twig_Display_TaintedName(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_GET["view"];
    $twig = new Twig\Environment($loader);
    $twig->display($name, []);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for $_GET -> Twig Environment::display")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSTI_Blade_CompileString_Tainted(t *testing.T) {
	code := `<?php
function handler() {
    $tpl = $_REQUEST["tpl"];
    $compiled = Blade::compileString($tpl);
    echo eval("?>" . $compiled);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for $_REQUEST -> Blade::compileString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSTI_LaravelView_Make_TaintedName(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_GET["page"];
    return View::make($name, ["user" => "alice"]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI/template-name-injection flow for $_GET -> View::make")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSTI_LaravelView_Make_StaticName_Safe(t *testing.T) {
	code := `<?php
function handler() {
    return View::make("home", ["user" => "alice"]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("static view name should not trigger SSTI")
	}
}

func TestPHP_SSTI_Latte_RenderToString_Tainted(t *testing.T) {
	code := `<?php
function handler() {
    $path = $_GET["tpl"];
    $latte = new Latte\Engine();
    $html = $latte->renderToString($path, ["title" => "hi"]);
    echo $html;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for $_GET -> Latte Engine::renderToString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
