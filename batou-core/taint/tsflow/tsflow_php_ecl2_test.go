package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// ECL2 PHP coverage-breadth cleanup wave — four framework detection
// categories closed via taint catalog entries:
//
//   1. Symfony ExpressionLanguage injection (CWE-94/917) — sink
//   2. Symfony Yaml::parse object-injection deserialization (CWE-502) — sink
//   3. Doctrine QueryBuilder where()/having() string injection (CWE-89) — sink
//   4. WordPress add_query_arg()/remove_query_arg() reflected XSS (CWE-79) — source
//
// Each category has a tainted (TP) case that must produce a flow and a
// safe/sanitized case that must stay clean.
// =========================================================================

// --- 1. Symfony ExpressionLanguage injection ---------------------------------

func TestPHP_ECL2_ExpressionLanguage_Evaluate_Tainted(t *testing.T) {
	code := `<?php
function check($request) {
    $expr = $request->get("expr");
    $expressionLanguage = new ExpressionLanguage();
    return $expressionLanguage->evaluate($expr);
}
?>`
	flows := Analyze(code, "/app/Voter.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for Symfony Request -> ExpressionLanguage::evaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_ECL2_ExpressionLanguage_Compile_Tainted(t *testing.T) {
	code := `<?php
function build() {
    $raw = $_GET["e"];
    $el = new ExpressionLanguage();
    $code = $el->compile($raw);
    return $code;
}
?>`
	flows := Analyze(code, "/app/compile.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for $_GET -> ExpressionLanguage::compile")
	}
}

func TestPHP_ECL2_ExpressionLanguage_StaticExpr_Safe(t *testing.T) {
	code := `<?php
function check() {
    $expressionLanguage = new ExpressionLanguage();
    return $expressionLanguage->evaluate("user.isAdmin() and user.isActive()");
}
?>`
	flows := Analyze(code, "/app/Voter.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("static, developer-authored expression must not flag as EL injection (sink=%s)", f.Sink.MethodName)
		}
	}
}

// --- 2. Symfony Yaml::parse object-injection deserialization -----------------

func TestPHP_ECL2_SymfonyYaml_Parse_Tainted(t *testing.T) {
	code := `<?php
function load($request) {
    $body = $request->getContent();
    $config = Yaml::parse($body, Yaml::PARSE_OBJECT);
    return $config;
}
?>`
	flows := Analyze(code, "/app/Loader.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-502") {
		t.Error("expected CWE-502 deserialization flow for Symfony Request -> Yaml::parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_ECL2_SymfonyYaml_Parse_StaticString_Safe(t *testing.T) {
	code := `<?php
function load() {
    $config = Yaml::parse("name: app\nversion: 1.0");
    return $config;
}
?>`
	flows := Analyze(code, "/app/Loader.php", rules.LangPHP)
	for _, f := range flows {
		// A static literal YAML string carries no taint, so no source->sink
		// deserialization flow should be recorded.
		if f.Sink.CWEID == "CWE-502" && f.Sink.MethodName == "parse/parseFile" {
			t.Error("static literal YAML string must not flag as Yaml::parse object injection")
		}
	}
}

// --- 3. Doctrine QueryBuilder where()/having() string injection --------------

func TestPHP_ECL2_DoctrineQueryBuilder_Where_Tainted(t *testing.T) {
	code := `<?php
function find($request, $qb) {
    $name = $request->query->get("name");
    $qb->where("u.name = '" . $name . "'");
    return $qb->getQuery()->getResult();
}
?>`
	flows := Analyze(code, "/app/Repo.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for Symfony Request -> Doctrine QueryBuilder::where (concatenated fragment)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_ECL2_DoctrineQueryBuilder_AndWhere_Tainted(t *testing.T) {
	code := `<?php
function find($qb) {
    $id = $_GET["id"];
    $qb->andWhere("u.id = " . $id);
    return $qb;
}
?>`
	flows := Analyze(code, "/app/Repo.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for $_GET -> Doctrine QueryBuilder::andWhere")
	}
}

func TestPHP_ECL2_DoctrineQueryBuilder_SetParameter_Safe(t *testing.T) {
	code := `<?php
function find($request, $qb) {
    $name = $request->query->get("name");
    $qb->where("u.name = :name");
    $qb->setParameter("name", $name);
    return $qb->getQuery()->getResult();
}
?>`
	flows := Analyze(code, "/app/Repo.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("placeholder + setParameter binding must not flag as SQLi (sink=%s)", f.Sink.MethodName)
		}
	}
}

// Nextcloud/Doctrine expression-builder idiom: where() with $qb->expr() and
// createNamedParameter() binds the value out-of-band. Must NOT flag even when
// receiver-taint reaches $qb across methods (the real-repo FP this gate fixes).
func TestPHP_ECL2_DoctrineQueryBuilder_ExprNamedParam_Safe(t *testing.T) {
	code := `<?php
function getByEvent($request, $qb) {
    $event = $request->query->get("event");
    $qb->select('*')
        ->from('webhook_listeners')
        ->where($qb->expr()->eq('event', $qb->createNamedParameter($event, IQueryBuilder::PARAM_STR)));
    $qb->andWhere($qb->expr()->emptyString('user_id_filter'));
    return $qb->executeQuery();
}
?>`
	flows := Analyze(code, "/app/Db/WebhookListenerMapper.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ObjectType == "QueryBuilder" {
			t.Errorf("expr()->eq + createNamedParameter binding must not flag as QueryBuilder SQLi (sink=%s)", f.Sink.MethodName)
		}
	}
}

// --- 4. WordPress add_query_arg()/remove_query_arg() reflected XSS -----------

func TestPHP_ECL2_WordPress_AddQueryArg_Echoed_Tainted(t *testing.T) {
	code := `<?php
function render() {
    $url = add_query_arg("paged", 2);
    echo $url;
}
?>`
	flows := Analyze(code, "/wp-content/plugins/x/render.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected reflected-XSS flow for add_query_arg() -> echo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_ECL2_WordPress_RemoveQueryArg_Echoed_Tainted(t *testing.T) {
	code := `<?php
function render() {
    $url = remove_query_arg("filter");
    print $url;
}
?>`
	flows := Analyze(code, "/wp-content/plugins/x/render.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected reflected-XSS flow for remove_query_arg() -> print")
	}
}

func TestPHP_ECL2_WordPress_AddQueryArg_EscUrl_Safe(t *testing.T) {
	code := `<?php
function render() {
    $url = esc_url(add_query_arg("paged", 2));
    echo $url;
}
?>`
	flows := Analyze(code, "/wp-content/plugins/x/render.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("esc_url(add_query_arg(...)) must not flag as reflected XSS (sink=%s)", f.Sink.MethodName)
		}
	}
}
