package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP Drupal 10+ taint flow tests
// =========================================================================

// --- Sources: FormState ---

func TestPHP_Drupal_FormState_GetValue_SQLInjection(t *testing.T) {
	code := `<?php
use Drupal\Core\Form\FormStateInterface;

function submitForm(array &$form, FormStateInterface $form_state) {
    $name = $form_state->getValue('name');
    $db = \Drupal::database();
    $db->query("SELECT * FROM users WHERE name = '" . $name . "'");
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Form/MyForm.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Drupal FormState::getValue -> query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_FormState_GetValues_CommandInjection(t *testing.T) {
	code := `<?php
use Drupal\Core\Form\FormStateInterface;

function submitForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $cmd = $values['command'];
    exec($cmd);
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Form/MyForm.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Drupal FormState::getValues -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_FormState_GetUserInput_SQLInjection(t *testing.T) {
	code := `<?php
use Drupal\Core\Form\FormStateInterface;

function submitForm(array &$form, FormStateInterface $form_state) {
    $raw = $form_state->getUserInput();
    $search = $raw['search'];
    db_query("SELECT * FROM node WHERE title LIKE '%" . $search . "%'");
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Form/SearchForm.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Drupal FormState::getUserInput -> db_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Sinks ---

func TestPHP_Drupal_DbQuery_SQLInjection(t *testing.T) {
	code := `<?php
function loadUser() {
    $name = $_GET['name'];
    db_query("SELECT * FROM users WHERE name = '" . $name . "'");
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/mymodule.module", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_GET -> db_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_DatabaseQuery_SQLInjection(t *testing.T) {
	code := `<?php
function searchNodes() {
    $search = $_POST['search'];
    $connection = \Drupal::database();
    $connection->query("SELECT nid FROM node WHERE title = '" . $search . "'");
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/mymodule.module", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_POST -> $connection->query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_MarkupCreate_XSS(t *testing.T) {
	code := `<?php
use Drupal\Core\Render\Markup;

function renderMessage() {
    $input = $_GET['msg'];
    $markup = Markup::create('<div>' . $input . '</div>');
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Controller/MyController.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for $_GET -> Markup::create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_DbSelect_SQLInjection(t *testing.T) {
	code := `<?php
function listItems() {
    $table = $_GET['table'];
    db_select($table)->fields('n', array('nid', 'title'))->execute();
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/mymodule.module", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_GET -> db_select (tainted table name)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Sanitizers ---

func TestPHP_Drupal_XssFilter_Sanitized(t *testing.T) {
	code := `<?php
use Drupal\Component\Utility\Xss;

function renderComment() {
    $input = $_GET['comment'];
    $safe = Xss::filter($input);
    echo $safe;
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Controller/MyController.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("Xss::filter should sanitize XSS — no SnkHTMLOutput flow expected")
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_XssFilterAdmin_Sanitized(t *testing.T) {
	code := `<?php
use Drupal\Component\Utility\Xss;

function renderBody() {
    $input = $_GET['body'];
    $safe = Xss::filterAdmin($input);
    echo $safe;
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Controller/AdminController.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("Xss::filterAdmin should sanitize XSS — no SnkHTMLOutput flow expected")
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_HtmlEscape_Sanitized(t *testing.T) {
	code := `<?php
use Drupal\Component\Utility\Html;

function renderTitle() {
    $input = $_GET['title'];
    $safe = Html::escape($input);
    echo $safe;
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Controller/MyController.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("Html::escape should sanitize XSS — no SnkHTMLOutput flow expected")
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_UrlHelper_FilterBadProtocol_Sanitized(t *testing.T) {
	code := `<?php
use Drupal\Component\Utility\UrlHelper;

function doRedirect() {
    $url = $_GET['redirect'];
    $safe = UrlHelper::filterBadProtocol($url);
    header("Location: " . $safe);
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Controller/RedirectController.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("UrlHelper::filterBadProtocol should sanitize redirect — no SnkRedirect flow expected")
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Drupal_UrlHelper_StripDangerousProtocols_Sanitized(t *testing.T) {
	code := `<?php
use Drupal\Component\Utility\UrlHelper;

function doLink() {
    $url = $_GET['link'];
    $safe = UrlHelper::stripDangerousProtocols($url);
    header("Location: " . $safe);
}
?>`
	flows := Analyze(code, "/app/modules/custom/mymodule/src/Controller/LinkController.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("UrlHelper::stripDangerousProtocols should sanitize redirect — no SnkRedirect flow expected")
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
