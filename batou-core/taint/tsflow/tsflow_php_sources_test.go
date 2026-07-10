package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP source tests — PSR-7, CakePHP, Yii2, superglobals, Laravel additional
// =========================================================================

// --- PSR-7 ServerRequestInterface ---

func TestPHP_PSR7_GetParsedBody_SQLInjection(t *testing.T) {
	code := `<?php
function handle($request) {
    $data = $request->getParsedBody();
    $name = $data['name'];
    $db->query("SELECT * FROM users WHERE name = '" . $name . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for PSR-7 getParsedBody -> query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_PSR7_GetQueryParams_CommandInjection(t *testing.T) {
	code := `<?php
function handle($request) {
    $params = $request->getQueryParams();
    $host = $params['host'];
    exec("ping " . $host);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PSR-7 getQueryParams -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_PSR7_GetCookieParams_CommandInjection(t *testing.T) {
	code := `<?php
function handle($request) {
    $cookies = $request->getCookieParams();
    exec($cookies);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PSR-7 getCookieParams -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_PSR7_GetHeaderLine_CommandInjection(t *testing.T) {
	code := `<?php
function handle($request) {
    $ua = $request->getHeaderLine('User-Agent');
    exec($ua);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PSR-7 getHeaderLine -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_PSR7_GetUploadedFiles_CommandInjection(t *testing.T) {
	code := `<?php
function handle($request) {
    $files = $request->getUploadedFiles();
    exec($files);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PSR-7 getUploadedFiles -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_PSR7_GetServerParams_CommandInjection(t *testing.T) {
	code := `<?php
function handle($request) {
    $server = $request->getServerParams();
    exec($server);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PSR-7 getServerParams -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- CakePHP ---

func TestPHP_CakePHP_GetData_SQLInjection(t *testing.T) {
	code := `<?php
function add($request) {
    $name = $request->getData('name');
    $db->query("INSERT INTO users (name) VALUES ('" . $name . "')");
}
?>`
	flows := Analyze(code, "/app/controller.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for CakePHP getData -> query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_CakePHP_GetQuery_CommandInjection(t *testing.T) {
	code := `<?php
function search($request) {
    $q = $request->getQuery('q');
    exec($q);
}
?>`
	flows := Analyze(code, "/app/controller.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for CakePHP getQuery -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_CakePHP_GetCookie_CommandInjection(t *testing.T) {
	code := `<?php
function handler($request) {
    $token = $request->getCookie('session');
    exec($token);
}
?>`
	flows := Analyze(code, "/app/controller.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for CakePHP getCookie -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Yii2 ---

func TestPHP_Yii2_RequestGet_CommandInjection(t *testing.T) {
	code := `<?php
function actionPing() {
    $host = Yii::$app->request->get('host');
    system("ping -c 1 " . $host);
}
?>`
	flows := Analyze(code, "/app/controller.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Yii2 request->get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Yii2_RequestPost_SQLInjection(t *testing.T) {
	code := `<?php
function actionCreate() {
    $email = Yii::$app->request->post('email');
    $db->query("SELECT * FROM users WHERE email = '" . $email . "'");
}
?>`
	flows := Analyze(code, "/app/controller.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Yii2 request->post -> query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Additional superglobals ---

func TestPHP_Session_SQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $username = $_SESSION['username'];
    $db->query("SELECT * FROM logs WHERE user = '" . $username . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_SESSION -> query (second-order)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Laravel additional ---

func TestPHP_Laravel_RequestPath_CommandInjection(t *testing.T) {
	code := `<?php
function handler($request) {
    $path = $request->path();
    exec($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Laravel request->path -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Laravel_RequestSegment_SQLInjection(t *testing.T) {
	code := `<?php
function handler($request) {
    $slug = $request->segment(2);
    $db->query("SELECT * FROM pages WHERE slug = '" . $slug . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Laravel request->segment -> query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Laravel_RequestIp_CommandInjection(t *testing.T) {
	code := `<?php
function handler($request) {
    $ip = $request->ip();
    exec("ping " . $ip);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Laravel request->ip -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
