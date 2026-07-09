package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// WordPress REST API source tests — WP_REST_Request snake_case getters.
// REST handlers receive a WP_REST_Request whose get_param/get_json_params/
// get_url_params/etc. expose user-controlled HTTP request data. Real CVEs:
// CVE-2023-32243 (Essential Addons), CVE-2024-2876, CVE-2023-25132 — all
// flow get_param/get_json_params into wpdb queries or eval/wp_remote_get.
// =========================================================================

func TestPHP_WPRESTRequest_GetParam_SQLInjection(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    global $wpdb;
    $term = $request->get_param('term');
    return $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $term . "%'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for WP_REST_Request::get_param -> wpdb->get_results")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetJsonParams_CommandInjection(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    $data = $request->get_json_params();
    $cmd = $data['cmd'];
    exec("convert " . $cmd);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for WP_REST_Request::get_json_params -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetQueryParams_SQLInjection(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    global $wpdb;
    $params = $request->get_query_params();
    $author = $params['author'];
    return $wpdb->get_var("SELECT COUNT(*) FROM wp_posts WHERE post_author = " . $author);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for WP_REST_Request::get_query_params -> wpdb->get_var")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetUrlParams_SQLInjection(t *testing.T) {
	// Route registered as /wp-json/myplugin/v1/users/(?P<id>\d+)
	code := `<?php
function batou_handler($request) {
    global $wpdb;
    $params = $request->get_url_params();
    $id = $params['id'];
    return $wpdb->get_row("SELECT * FROM wp_users WHERE ID = " . $id);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for WP_REST_Request::get_url_params -> wpdb->get_row")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetBodyParams_SQLInjection(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    global $wpdb;
    $body = $request->get_body_params();
    $status = $body['status'];
    return $wpdb->get_col("SELECT post_title FROM wp_posts WHERE post_status = '" . $status . "'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for WP_REST_Request::get_body_params -> wpdb->get_col")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetHeader_CommandInjection(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    $ua = $request->get_header('User-Agent');
    exec("logger " . $ua);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for WP_REST_Request::get_header -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetHeaders_CommandInjection(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    $headers = $request->get_headers();
    exec("logger " . $headers['x-forwarded-for'][0]);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for WP_REST_Request::get_headers -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetBody_Eval(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    $body = $request->get_body();
    eval($body);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for WP_REST_Request::get_body -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_WPRESTRequest_GetFileParams_FileSink(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    $files = $request->get_file_params();
    $path = $files['attachment']['tmp_name'];
    file_put_contents("/var/www/uploads/" . $files['attachment']['name'], file_get_contents($path));
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow for WP_REST_Request::get_file_params -> file_put_contents")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Receiver-name variation: $req short form should also be tainted ---

func TestPHP_WPRESTRequest_ShortReceiver_GetParam_SQLInjection(t *testing.T) {
	code := `<?php
function batou_handler($req) {
    global $wpdb;
    $term = $req->get_param('q');
    return $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title = '" . $term . "'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for short receiver $req->get_param -> wpdb->get_results")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Safe path: WordPress sanitizer between source and sink ---

func TestPHP_WPRESTRequest_GetParam_EscSQL_Sanitized(t *testing.T) {
	code := `<?php
function batou_handler($request) {
    global $wpdb;
    $term = esc_sql($request->get_param('term'));
    return $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title = '" . $term . "'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL flow when esc_sql() sanitizes get_param result")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
