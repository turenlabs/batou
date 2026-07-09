package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// WordPress taint sinks — wpdb read helpers (SQLi), wp_mail (header
// injection), and template loaders (LFI). Every new sink must have a
// vulnerable + safe test here.
// =========================================================================

func TestPHP_Wordpress_WpdbGetVar(t *testing.T) {
	code := `<?php
function fetch_count() {
    global $wpdb;
    $term = $_GET["term"];
    return $wpdb->get_var("SELECT COUNT(*) FROM wp_posts WHERE post_title LIKE '%" . $term . "%'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for $_GET -> wpdb->get_var")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_WpdbGetRow(t *testing.T) {
	code := `<?php
function fetch_user() {
    global $wpdb;
    $id = $_POST["user_id"];
    return $wpdb->get_row("SELECT * FROM wp_users WHERE ID = " . $id);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for $_POST -> wpdb->get_row")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_WpdbGetCol(t *testing.T) {
	code := `<?php
function fetch_titles() {
    global $wpdb;
    $status = $_REQUEST["status"];
    return $wpdb->get_col("SELECT post_title FROM wp_posts WHERE post_status = '" . $status . "'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for $_REQUEST -> wpdb->get_col")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_WpMail(t *testing.T) {
	code := `<?php
function send_notification() {
    $recipient = $_POST["email"];
    wp_mail($recipient, "Welcome", "Thanks for signing up.");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for $_POST -> wp_mail")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_LoadTemplate(t *testing.T) {
	code := `<?php
function render_page() {
    $template = $_GET["view"];
    load_template($template);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected LFI flow for $_GET -> load_template")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_LocateTemplate(t *testing.T) {
	code := `<?php
function render() {
    $slug = $_GET["slug"];
    locate_template($slug, true, false);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected LFI flow for $_GET -> locate_template")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_GetTemplatePart(t *testing.T) {
	code := `<?php
function render_part() {
    $slug = $_GET["part"];
    get_template_part($slug);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected LFI flow for $_GET -> get_template_part")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// WordPress sanitizers — each should neutralize taint for its category.
// =========================================================================

func TestPHP_Wordpress_Sanitizer_EscJs(t *testing.T) {
	code := `<?php
function render_inline() {
    $name = $_GET["name"];
    $safe = esc_js($name);
    echo "<script>var user = '" . $safe . "';</script>";
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("esc_js() should neutralize XSS taint for echo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_Sanitizer_WpdbEscLike(t *testing.T) {
	code := `<?php
function search_posts() {
    global $wpdb;
    $term = $_GET["term"];
    $like = $wpdb->esc_like($term);
    return $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $like . "%'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("wpdb->esc_like() should neutralize SQL taint for get_results")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_Sanitizer_SanitizeKey(t *testing.T) {
	code := `<?php
function load_setting() {
    global $wpdb;
    $key = $_GET["key"];
    $safe = sanitize_key($key);
    return $wpdb->get_var("SELECT option_value FROM wp_options WHERE option_name = '" . $safe . "'");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("sanitize_key() should neutralize SQL taint for wpdb->get_var")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe variants — hardcoded inputs should not produce flows.

func TestPHP_Wordpress_WpMail_HardcodedRecipient(t *testing.T) {
	code := `<?php
function alert_admin() {
    wp_mail("admin@example.com", "Alert", "Something happened.");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("hardcoded recipient in wp_mail should not produce header flow")
	}
}

func TestPHP_Wordpress_LoadTemplate_HardcodedPath(t *testing.T) {
	code := `<?php
function render_home() {
    load_template(get_template_directory() . "/home.php");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("hardcoded path in load_template should not produce file-read flow")
	}
}

// =========================================================================
// WordPress HTTP API SSRF sinks — wp_remote_*() and download_url() do NOT
// validate the target host against private/loopback ranges. The
// wp_safe_remote_*() variants do (and are registered as sanitizers).
// Real-world examples: CVE-2024-1071, CVE-2023-48329.
// =========================================================================

func TestPHP_Wordpress_WpRemoteGet_SSRF(t *testing.T) {
	code := `<?php
function fetch_remote() {
    $url = $_GET["url"];
    return wp_remote_get($url);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_GET -> wp_remote_get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_WpRemotePost_SSRF(t *testing.T) {
	code := `<?php
function post_remote() {
    $endpoint = $_POST["endpoint"];
    return wp_remote_post($endpoint, array("body" => "ping"));
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_POST -> wp_remote_post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_WpRemoteRequest_SSRF(t *testing.T) {
	code := `<?php
function call_remote() {
    $target = $_REQUEST["target"];
    return wp_remote_request($target, array("method" => "PUT"));
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_REQUEST -> wp_remote_request")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_WpRemoteHead_SSRF(t *testing.T) {
	code := `<?php
function head_remote() {
    $url = $_GET["probe"];
    return wp_remote_head($url);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_GET -> wp_remote_head")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_DownloadUrl_SSRF(t *testing.T) {
	code := `<?php
function fetch_to_temp() {
    $url = $_POST["asset_url"];
    return download_url($url, 60);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_POST -> download_url")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Sanitizer cases — wp_safe_remote_*() should neutralize SSRF taint.

func TestPHP_Wordpress_Sanitizer_WpSafeRemoteRequest(t *testing.T) {
	code := `<?php
function call_remote_safe() {
    $target = $_REQUEST["target"];
    return wp_safe_remote_request($target, array("method" => "GET"));
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("wp_safe_remote_request() should neutralize SSRF taint")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wordpress_Sanitizer_WpSafeRemoteHead(t *testing.T) {
	code := `<?php
function head_remote_safe() {
    $url = $_GET["probe"];
    return wp_safe_remote_head($url);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("wp_safe_remote_head() should neutralize SSRF taint")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe variants — hardcoded URLs should not produce SSRF flows.

func TestPHP_Wordpress_WpRemoteGet_HardcodedURL(t *testing.T) {
	code := `<?php
function ping_api() {
    return wp_remote_get("https://api.example.com/status");
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("hardcoded URL in wp_remote_get should not produce SSRF flow")
	}
}

func TestPHP_Wordpress_DownloadUrl_HardcodedURL(t *testing.T) {
	code := `<?php
function fetch_known_asset() {
    return download_url("https://cdn.example.com/asset.zip", 60);
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("hardcoded URL in download_url should not produce SSRF flow")
	}
}
