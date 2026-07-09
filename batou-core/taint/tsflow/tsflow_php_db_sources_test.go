package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP database & cache source tests — second-order injection detection
// =========================================================================

// --- WordPress $wpdb sources ---

func TestPHP_Wpdb_GetVar_XSS(t *testing.T) {
	code := `<?php
function show_title() {
    global $wpdb;
    $title = $wpdb->get_var("SELECT post_title FROM wp_posts WHERE ID = 1");
    printf($title);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from $wpdb->get_var() to printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wpdb_GetVar_XSS_Sanitized(t *testing.T) {
	code := `<?php
function show_title() {
    global $wpdb;
    $title = $wpdb->get_var("SELECT post_title FROM wp_posts WHERE ID = 1");
    $safe = htmlspecialchars($title);
    printf($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("htmlspecialchars() should neutralize XSS flow from $wpdb->get_var()")
	}
}

func TestPHP_Wpdb_GetResults_SQLi(t *testing.T) {
	code := `<?php
function search_users($pdo) {
    global $wpdb;
    $name = $wpdb->get_results("SELECT display_name FROM wp_users LIMIT 1");
    $pdo->query("SELECT * FROM wp_posts WHERE author_name = '" . $name . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from $wpdb->get_results() to pdo->query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wpdb_GetRow_Command(t *testing.T) {
	code := `<?php
function process_setting() {
    global $wpdb;
    $path = $wpdb->get_row("SELECT option_value FROM wp_options WHERE option_name = 'backup_path'");
    exec($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from $wpdb->get_row() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Wpdb_GetCol_XSS(t *testing.T) {
	code := `<?php
function list_titles() {
    global $wpdb;
    $titles = $wpdb->get_col("SELECT post_title FROM wp_posts");
    printf($titles);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from $wpdb->get_col() to printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Laravel Eloquent sources ---

func TestPHP_Eloquent_Find_XSS(t *testing.T) {
	code := `<?php
function show_user($id) {
    $user = User::find($id);
    printf($user);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Eloquent find() to printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Eloquent_Find_Sanitized(t *testing.T) {
	code := `<?php
function show_user($id) {
    $user = User::find($id);
    $safe = htmlspecialchars($user);
    printf($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("htmlspecialchars() should neutralize XSS from Eloquent find()")
	}
}

func TestPHP_Eloquent_Pluck_Command(t *testing.T) {
	code := `<?php
function run_script() {
    $script = User::pluck('script_path');
    exec($script);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Eloquent pluck() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Eloquent_FirstWhere_Command(t *testing.T) {
	code := `<?php
function process() {
    $job = Job::firstWhere('status', 'pending');
    system($job);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Eloquent firstWhere() to system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Eloquent_Value_Deser(t *testing.T) {
	code := `<?php
function load_config() {
    $data = Setting::value('serialized_config');
    $config = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from Eloquent value() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Doctrine ORM sources ---

func TestPHP_Doctrine_FindOneBy_Command(t *testing.T) {
	code := `<?php
function run_task() {
    $task = $repository->findOneBy(['status' => 'pending']);
    exec($task);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Doctrine findOneBy() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Doctrine_GetResult_Command(t *testing.T) {
	code := `<?php
function process_jobs() {
    $cmd = $query->getResult();
    exec($cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Doctrine getResult() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Doctrine_FindBy_XSS(t *testing.T) {
	code := `<?php
function list_articles() {
    $articles = $repository->findBy(['published' => true]);
    printf($articles);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Doctrine findBy() to printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Doctrine_GetSingleResult_Deser(t *testing.T) {
	code := `<?php
function load_serialized() {
    $data = $query->getSingleResult();
    $obj = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from Doctrine getSingleResult() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Redis cache sources ---

func TestPHP_Redis_Get_Deserialization(t *testing.T) {
	code := `<?php
function load_cached() {
    $data = $redis->get('user_prefs');
    $obj = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->get() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_HGet_Command(t *testing.T) {
	code := `<?php
function run_cached_cmd() {
    $cmd = $redis->hGet('jobs', 'pending_cmd');
    exec($cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from $redis->hGet() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_List_Deser(t *testing.T) {
	code := `<?php
function process_queue() {
    $item = $redis->lPop('task_queue');
    $task = unserialize($item);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->lPop() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Memcached sources ---

func TestPHP_Memcached_Get_Deserialization(t *testing.T) {
	code := `<?php
function load_session() {
    $data = $memcached->get('session_data');
    $session = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $memcached->get() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MemcacheProc_Get_Deser(t *testing.T) {
	code := `<?php
function load_cached() {
    $data = memcache_get($conn, 'cached_data');
    $obj = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from memcache_get() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- MongoDB sources ---

func TestPHP_MongoDB_FindOne_Command(t *testing.T) {
	code := `<?php
function run_task() {
    $doc = $collection->findOne(['_id' => $id]);
    exec($doc);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from MongoDB findOne() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
