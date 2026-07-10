package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — second-order DB-read sources (data stored on an earlier request and
// read back later). Mirrors the cross-language wave: pymongo/SQLAlchemy
// (python), MongoDB Document (java), NoSQL document DBs (csharp), Jedis/Mongo
// (kotlin), pg_fetch/mysqli/Doctrine (php), libbson (c), mongocxx (cpp).
//
// Ruby already had ActiveRecord/Sequel/pg-exec_params/sqlite3 read sources;
// this adds the conspicuously-missing raw drivers: Mysql2::Client#query,
// PG::Connection#exec/#query/#sync_exec/#exec_prepared, TinyTds::Client#execute,
// and the Mongo::Collection read methods (find/find_one/aggregate/distinct/
// find_one_and_{update,replace,delete}).
//
// Test note: fixtures assign the source call to its own variable first, then
// extract a column with `.to_a[0]["col"]` (chaining transformations directly
// off the source-call sub-expression does not carry taint to the LHS — the
// `__expr__` propagation needs the RHS to be the bare source call). They
// avoid `.first` because the pre-existing `ruby.sequel.dataset.first` entry
// has ObjectType "" (wildcard receiver) and would otherwise taint any `x.first`
// call, masking whether the new entry is the one carrying the taint. Functions
// take no params so seedParams() can't auto-taint anything — the DB read is the
// only taint origin.
// =========================================================================

func TestRuby_DBRead_Mysql2Query_CommandInjection(t *testing.T) {
	code := `
require "mysql2"

def report
  client = Mysql2::Client.new(host: "localhost", database: "app")
  rows = client.query("SELECT note FROM audit_log ORDER BY id DESC")
  note = rows.to_a[0]["note"]
  system("logger " + note)
end
`
	flows := Analyze(code, "/app/jobs/report_job.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mysql2::Client#query result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_PGExec_CommandInjection(t *testing.T) {
	code := `
require "pg"

def show_bio
  conn = PG.connect(dbname: "app")
  res = conn.exec("SELECT bio FROM profiles WHERE id = 1")
  bio = res.to_a[0]["bio"]
  system("echo " + bio)
end
`
	flows := Analyze(code, "/app/services/bio_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from PG::Connection#exec result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_PGQuery_CommandInjection(t *testing.T) {
	code := `
require "pg"

def list_tags
  conn = PG.connect(dbname: "app")
  res = conn.query("SELECT label FROM tags LIMIT 1")
  label = res.to_a[0]["label"]
  system("echo " + label)
end
`
	flows := Analyze(code, "/app/services/tag_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from PG::Connection#query result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_PGSyncExec_CommandInjection(t *testing.T) {
	code := `
require "pg"

def get_setting
  conn = PG.connect(dbname: "app")
  res = conn.sync_exec("SELECT value FROM settings WHERE key = 'theme'")
  val = res.to_a[0]["value"]
  system("apply_theme " + val)
end
`
	flows := Analyze(code, "/app/services/setting_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from PG::Connection#sync_exec result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_PGExecPrepared_CommandInjection(t *testing.T) {
	code := `
require "pg"

def fetch_user
  conn = PG.connect(dbname: "app")
  conn.prepare("get_user", "SELECT name FROM users WHERE id = $1")
  res = conn.exec_prepared("get_user", [1])
  name = res.to_a[0]["name"]
  system("greet " + name)
end
`
	flows := Analyze(code, "/app/services/user_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from PG::Connection#exec_prepared result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_TinyTdsExecute_CommandInjection(t *testing.T) {
	code := `
require "tiny_tds"

def latest_event
  client = TinyTds::Client.new(username: "sa", host: "localhost")
  res = client.execute("SELECT TOP 1 payload FROM events ORDER BY id DESC")
  payload = res.to_a[0]["payload"]
  system("process " + payload)
end
`
	flows := Analyze(code, "/app/services/event_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from TinyTds::Client#execute result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoFind_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def list_posts
  coll = Mongo::Client.new(["localhost:27017"]).use("blog")[:posts]
  cursor = coll.find(published: true)
  docs = cursor.to_a
  system("render " + docs[0]["title"])
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#find result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoFindOne_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def show_user
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  doc = coll.find_one(role: "admin")
  system("audit " + doc["email"])
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#find_one result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoAggregate_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def author_totals
  coll = Mongo::Client.new(["localhost:27017"]).use("blog")[:posts]
  cursor = coll.aggregate([{ "$group" => { "_id" => "$author" } }])
  rows = cursor.to_a
  system("report " + rows[0]["_id"])
end
`
	flows := Analyze(code, "/app/services/stats_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#aggregate result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoDistinct_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def category_index
  coll = Mongo::Client.new(["localhost:27017"]).use("shop")[:products]
  cats = coll.distinct("category")
  system("index " + cats[0])
end
`
	flows := Analyze(code, "/app/services/catalog_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#distinct result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoFindOneAndUpdate_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def claim_job
  coll = Mongo::Client.new(["localhost:27017"]).use("queue")[:jobs]
  doc = coll.find_one_and_update({ status: "pending" }, { "$set" => { status: "claimed" } })
  system("run " + doc["cmd"])
end
`
	flows := Analyze(code, "/app/jobs/worker.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#find_one_and_update result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoFindOneAndReplace_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def swap_record
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:configs]
  doc = coll.find_one_and_replace({ name: "active" }, { name: "active", cmd: "default" })
  system("apply " + doc["cmd"])
end
`
	flows := Analyze(code, "/app/services/config_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#find_one_and_replace result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DBRead_MongoFindOneAndDelete_CommandInjection(t *testing.T) {
	code := `
require "mongo"

def pop_task
  coll = Mongo::Client.new(["localhost:27017"]).use("queue")[:tasks]
  doc = coll.find_one_and_delete({ ready: true })
  system("exec " + doc["script"])
end
`
	flows := Analyze(code, "/app/jobs/task_runner.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Mongo::Collection#find_one_and_delete result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// --- Negative controls ---

// Shellwords.escape() neutralizes SnkCommand — a DB-read value passed through
// it should not produce a high-confidence command-injection flow.
func TestRuby_DBRead_Mysql2Query_Sanitized_NoFlow(t *testing.T) {
	code := `
require "mysql2"
require "shellwords"

def safe_report
  client = Mysql2::Client.new(host: "localhost", database: "app")
  rows = client.query("SELECT note FROM audit_log")
  note = rows.to_a[0]["note"]
  safe = Shellwords.escape(note)
  system(safe)
end
`
	flows := Analyze(code, "/app/jobs/safe_report_job.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("should not detect high-confidence command injection when Shellwords.escape sanitizes the DB-read value (conf %.2f, sink %s)", f.Confidence, f.Sink.ID)
		}
	}
}

// The new sources must not taint unrelated literals: a DB-read value that is
// fetched but never reaches a sink (sink arg is a constant) must not flag.
func TestRuby_DBRead_ConstantSinkArg_NoFlow(t *testing.T) {
	code := `
require "pg"

def safe_query
  conn = PG.connect(dbname: "app")
  res = conn.exec("SELECT COUNT(*) AS n FROM users")
  count = res.to_a[0]["n"]
  system("echo static-message")
end
`
	flows := Analyze(code, "/app/services/count_service.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command injection flow: the system() argument is a constant, not the DB-read value")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// --- Registration check ---

func TestRuby_DBRead_SourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangRuby)
	if cat == nil {
		t.Fatal("Ruby catalog not loaded")
	}
	cats := map[string]taint.SourceCategory{}
	for _, s := range cat.Sources() {
		cats[s.ID] = s.Category
	}
	want := []string{
		"ruby.pg.exec.result",
		"ruby.pg.query.result",
		"ruby.pg.sync_exec.result",
		"ruby.pg.exec_prepared.result",
		"ruby.mysql2.query.result",
		"ruby.tiny_tds.execute.result",
		"ruby.mongo.collection.find.result",
		"ruby.mongo.collection.find_one.result",
		"ruby.mongo.collection.aggregate.result",
		"ruby.mongo.collection.distinct.result",
		"ruby.mongo.collection.find_one_and_update.result",
		"ruby.mongo.collection.find_one_and_replace.result",
		"ruby.mongo.collection.find_one_and_delete.result",
	}
	for _, id := range want {
		c, ok := cats[id]
		if !ok {
			t.Errorf("missing expected Ruby source: %s", id)
			continue
		}
		if c != taint.SrcDatabase {
			t.Errorf("source %s: expected category SrcDatabase, got %v", id, c)
		}
	}
}
