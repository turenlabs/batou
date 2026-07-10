package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Mojo::Pg::Results / Mojo::mysql::Results / Mojo::SQLite::Results
// + MongoDB::Cursor second-order DB-read sources.
//
// Perl previously modeled DBI fetchrow_* / Redis read / memcached get /
// LWP / Kafka / RabbitMQ / Paws S3-SQS as second-order sources, but the
// Mojolicious DB result iterator family (hash/hashes/array/arrays) and
// the MongoDB::Cursor read methods (next/all) were missing. Values
// previously stored by an untrusted user via a Mojo or MongoDB write
// endpoint were therefore not flagged when later concatenated into a
// command/SQL/eval/HTML sink.
//
// Mirrors the in-flight cross-language second-order DB-read source wave:
// groovy JdbcTemplate / MyBatis (PR #768), lua SQLite (PR #766), rust
// MongoDB aggregate (PR #765), go DynamoDB (PR #763), swift SQLite.swift /
// MongoSwift (PR #762), ruby Mysql2/PG/MongoDB (PR #760), cpp MySQL
// Connector / mongocxx (PR #758), c libbson (PR #756), php pg_fetch /
// Doctrine DBAL (PR #753), kotlin Jedis + MongoDB (PR #749), csharp NoSQL
// (PR #748), python SQLAlchemy + pymongo (PR #736), javascript
// node-redis / ioredis (PR #728).
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// ---- Mojo::Pg::Results -------------------------------------------------

func TestPerl_MojoPg_Results_Hash_SecondOrder_Command(t *testing.T) {
	code := `
use Mojo::Pg;
sub handler {
    my $pg = Mojo::Pg->new('postgresql://localhost/app');
    my $results = $pg->db->query('SELECT name FROM users WHERE id = ?', 1);
    my $row = $results->hash;
    return system("echo " . $row);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $results->hash -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_MojoPg_Results_Hashes_SecondOrder_Command(t *testing.T) {
	code := `
use Mojo::Pg;
sub handler {
    my $pg = Mojo::Pg->new('postgresql://localhost/app');
    my $results = $pg->db->query('SELECT name FROM users');
    my $rows = $results->hashes;
    return system("/usr/bin/run " . $rows);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $results->hashes -> system")
	}
}

func TestPerl_MojoPg_Results_Array_SecondOrder_Command(t *testing.T) {
	code := `
use Mojo::Pg;
sub handler {
    my $pg = Mojo::Pg->new('postgresql://localhost/app');
    my $results = $pg->db->query('SELECT name FROM users WHERE id = ?', 1);
    my $row = $results->array;
    return system("echo " . $row);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $results->array -> system")
	}
}

func TestPerl_MojoPg_Results_Arrays_SecondOrder_Command(t *testing.T) {
	code := `
use Mojo::Pg;
sub handler {
    my $pg = Mojo::Pg->new('postgresql://localhost/app');
    my $results = $pg->db->query('SELECT name FROM users');
    my $rows = $results->arrays;
    return system("echo " . $rows);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $results->arrays -> system")
	}
}

// ---- Mojo::mysql::Results (same lastPart "Results") -------------------

func TestPerl_MojoMysql_Results_Hash_SecondOrder_Command(t *testing.T) {
	code := `
use Mojo::mysql;
sub handler {
    my $mysql = Mojo::mysql->new('mysql://localhost/app');
    my $results = $mysql->db->query('SELECT name FROM users WHERE id = ?', 1);
    my $row = $results->hash;
    return system("echo " . $row);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for Mojo::mysql $results->hash -> system")
	}
}

// ---- Mojo::SQLite::Results (same lastPart "Results") ------------------

func TestPerl_MojoSQLite_Results_Hash_SecondOrder_Command(t *testing.T) {
	code := `
use Mojo::SQLite;
sub handler {
    my $sql = Mojo::SQLite->new('sqlite:test.db');
    my $results = $sql->db->query('SELECT name FROM users WHERE id = ?', 1);
    my $row = $results->hash;
    return system("echo " . $row);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for Mojo::SQLite $results->hash -> system")
	}
}

// ---- Short-receiver-name variants (matcher abbrev heuristic) ----------

func TestPerl_MojoPg_Results_ShortReceiverName_Hash(t *testing.T) {
	code := `
use Mojo::Pg;
sub handler {
    my $pg = Mojo::Pg->new('postgresql://localhost/app');
    my $res = $pg->db->query('SELECT name FROM users WHERE id = ?', 1);
    my $row = $res->hash;
    return system("echo " . $row);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $res->hash (abbrev of $results) -> system")
	}
}

// ---- MongoDB::Cursor next/all -----------------------------------------

func TestPerl_MongoCursor_Next_SecondOrder_Command(t *testing.T) {
	code := `
use MongoDB;
sub handler {
    my $client = MongoDB->connect('mongodb://localhost');
    my $coll = $client->ns('app.users');
    my $cursor = $coll->find({ active => 1 });
    my $doc = $cursor->next;
    return system("echo " . $doc);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $cursor->next -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_MongoCursor_All_SecondOrder_Command(t *testing.T) {
	code := `
use MongoDB;
sub handler {
    my $client = MongoDB->connect('mongodb://localhost');
    my $coll = $client->ns('app.users');
    my $cursor = $coll->find({ active => 1 });
    my $docs = $cursor->all;
    return system("/usr/bin/run " . $docs);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $cursor->all -> system")
	}
}

// ---- MongoDB::Cursor → SQL injection sink (cross-store stored-injection)

func TestPerl_MongoCursor_Next_To_SQLi(t *testing.T) {
	code := `
use MongoDB;
use DBI;
sub handler {
    my $dbi = DBI->connect('dbi:Pg:dbname=app');
    my $mongo = MongoDB->connect('mongodb://localhost');
    my $coll = $mongo->ns('app.users');
    my $cursor = $coll->find({ active => 1 });
    my $doc = $cursor->next;
    $dbi->do("SELECT * FROM logs WHERE note = '" . $doc . "'");
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for Mongo cursor->next -> DBI->do")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---- Negative regression: constant value through same call shape ------

func TestPerl_MojoPg_Results_Constant_NoFlow(t *testing.T) {
	code := `
sub handler {
    my $row = "constant-string";
    return system("echo " . $row);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase && f.Sink.Category == taint.SnkCommand {
			t.Errorf("did not expect SrcDatabase flow for constant string assignment, got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
