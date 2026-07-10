package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl MongoDB NoSQL injection sinks (CWE-943) — MongoDB.pm driver
//
// Real-world attack: user-controlled filter documents enable NoSQL operator
// injection ({ '$ne' => '' }, { '$regex' => '.*' }, { '$where' => 'JS' })
// that bypass authentication or exfiltrate records.
// =========================================================================

func TestPerl_Mongo_Find_NoSQLInjection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $username = $cgi->param("user");
    my $client = MongoDB->connect;
    my $coll = $client->ns("app.users");
    my @results = $coll->find({ name => $username })->all;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->find()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Mongo_FindOne_AuthBypass(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub login {
    my $cgi = CGI->new;
    my $user = $cgi->param("user");
    my $pass = $cgi->param("pass");
    my $coll = MongoDB->connect->ns("app.users");
    my $doc = $coll->find_one({ name => $user, password => $pass });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->find_one() (auth bypass)")
	}
}

func TestPerl_Mongo_FindOneAndUpdate_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $id = $cgi->param("id");
    my $coll = MongoDB->connect->ns("app.posts");
    my $doc = $coll->find_one_and_update({ _id => $id }, { '$set' => { viewed => 1 } });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->find_one_and_update()")
	}
}

func TestPerl_Mongo_FindOneAndReplace_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $filter = $cgi->param("filter");
    my $coll = MongoDB->connect->ns("app.users");
    my $old = $coll->find_one_and_replace({ name => $filter }, { name => "x" });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->find_one_and_replace()")
	}
}

func TestPerl_Mongo_FindOneAndDelete_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $id = $cgi->param("id");
    my $coll = MongoDB->connect->ns("app.items");
    $coll->find_one_and_delete({ _id => $id });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->find_one_and_delete()")
	}
}

func TestPerl_Mongo_UpdateOne_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $uid = $cgi->param("uid");
    my $coll = MongoDB->connect->ns("app.users");
    $coll->update_one({ _id => $uid }, { '$set' => { admin => 1 } });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->update_one()")
	}
}

func TestPerl_Mongo_UpdateMany_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $role = $cgi->param("role");
    my $coll = MongoDB->connect->ns("app.users");
    $coll->update_many({ role => $role }, { '$set' => { active => 0 } });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->update_many()")
	}
}

func TestPerl_Mongo_ReplaceOne_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $id = $cgi->param("id");
    my $coll = MongoDB->connect->ns("app.records");
    $coll->replace_one({ _id => $id }, { name => "replaced" });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->replace_one()")
	}
}

func TestPerl_Mongo_DeleteOne_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $id = $cgi->param("id");
    my $coll = MongoDB->connect->ns("app.records");
    $coll->delete_one({ _id => $id });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->delete_one()")
	}
}

func TestPerl_Mongo_DeleteMany_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $tag = $cgi->param("tag");
    my $coll = MongoDB->connect->ns("app.posts");
    $coll->delete_many({ tag => $tag });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->delete_many()")
	}
}

func TestPerl_Mongo_CountDocuments_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $coll = MongoDB->connect->ns("app.users");
    my $n = $coll->count_documents({ name => $name });
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->count_documents()")
	}
}

func TestPerl_Mongo_Aggregate_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $match = $cgi->param("match");
    my $coll = MongoDB->connect->ns("app.orders");
    my $cursor = $coll->aggregate([{ '$match' => { status => $match } }]);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->aggregate()")
	}
}

func TestPerl_Mongo_Distinct_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $field = $cgi->param("field");
    my $coll = MongoDB->connect->ns("app.users");
    my @values = $coll->distinct($field, {});
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->distinct()")
	}
}

func TestPerl_Mongo_BulkWrite_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $id = $cgi->param("id");
    my $coll = MongoDB->connect->ns("app.records");
    $coll->bulk_write([{ delete_one => { filter => { _id => $id } } }]);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $coll->bulk_write()")
	}
}

func TestPerl_Mongo_RunCommand_Injection(t *testing.T) {
	code := `
use CGI;
use MongoDB;
sub handler {
    my $cgi = CGI->new;
    my $cmd_name = $cgi->param("cmd");
    my $db = MongoDB->connect->get_database("app");
    my $result = $db->run_command([$cmd_name => 1]);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from $cgi->param -> $db->run_command()")
	}
}
