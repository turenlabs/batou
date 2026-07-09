package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — MongoDB NoSQL injection sinks (CWE-943) — mongo ruby driver
//
// Real-world attack: user-controlled filter/update documents enable NoSQL
// operator injection ({ "$ne" => "" }, { "$regex" => ".*" }, { "$where" =>
// "JS" }) that bypasses authentication or exfiltrates records.
// =========================================================================

func TestRuby_Mongo_FindOne_AuthBypass(t *testing.T) {
	code := `
def login(params)
  username = params[:user]
  password = params[:pass]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  doc = coll.find_one(name: username, password: password)
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.find_one() (auth bypass)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Mongo_FindOneAndUpdate_Injection(t *testing.T) {
	code := `
def update(params)
  id = params[:id]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:posts]
  doc = coll.find_one_and_update({ _id: id }, { "$set" => { viewed: true } })
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.find_one_and_update()")
	}
}

func TestRuby_Mongo_FindOneAndReplace_Injection(t *testing.T) {
	code := `
def replace(params)
  filter = params[:filter]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  old = coll.find_one_and_replace({ name: filter }, { name: "x" })
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.find_one_and_replace()")
	}
}

func TestRuby_Mongo_FindOneAndDelete_Injection(t *testing.T) {
	code := `
def destroy(params)
  target = params[:id]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:sessions]
  doc = coll.find_one_and_delete(_id: target)
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.find_one_and_delete()")
	}
}

func TestRuby_Mongo_UpdateOne_Injection(t *testing.T) {
	code := `
def bump(params)
  id = params[:id]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:posts]
  coll.update_one({ _id: id }, { "$inc" => { views: 1 } })
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.update_one()")
	}
}

func TestRuby_Mongo_UpdateMany_Injection(t *testing.T) {
	code := `
def ban(params)
  role = params[:role]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  coll.update_many({ role: role }, { "$set" => { banned: true } })
end
`
	flows := Analyze(code, "/app/controllers/admin_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.update_many()")
	}
}

func TestRuby_Mongo_ReplaceOne_Injection(t *testing.T) {
	code := `
def swap(params)
  id = params[:id]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:docs]
  coll.replace_one({ _id: id }, { title: "x" })
end
`
	flows := Analyze(code, "/app/controllers/docs_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.replace_one()")
	}
}

func TestRuby_Mongo_DeleteOne_Injection(t *testing.T) {
	code := `
def destroy(params)
  id = params[:id]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  coll.delete_one(_id: id)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.delete_one()")
	}
}

func TestRuby_Mongo_DeleteMany_MassDelete(t *testing.T) {
	code := `
def purge(params)
  status = params[:status]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:sessions]
  coll.delete_many(status: status)
end
`
	flows := Analyze(code, "/app/controllers/admin_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.delete_many() (mass delete)")
	}
}

func TestRuby_Mongo_InsertOne_MassAssignment(t *testing.T) {
	code := `
def create(params)
  doc = params[:user]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  coll.insert_one(doc)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.insert_one() (mass-assignment)")
	}
}

func TestRuby_Mongo_BulkWrite_Injection(t *testing.T) {
	code := `
def batch(params)
  ops = params[:operations]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:events]
  coll.bulk_write(ops)
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.bulk_write()")
	}
}

func TestRuby_Mongo_Aggregate_PipelineInjection(t *testing.T) {
	code := `
def report(params)
  pipeline = params[:stages]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:orders]
  result = coll.aggregate(pipeline).to_a
end
`
	flows := Analyze(code, "/app/controllers/reports_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.aggregate() (pipeline stage injection)")
	}
}

func TestRuby_Mongo_CountDocuments_Enumeration(t *testing.T) {
	code := `
def count(params)
  filter = params[:filter]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  total = coll.count_documents(filter)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow from params -> coll.count_documents() (blind enumeration)")
	}
}
