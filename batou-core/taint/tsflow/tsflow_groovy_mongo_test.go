package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy MongoDB NoSQL injection tests (CWE-943)
// Covers MongoDB Java driver (MongoCollection) + Spring Data MongoTemplate
// used from Groovy/Grails applications on the JVM.
// =========================================================================

func TestGroovy_MongoCollectionFind(t *testing.T) {
	code := `
def handler(params) {
    def query = BasicDBObject.parse(params.filter)
    collection.find(query)
}
`
	flows := Analyze(code, "/app/UserController.groovy", rules.LangGroovy)
	// Either the BasicDBObject.parse sink or collection.find sink should fire.
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for params.filter -> MongoDB query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollectionAggregate(t *testing.T) {
	code := `
def search(params) {
    def pipeline = params.pipeline
    collection.aggregate(pipeline)
}
`
	flows := Analyze(code, "/app/SearchController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for params.pipeline -> collection.aggregate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollectionUpdateOne(t *testing.T) {
	code := `
def update(params) {
    def filter = params.filter
    collection.updateOne(filter, params.update)
}
`
	flows := Analyze(code, "/app/UpdateController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for params.filter -> collection.updateOne")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollectionDeleteMany(t *testing.T) {
	code := `
def delete(params) {
    def filter = params.filter
    collection.deleteMany(filter)
}
`
	flows := Analyze(code, "/app/DeleteController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for params.filter -> collection.deleteMany")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoFindOneAndUpdate(t *testing.T) {
	code := `
def modify(params) {
    def filter = params.filter
    collection.findOneAndUpdate(filter, params.update)
}
`
	flows := Analyze(code, "/app/ModifyController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for params.filter -> findOneAndUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoBasicDBObjectParse(t *testing.T) {
	code := `
def queryUser(params) {
    def query = BasicDBObject.parse(params.json)
}
`
	flows := Analyze(code, "/app/UserDao.groovy", rules.LangGroovy)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "groovy.mongodb.basicdbobject.parse" {
			found = true
		}
	}
	if !found {
		t.Error("expected NoSQL injection flow for BasicDBObject.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestGroovy_MongoBsonDocumentParse(t *testing.T) {
	code := `
def queryUser(params) {
    def query = BsonDocument.parse(params.json)
}
`
	flows := Analyze(code, "/app/UserDao.groovy", rules.LangGroovy)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "groovy.mongo.bsondocument.parse" {
			found = true
		}
	}
	if !found {
		t.Error("expected NoSQL injection flow for BsonDocument.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestGroovy_MongoRunCommand(t *testing.T) {
	code := `
def runCmd(params) {
    def cmd = params.command
    database.runCommand(cmd)
}
`
	flows := Analyze(code, "/app/AdminController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for params.command -> database.runCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringMongoTemplateFind(t *testing.T) {
	code := `
def search(params) {
    def query = params.query
    mongoTemplate.find(query, User.class)
}
`
	flows := Analyze(code, "/app/UserRepository.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for params.query -> mongoTemplate.find")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringMongoTemplateFindOne(t *testing.T) {
	code := `
def lookup(params) {
    def query = params.query
    mongoTemplate.findOne(query, User.class)
}
`
	flows := Analyze(code, "/app/UserRepository.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for params.query -> mongoTemplate.findOne")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
