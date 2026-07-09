package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// Tests for Groovy MongoDB NoSQL-injection sinks (CWE-943).
// Covers mongo-java-driver (MongoCollection), BSON Document/BasicDBObject
// static parsers, and Spring Data MongoDB MongoTemplate — all commonly used
// from Groovy (Grails / Micronaut / standalone scripts).
// Function parameters named `query`, `body`, `input`, `params`, `data`, `form`
// are seeded as tainted by the tsflow walker (see isInputParamName).

// ---------------------------------------------------------------------------
// mongo-java-driver MongoCollection — distinctive method names
// ---------------------------------------------------------------------------

func TestGroovy_MongoCollection_FindOneAndUpdate_NoSQLInjection(t *testing.T) {
	code := `
def updateProfile(query, body) {
    collection.findOneAndUpdate(query, body)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for parameter -> MongoCollection.findOneAndUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollection_FindOneAndDelete_NoSQLInjection(t *testing.T) {
	code := `
def purgeOne(query) {
    collection.findOneAndDelete(query)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for parameter -> MongoCollection.findOneAndDelete")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollection_DeleteMany_NoSQLInjection(t *testing.T) {
	code := `
def purge(query) {
    collection.deleteMany(query)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for parameter -> MongoCollection.deleteMany")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollection_UpdateOne_NoSQLInjection(t *testing.T) {
	code := `
def rename(query, body) {
    collection.updateOne(query, body)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for parameter -> MongoCollection.updateOne")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MongoCollection_CountDocuments_NoSQLInjection(t *testing.T) {
	code := `
def countMatching(query) {
    def n = collection.countDocuments(query)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for parameter -> MongoCollection.countDocuments")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// BSON BasicDBObject.parse — tainted JSON string sink (unique to MongoDB)
// ---------------------------------------------------------------------------

func TestGroovy_BasicDBObjectParse_NoSQLInjection(t *testing.T) {
	code := `
def legacySearch(input) {
    def q = BasicDBObject.parse(input)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for parameter -> BasicDBObject.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Spring Data MongoDB MongoTemplate
// ---------------------------------------------------------------------------

func TestGroovy_SpringMongoTemplate_FindAndRemove_NoSQLInjection(t *testing.T) {
	code := `
def purgeUser(query) {
    mongoTemplate.findAndRemove(query, User.class)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for parameter -> MongoTemplate.findAndRemove")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringMongoTemplate_UpdateFirst_NoSQLInjection(t *testing.T) {
	code := `
def rename(query, body) {
    mongoTemplate.updateFirst(query, body, User.class)
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for parameter -> MongoTemplate.updateFirst")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Sanitizer: MongoDB Filters builder (neutralizes tainted input)
// ---------------------------------------------------------------------------

func TestGroovy_MongoFiltersBuilder_Sanitizes(t *testing.T) {
	code := `
def safeSearch(input) {
    collection.find(Filters.eq("name", input))
}
`
	flows := Analyze(code, "/app/controller.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Filters.eq should sanitize; did not expect NoSQL injection flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
