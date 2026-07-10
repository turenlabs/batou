package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------- BsonDocument.parse (CWE-943) ----------

func TestKotlin_MongoBsonDocumentParse(t *testing.T) {
	code := `
import org.bson.BsonDocument

fun queryByBson(input: String) {
    val bsonFilter = BsonDocument.parse(input)
}
`
	flows := Analyze(code, "/app/MongoHandler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.bsondocument.parse" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for BsonDocument.parse")
	}
}

// ---------- BasicDBObject constructor (CWE-943) ----------

func TestKotlin_MongoBasicDBObject(t *testing.T) {
	code := `
import com.mongodb.BasicDBObject

fun unsafeQuery(input: String) {
    val query = BasicDBObject(input, "value")
    collection.find(query)
}
`
	flows := Analyze(code, "/app/MongoHandler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.basicdbobject" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for BasicDBObject constructor")
	}
}

// ---------- MongoDatabase.runCommand (CWE-943) ----------

func TestKotlin_MongoRunCommand(t *testing.T) {
	code := `
import com.mongodb.client.MongoDatabase

fun executeRaw(db: MongoDatabase, input: String) {
    db.runCommand(Document(input))
}
`
	flows := Analyze(code, "/app/MongoHandler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.runcommand" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for MongoDatabase.runCommand")
	}
}

// ---------- findOneAndUpdate (CWE-943) ----------

func TestKotlin_MongoFindOneAndUpdate(t *testing.T) {
	code := `
import com.mongodb.client.MongoCollection

fun updateUser(input: String) {
    val update = Document("active", true)
    collection.findOneAndUpdate(Document(input), update)
}
`
	flows := Analyze(code, "/app/MongoHandler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.findoneandupdate" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for findOneAndUpdate")
	}
}

// ---------- findOneAndDelete (CWE-943) ----------

func TestKotlin_MongoFindOneAndDelete(t *testing.T) {
	code := `
fun deleteUser(input: String) {
    collection.findOneAndDelete(Document(input))
}
`
	flows := Analyze(code, "/app/MongoHandler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.findoneanddelete" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for findOneAndDelete")
	}
}

// ---------- Spring Data MongoTemplate.find (CWE-943) ----------

func TestKotlin_MongoTemplateFindTainted(t *testing.T) {
	code := `
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.core.query.Query

fun searchByInput(mongoTemplate: MongoTemplate, input: String) {
    val query = Query.query(Criteria.where("name").` + "`" + `is` + "`" + `(input))
    val results = mongoTemplate.find(query, User::class.java)
}
`
	flows := Analyze(code, "/app/UserService.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.template.find" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for MongoTemplate.find")
	}
}

// ---------- Spring Data MongoTemplate.executeCommand (CWE-943) ----------

func TestKotlin_MongoTemplateExecuteCommand(t *testing.T) {
	code := `
import org.springframework.data.mongodb.core.MongoTemplate

fun runRawCommand(mongoTemplate: MongoTemplate, input: String) {
    mongoTemplate.executeCommand(input)
}
`
	flows := Analyze(code, "/app/AdminService.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.mongo.template.executecommand" {
			found = true
		}
	}
	if !found {
		t.Error("Expected NoSQL injection finding for MongoTemplate.executeCommand")
	}
}
