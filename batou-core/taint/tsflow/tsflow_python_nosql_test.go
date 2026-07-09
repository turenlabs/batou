package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python NoSQL / MongoDB (CWE-943) tests
// =========================================================================

func TestPython_NoSQL_PyMongoFindOne(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

client = MongoClient()
db = client.mydb

def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = db.users.find_one({"username": username, "password": password})
    return user
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for request.form.get -> collection.find_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_NoSQL_PyMongoUpdateOne(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

def update_profile():
    user_id = request.args.get("id")
    new_name = request.form.get("name")
    db.users.update_one({"_id": user_id}, {"$set": {"name": new_name}})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for request.args.get -> collection.update_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_NoSQL_PyMongoDeleteMany(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

def delete_items():
    category = request.args.get("category")
    db.items.delete_many({"category": category})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for request.args.get -> collection.delete_many")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_NoSQL_PyMongoAggregate(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

def search():
    field = request.args.get("field")
    pipeline = [{"$match": {"status": field}}]
    results = db.orders.aggregate(pipeline)
    return list(results)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for request.args.get -> collection.aggregate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_NoSQL_PyMongoCountDocuments(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

def count():
    status = request.args.get("status")
    count = db.orders.count_documents({"status": status})
    return count
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for request.args.get -> collection.count_documents")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_NoSQL_PyMongoInsertOne(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

def create_item():
    data = request.get_json()
    db.items.insert_one(data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for request.get_json -> collection.insert_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe patterns (sanitized) ---

func TestPython_NoSQL_Sanitized_ObjectId(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient
from bson import ObjectId

db = MongoClient().mydb

def get_user():
    user_id = request.args.get("id")
    safe_id = bson.ObjectId(user_id)
    user = db.users.find_one({"_id": safe_id})
    return user
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NO flow when ObjectId sanitizes the input before find_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_NoSQL_Sanitized_IntCoerce(t *testing.T) {
	code := `
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

def get_by_age():
    age = request.args.get("age")
    safe_age = int(age)
    results = db.users.find_one({"age": safe_age})
    return results
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NO flow when int() sanitizes the input before find_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
