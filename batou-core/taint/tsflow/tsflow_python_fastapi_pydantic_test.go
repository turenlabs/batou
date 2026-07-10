package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for FastAPI Pydantic-model parameter source detection.
//
// Mature SAST tools model the same pattern as a Pydantic-bound request
// handler parameter source: a class-annotated parameter of a function
// decorated with @app.get/post/... is a request body source.
//
// Source ID: "py.fastapi.pydantic_body" (Description: "FastAPI Pydantic-bound
// request body parameter") seeded in walker.go:seedPythonPydanticParams.

// hasPydanticBodyFlow returns true if any flow's source is the FastAPI
// Pydantic body source seeded by seedPythonPydanticParams.
func hasPydanticBodyFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Source.ID == "py.fastapi.pydantic_body" {
			return true
		}
	}
	return false
}

// --- Positive: vulnerable Pydantic body parameter flowing to SQL sink. ---
func TestPython_FastAPI_PydanticBody_SQLi(t *testing.T) {
	code := `
from pydantic import BaseModel
from fastapi import FastAPI
import sqlite3

app = FastAPI()

class User(BaseModel):
    name: str
    email: str

@app.post("/users")
def create_user(user: User):
    cursor.execute("INSERT INTO users VALUES ('" + user.name + "')")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatal("expected SQL injection flow from Pydantic body user.name to cursor.execute")
	}
	if !hasPydanticBodyFlow(flows) {
		t.Errorf("expected a flow with source py.fastapi.pydantic_body; got:")
		for _, f := range flows {
			t.Logf("  src=%s desc=%q sink=%s", f.Source.ID, f.Source.Description, f.Sink.Category)
		}
	}
}

// Same as above but on an APIRouter (@router.post) instead of @app.post.
func TestPython_FastAPI_PydanticBody_APIRouter_SQLi(t *testing.T) {
	code := `
from pydantic import BaseModel
from fastapi import APIRouter

router = APIRouter()

class Item(BaseModel):
    name: str

@router.put("/items")
def update_item(item: Item):
    cursor.execute("UPDATE items SET name='" + item.name + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasPydanticBodyFlow(flows) {
		t.Errorf("expected a py.fastapi.pydantic_body flow for @router.put Pydantic param; flows:")
		for _, f := range flows {
			t.Logf("  src=%s sink=%s", f.Source.ID, f.Sink.Category)
		}
	}

}

// --- Negative: parameter typed as `str` must NOT be flagged as Pydantic body.
// (The existing isHandler heuristic may still taint it as a generic web
// handler parameter — that's a separate path. We only assert that our new
// precise Pydantic source does NOT fire on a primitive type.) ---
func TestPython_FastAPI_NonPydanticParam_NoFlow(t *testing.T) {
	code := `
from fastapi import FastAPI
app = FastAPI()

@app.get("/items/{name}")
def get_item(name: str, count: int):
    cursor.execute("SELECT * FROM items WHERE name = '" + name + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasPydanticBodyFlow(flows) {
		t.Error("unexpected py.fastapi.pydantic_body flow for primitive str/int parameter")
		for _, f := range flows {
			t.Logf("  src=%s sink=%s", f.Source.ID, f.Sink.Category)
		}
	}
}

// --- Negative: parameter typed as `Request` (Starlette/FastAPI request
// object) must NOT double-fire as a Pydantic body. The existing
// request.query_params/headers/cookies catalog sources still apply. ---
func TestPython_FastAPI_RequestParam_NoDoubleFlag(t *testing.T) {
	code := `
from fastapi import FastAPI, Request
app = FastAPI()

@app.get("/items")
def get_item(request: Request):
    name = request.query_params.get("name")
    cursor.execute("SELECT * FROM items WHERE name = '" + name + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasPydanticBodyFlow(flows) {
		t.Error("unexpected py.fastapi.pydantic_body flow for Request-typed parameter")
		for _, f := range flows {
			t.Logf("  src=%s sink=%s", f.Source.ID, f.Sink.Category)
		}
	}
}

// --- Negative: utility function (no route decorator) with a Pydantic-typed
// parameter must NOT be flagged. Tainting non-route helpers would lead to
// over-reporting (e.g. internal mappers that accept a model). ---
func TestPython_NonRouteHandler_NoFlow(t *testing.T) {
	code := `
from pydantic import BaseModel

class User(BaseModel):
    name: str

def process_user(user: User):
    cursor.execute("INSERT INTO users VALUES ('" + user.name + "')")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasPydanticBodyFlow(flows) {
		t.Error("unexpected py.fastapi.pydantic_body flow on non-route function")
		for _, f := range flows {
			t.Logf("  src=%s sink=%s", f.Source.ID, f.Sink.Category)
		}
	}
}

// --- Sanity: bare @app.get (no parentheses) decorator should also count as
// a route handler. Mature SAST tools treat decorator references identically. ---
func TestPython_FastAPI_PydanticBody_BareDecorator(t *testing.T) {
	code := `
from pydantic import BaseModel
from fastapi import FastAPI

app = FastAPI()

class Item(BaseModel):
    name: str

@app.post
def make_item(item: Item):
    cursor.execute("INSERT INTO items VALUES ('" + item.name + "')")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasPydanticBodyFlow(flows) {
		t.Errorf("expected py.fastapi.pydantic_body flow for bare @app.post decorator")
	}
}

// --- Negative: a non-FastAPI decorator (e.g. @staticmethod or random
// decorator) must NOT cause Pydantic seeding. ---
func TestPython_NonFastAPIDecorator_NoFlow(t *testing.T) {
	code := `
from pydantic import BaseModel

class User(BaseModel):
    name: str

@staticmethod
def process_user(user: User):
    cursor.execute("INSERT INTO users VALUES ('" + user.name + "')")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasPydanticBodyFlow(flows) {
		t.Error("unexpected py.fastapi.pydantic_body flow under unrelated decorator")
	}
}
