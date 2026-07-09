package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- redis-rs: Script::new with tainted Lua source (CWE-94) ---

func TestRust_Redis_ScriptNew_Tainted(t *testing.T) {
	code := `
use std::env;
use redis::Script;

fn handle() {
    let user_lua = env::var("USER_SCRIPT").unwrap();
    let script = redis::Script::new(&user_lua);
    let _: () = script.invoke(&mut con).unwrap();
}
`
	flows := Analyze(code, "/app/redis_eval.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow: env::var -> redis::Script::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- redis-rs: Script::new with hardcoded string should NOT flag ---

func TestRust_Redis_ScriptNew_Hardcoded_Safe(t *testing.T) {
	code := `
use redis::Script;

fn handle() {
    let script = redis::Script::new("return ARGV[1]");
    let _: () = script.invoke(&mut con).unwrap();
}
`
	flows := Analyze(code, "/app/redis_eval.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "rust.redis.script.new" {
			t.Errorf("hardcoded redis::Script::new should not produce eval flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- fred: Script::from_lua with tainted Lua source (CWE-94) ---

func TestRust_Fred_ScriptFromLua_Tainted(t *testing.T) {
	code := `
use std::env;
use fred::types::scripts::Script;

async fn handle(client: &RedisClient) {
    let user_lua = env::var("USER_SCRIPT").unwrap();
    let script = Script::from_lua(user_lua);
    let _ = script.load(client).await.unwrap();
    let _: String = script.evalsha(client, "key", "arg").await.unwrap();
}
`
	flows := Analyze(code, "/app/fred_eval.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow: env::var -> fred Script::from_lua")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- fred: Script::from_lua with hardcoded string should NOT flag ---

func TestRust_Fred_ScriptFromLua_Hardcoded_Safe(t *testing.T) {
	code := `
use fred::types::scripts::Script;

async fn handle(client: &RedisClient) {
    let script = Script::from_lua("return ARGV[1]");
    let _ = script.load(client).await.unwrap();
}
`
	flows := Analyze(code, "/app/fred_eval.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "rust.fred.script.from_lua" {
			t.Errorf("hardcoded Script::from_lua should not produce eval flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- redis-rs: HTTP-sourced tainted Lua via request body (CWE-94) ---

func TestRust_Redis_ScriptNew_HttpSource(t *testing.T) {
	code := `
use actix_web::{web, HttpResponse};
use redis::Script;

async fn handle(body: web::Bytes) -> HttpResponse {
    let user_script = String::from_utf8(body.to_vec()).unwrap();
    let script = redis::Script::new(&user_script);
    let _: () = script.invoke(&mut con).unwrap();
    HttpResponse::Ok().finish()
}
`
	flows := Analyze(code, "/app/actix_redis.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow: actix body -> redis::Script::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
