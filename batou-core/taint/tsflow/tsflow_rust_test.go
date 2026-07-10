package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Weak PRNG (CWE-330) ---

func TestRust_WeakRandom_SmallRng_Seeded(t *testing.T) {
	code := `
use std::env;
use rand::rngs::SmallRng;
use rand::SeedableRng;

fn handler() {
    let seed: u64 = env::var("SEED").unwrap().parse().unwrap();
    let mut rng = SmallRng::seed_from_u64(seed);
}
`
	flows := Analyze(code, "/app/crypto.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak random flow for env::var -> SmallRng::seed_from_u64")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_WeakRandom_StdRng_Seeded(t *testing.T) {
	code := `
use std::env;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn handler() {
    let seed: u64 = env::var("SEED").unwrap().parse().unwrap();
    let mut rng = StdRng::seed_from_u64(seed);
}
`
	flows := Analyze(code, "/app/crypto.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak random flow for env::var -> StdRng::seed_from_u64")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_WeakRandom_StepRng(t *testing.T) {
	code := `
use std::env;
use rand::rngs::mock::StepRng;

fn handler() {
    let start: u64 = env::var("START").unwrap().parse().unwrap();
    let mut rng = StepRng::new(start, 1);
}
`
	flows := Analyze(code, "/app/crypto.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak random flow for env::var -> StepRng::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_WeakRandom_Safe_ThreadRng(t *testing.T) {
	code := `
use rand::thread_rng;
use rand::Rng;

fn generate_token() -> u64 {
    let mut rng = thread_rng();
    rng.gen()
}
`
	flows := Analyze(code, "/app/crypto.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("thread_rng() is cryptographically secure — should not produce weak random flow")
		}
	}
}

// --- HTTP Header Injection (CWE-113) ---

func TestRust_HeaderInjection_Rocket(t *testing.T) {
	code := `
use std::env;
use rocket::http::Header;

fn handler() {
    let val = env::var("REDIRECT_URL").unwrap();
    let h = Header::new("Location", val);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for env::var -> Header::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_HeaderInjection_Warp(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let val = env::var("HEADER_VAL").unwrap();
    let reply = with_header("ok", "X-Custom", val);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for env::var -> with_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_HeaderInjection_Hyper(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let val = env::var("HEADER_VAL").unwrap();
    let resp = Response::builder().header("X-Custom", val);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for env::var -> Response::builder().header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_HeaderInjection_Safe_HeaderValue(t *testing.T) {
	code := `
use std::env;
use http::header::HeaderValue;

fn handler() {
    let val = env::var("HEADER_VAL").unwrap();
    let safe = HeaderValue::from_str(&val).unwrap();
    resp.insert_header(("X-Custom", safe));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("HeaderValue::from_str should sanitize header injection")
		}
	}
}

// --- Trust Boundary Violation (CWE-501) ---

func TestRust_TrustBoundary_ActixSession(t *testing.T) {
	code := `
use actix_web::web;
use actix_session::Session;

async fn handler(session: Session, body: web::Json<LoginRequest>) {
    let username = &body.username;
    session.insert("user", username).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for web::Json -> session.insert")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TrustBoundary_TowerSessions(t *testing.T) {
	code := `
use axum::extract::Query;
use tower_sessions::Session;

async fn handler(session: Session, Query(params): Query<LoginParams>) {
    let user_id = &params.user_id;
    session.insert("user_id", user_id).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for Query -> session.insert")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TrustBoundary_ActixIdentity(t *testing.T) {
	code := `
use actix_web::{web, HttpRequest};
use actix_identity::Identity;

async fn login(req: HttpRequest, body: web::Json<LoginRequest>) {
    let user_id = &body.user_id;
    Identity::login(&req.extensions(), user_id.to_string()).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for web::Json -> Identity::login")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TrustBoundary_CookieNew(t *testing.T) {
	code := `
use actix_web::web;
use cookie::Cookie;

async fn handler(body: web::Json<Prefs>) {
    let theme = &body.theme;
    let c = Cookie::new("theme", theme);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for web::Json -> Cookie::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TrustBoundary_RocketCookiesAddPrivate(t *testing.T) {
	code := `
use rocket::http::{CookieJar, Cookie};

fn handler(cookies: &CookieJar<'_>, token: &str) {
    let val = std::env::var("USER_TOKEN").unwrap();
    cookies.add_private(Cookie::new("session", val));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for env::var -> cookies.add_private")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TrustBoundary_Safe_Hardcoded(t *testing.T) {
	code := `
use actix_session::Session;

async fn handler(session: Session) {
    let role = "admin";
    session.insert("role", role).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("hardcoded value should not trigger trust boundary violation")
		}
	}
}

// --- MongoDB NoSQL Injection (CWE-943) ---

func TestRust_MongoDB_NoSQL_FindOne(t *testing.T) {
	code := `
use axum::extract::Query;
use mongodb::Collection;
use bson::doc;

async fn handler(Query(params): Query<SearchParams>, coll: Collection<User>) {
    let name = &params.name;
    let result = coll.find_one(doc! { "name": name }).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Query -> Collection::find_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_MongoDB_NoSQL_DeleteOne(t *testing.T) {
	code := `
use actix_web::web;
use mongodb::Collection;
use bson::doc;

async fn handler(body: web::Json<DeleteRequest>, coll: Collection<User>) {
    let user_id = &body.user_id;
    coll.delete_one(doc! { "_id": user_id }).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for web::Json -> Collection::delete_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_MongoDB_NoSQL_RunCommand(t *testing.T) {
	code := `
use std::env;
use mongodb::Database;
use bson::doc;

async fn handler(db: Database) {
    let cmd = env::var("DB_COMMAND").unwrap();
    db.run_command(doc! { "eval": cmd }).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for env::var -> Database::run_command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Typed deserialization sanitizer tests (CWE-502) ---

func TestRust_Deser_Safe_TypedYaml(t *testing.T) {
	code := `
use axum::extract::Json;
use serde::Deserialize;

#[derive(Deserialize)]
struct Payload {
    yaml_data: String,
}

#[derive(Deserialize)]
struct Config {
    name: String,
    port: u16,
}

async fn handler(Json(payload): Json<Payload>) -> String {
    let config = serde_yaml::from_str::<Config>(&payload.yaml_data).unwrap();
    format!("name={}", config.name)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("serde_yaml::from_str::<Config> (typed) should sanitize deserialization")
		}
	}
}

func TestRust_Deser_Safe_TypedRon(t *testing.T) {
	code := `
use axum::extract::Json;
use serde::Deserialize;

#[derive(Deserialize)]
struct Payload {
    ron_data: String,
}

#[derive(Deserialize)]
struct Settings {
    debug: bool,
    level: u8,
}

async fn handler(Json(payload): Json<Payload>) -> String {
    let settings = ron::from_str::<Settings>(&payload.ron_data).unwrap();
    format!("debug={}", settings.debug)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("ron::from_str::<Settings> (typed) should sanitize deserialization")
		}
	}
}

func TestRust_Deser_Safe_TypedRmpSerde(t *testing.T) {
	code := `
use axum::extract::Bytes;
use serde::Deserialize;

#[derive(Deserialize)]
struct Message {
    topic: String,
    seq: u64,
}

async fn handler(body: Bytes) -> String {
    let msg = rmp_serde::from_slice::<Message>(&body).unwrap();
    msg.topic
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("rmp_serde::from_slice::<Message> (typed) should sanitize deserialization")
		}
	}
}

func TestRust_MongoDB_NoSQL_Safe_BsonToBson(t *testing.T) {
	code := `
use axum::extract::Query;
use mongodb::Collection;
use bson;

async fn handler(Query(params): Query<SearchParams>) {
    let coll = get_collection();
    let filter = bson::to_bson(params);
    let result = coll.find_one(filter).await;
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("bson::to_bson should sanitize NoSQL injection — typed struct constrains document shape")
		}
	}
}

// --- mysql_async SQL Injection (CWE-89) ---

func TestRust_MySQL_SQLInjection_QueryDrop(t *testing.T) {
	code := `
use axum::extract::Query;

async fn handler(Query(params): Query<SearchParams>, conn: &mut Conn) {
    let name = &params.name;
    let sql = format!("DELETE FROM users WHERE name = '{}'", name);
    conn.query_drop(sql).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Query -> Conn::query_drop")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_MySQL_SQLInjection_QueryFirst(t *testing.T) {
	code := `
use std::env;

async fn handler(conn: &mut Conn) {
    let user = env::var("USERNAME").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", user);
    let row = conn.query_first(sql).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for env::var -> Conn::query_first")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_MySQL_Safe_ExecDrop(t *testing.T) {
	code := `
use axum::extract::Query;

async fn handler(Query(params): Query<SearchParams>, conn: &mut Conn) {
    let name = &params.name;
    conn.exec_drop("DELETE FROM users WHERE name = ?", (name,)).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("exec_drop uses parameterized queries — should sanitize SQL injection")
		}
	}
}

func TestRust_MySQL_Safe_PreparedStatement(t *testing.T) {
	code := `
use std::env;

async fn handler(conn: &mut Conn) {
    let user = env::var("USERNAME").unwrap();
    let stmt = conn.prep("SELECT * FROM users WHERE name = ?").await.unwrap();
    let row = conn.exec_first(stmt, (user,)).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("prep + exec_first uses prepared statement — should sanitize SQL injection")
		}
	}
}

// --- XPath Injection (CWE-643) ---

func TestRust_XPath_Injection_StringConcat(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let name = env::var("USERNAME").unwrap();
    let xpath = format!("//user[@name='{}']", name);
    let result = sxd_xpath::evaluate_xpath(&doc, &xpath);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for env::var -> evaluate_xpath via string concat")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_XPath_Safe_ContextVariable(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let name = env::var("USERNAME").unwrap();
    let mut context = sxd_xpath::Context::new();
    context.set_variable("name", name.as_str());
    let xpath = factory.build("//user[@name=$name]").unwrap();
    let result = xpath.evaluate(&context, root);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Error("set_variable parameterizes the XPath query — should sanitize XPath injection")
		}
	}
}

func TestRust_XPath_Safe_QuickXmlEscape(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let name = env::var("USERNAME").unwrap();
    let escaped = quick_xml::escape::escape(&name);
    let xpath = format!("//user[@name='{}']", escaped);
    let result = sxd_xpath::evaluate_xpath(&doc, &xpath);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Error("quick_xml::escape::escape encodes XML entities — should sanitize XPath injection")
		}
	}
}

func TestRust_XPath_Safe_XmlRsEscape(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let name = env::var("USERNAME").unwrap();
    let escaped = xml::escape::escape_str_attribute(&name);
    let xpath = format!("//user[@name='{}']", escaped);
    let result = sxd_xpath::evaluate_xpath(&doc, &xpath);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Error("xml::escape::escape_str_attribute encodes XML entities — should sanitize XPath injection")
		}
	}
}

// --- Eval / Code Injection (CWE-94) ---

func TestRust_Eval_Rhai_Unsandboxed(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let script = env::var("USER_SCRIPT").unwrap();
    let engine = rhai::Engine::new();
    let result = engine.eval_expression(&script);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai eval_expression without sandboxing")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Eval_Safe_RegexEscape(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let pattern = env::var("USER_PATTERN").unwrap();
    let escaped = regex::escape(&pattern);
    let re = Regex::new(&escaped);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("regex::escape neutralizes metacharacters — should sanitize ReDoS")
		}
	}
}

func TestRust_Eval_Pyo3_Unsandboxed(t *testing.T) {
	code := `
use std::env;

fn handler(py: Python) {
    let code = env::var("USER_CODE").unwrap();
    py.eval(&code, None, None);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> py.eval without sandboxing")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
