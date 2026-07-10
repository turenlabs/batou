package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust coverage additions (cov/rust): deadpool/bb8 pooled SQL (CWE-89),
// diesel dsl::sql raw fragment (CWE-89), tonic gRPC metadata header
// injection (CWE-113), and uncontrolled allocation size (CWE-770) with its
// std::cmp::min clamp sanitizer. Each detection class has a TP case that
// fires and a near-miss/safe case that stays clean.
// =========================================================================

// --- deadpool-postgres pooled client SQL injection (CWE-89) ---

func TestRust_Deadpool_PooledClient_SQLi(t *testing.T) {
	code := `
async fn list(client: &deadpool_postgres::Client, req: actix_web::web::Query<String>) {
    let name = req.into_inner();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    let rows = client.query(&sql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for deadpool client.query with tainted format! SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_BB8_PooledConn_SQLi(t *testing.T) {
	code := `
async fn list(req: actix_web::web::Query<String>) {
    let name = req.into_inner();
    let sql = format!("SELECT * FROM t WHERE x = '{}'", name);
    let conn = pool.get().await.unwrap();
    let rows = conn.query(&sql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for bb8 conn.query with tainted format! SQL")
	}
}

// Safe: parameterized query with a hardcoded SQL string at arg 0 — the tainted
// value is bound as a parameter, not concatenated. Must stay clean.
func TestRust_Deadpool_Parameterized_Clean(t *testing.T) {
	code := `
async fn list(client: &deadpool_postgres::Client, req: actix_web::web::Query<String>) {
    let name = req.into_inner();
    let rows = client.query("SELECT * FROM users WHERE name = $1", &[&name]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("parameterized deadpool query (hardcoded SQL at arg 0) should NOT flag SQLi")
	}
}

// --- diesel dsl::sql raw fragment (CWE-89) ---

func TestRust_Diesel_DslSql_RawFragment(t *testing.T) {
	code := `
fn search(req: actix_web::web::Query<String>) {
    let term = req.into_inner();
    let expr = diesel::dsl::sql(&term);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for diesel::dsl::sql with tainted fragment")
	}
}

// --- tonic gRPC metadata header injection (CWE-113) ---

func TestRust_Tonic_MetadataInsert_HeaderInjection(t *testing.T) {
	code := `
fn add_meta(req: actix_web::web::Query<String>, request: &mut tonic::Request<()>) {
    let user = req.into_inner();
    let metadata = request.metadata_mut();
    metadata.insert("x-user", MetadataValue::try_from(user).unwrap());
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header-injection flow for tonic MetadataMap::insert with tainted value")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- uncontrolled allocation size (CWE-770) ---

func TestRust_Alloc_VecWithCapacity_Tainted(t *testing.T) {
	code := `
fn handle(req: actix_web::HttpRequest) {
    let len_hdr = req.headers().get("content-length").unwrap();
    let n: usize = len_hdr.to_str().unwrap().parse().unwrap();
    let mut buf: Vec<u8> = Vec::with_capacity(n);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkMemory) {
		t.Error("expected uncontrolled-allocation flow for Vec::with_capacity with tainted size")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: the tainted length is clamped with std::cmp::min before allocation —
// the rust.alloc.size_bound sanitizer must neutralize the SnkMemory flow.
func TestRust_Alloc_Clamped_Clean(t *testing.T) {
	code := `
fn handle(req: actix_web::HttpRequest) {
    let len_hdr = req.headers().get("content-length").unwrap();
    let n: usize = len_hdr.to_str().unwrap().parse().unwrap();
    let capped = std::cmp::min(n, 4096);
    let mut buf: Vec<u8> = Vec::with_capacity(capped);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkMemory) {
		t.Error("clamped allocation (std::cmp::min) should NOT flag uncontrolled-allocation")
	}
}
