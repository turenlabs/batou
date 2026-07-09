package tsflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust Cassandra / ScyllaDB read sources (second-order taint)
//
// Data persisted to Cassandra/ScyllaDB by any writer (possibly an attacker in
// an earlier request) is untrusted when read back. Reading it and formatting
// it into a downstream SQL query yields a second-order injection. Mirrors the
// Java (DataStax) and Kotlin Cassandra Row read-source cycles. The write-side
// CQL-injection sinks (rust.scylla.session.* / rust.cdrs_tokio.session.*)
// already exist in rust_sinks.go.
//
// The sink used throughout is sqlx::query(&sql) because its ObjectType "sqlx"
// reliably matches the scoped_identifier receiver, isolating the test to the
// new SOURCE entry under test.
//
// Several scylla extractors (`first_row_typed`, `rows_typed`, ...) are
// turbofish method calls (`result.first_row_typed::<(String,)>()`). These are
// matched via the rustConfig generic_function unwrap added alongside these
// sources — see TestRust_Turbofish_MethodCall_Detected /
// TestRust_Deser_Safe_Typed* for the before/after contract.
// =========================================================================

func rustCassQuery(body string) string {
	return "async fn handler(session: scylla::Session, pool: &sqlx::PgPool) {\n" +
		"    let result = session.query_unpaged(\"SELECT v FROM t\", &[]).await.unwrap();\n" +
		body + "\n" +
		"    let sql = format!(\"SELECT * FROM o WHERE c = '{}'\", v);\n" +
		"    sqlx::query(&sql).execute(pool).await.unwrap();\n}\n"
}

func assertCassSource(t *testing.T, code, wantSrcID string) {
	t.Helper()
	flows := Analyze(code, "/app/dao.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.ID == wantSrcID {
			return
		}
	}
	t.Errorf("expected second-order SQL injection via source %q; got flows:", wantSrcID)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s/%s (conf %.2f)", f.Source.ID, f.Sink.Category, f.Sink.ID, f.Confidence)
	}
}

// ---------- scylla::QueryResult extractors ----------

func TestRust_Scylla_FirstRow_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let row = result.first_row().unwrap();
    let v = row.columns[0].as_ref().unwrap().as_text().unwrap();`),
		"rust.scylla.first_row")
}

func TestRust_Scylla_FirstRowTyped_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let (v,): (String,) = result.first_row_typed::<(String,)>().unwrap();`),
		"rust.scylla.first_row_typed")
}

func TestRust_Scylla_SingleRow_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let row = result.single_row().unwrap();
    let v = row.columns[0].as_ref().unwrap().as_text().unwrap();`),
		"rust.scylla.single_row")
}

func TestRust_Scylla_SingleRowTyped_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let (v,): (String,) = result.single_row_typed::<(String,)>().unwrap();`),
		"rust.scylla.single_row_typed")
}

func TestRust_Scylla_MaybeFirstRow_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let row = result.maybe_first_row().unwrap().unwrap();
    let v = row.columns[0].as_ref().unwrap().as_text().unwrap();`),
		"rust.scylla.maybe_first_row")
}

func TestRust_Scylla_MaybeFirstRowTyped_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let (v,): (String,) = result.maybe_first_row_typed::<(String,)>().unwrap().unwrap();`),
		"rust.scylla.maybe_first_row_typed")
}

func TestRust_Scylla_RowsTyped_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let mut rows = result.rows_typed::<(String,)>().unwrap();
    let (v,) = rows.next().unwrap().unwrap();`),
		"rust.scylla.rows_typed")
}

func TestRust_Scylla_RowsTypedOrEmpty_Source(t *testing.T) {
	assertCassSource(t, rustCassQuery(
		`    let mut rows = result.rows_typed_or_empty::<(String,)>().unwrap();
    let (v,) = rows.next().unwrap().unwrap();`),
		"rust.scylla.rows_typed_or_empty")
}

// ---------- cdrs-tokio::Row extractors ----------

func rustCdrsRow(body string) string {
	return "async fn handler(row: cdrs_tokio::Row, pool: &sqlx::PgPool) {\n" +
		body + "\n" +
		"    let sql = format!(\"SELECT * FROM o WHERE c = '{}'\", v);\n" +
		"    sqlx::query(&sql).execute(pool).await.unwrap();\n}\n"
}

func TestRust_Cdrs_GetByName_Source(t *testing.T) {
	assertCassSource(t, rustCdrsRow(
		`    let v: String = row.get_by_name("v").unwrap().unwrap();`),
		"rust.cdrs_tokio.row.get_by_name")
}

func TestRust_Cdrs_GetRByName_Source(t *testing.T) {
	assertCassSource(t, rustCdrsRow(
		`    let v: String = row.get_r_by_name("v").unwrap();`),
		"rust.cdrs_tokio.row.get_r_by_name")
}

func TestRust_Cdrs_GetByIndex_Source(t *testing.T) {
	assertCassSource(t, rustCdrsRow(
		`    let v: String = row.get_by_index(0).unwrap().unwrap();`),
		"rust.cdrs_tokio.row.get_by_index")
}

func TestRust_Cdrs_GetRByIndex_Source(t *testing.T) {
	assertCassSource(t, rustCdrsRow(
		`    let v: String = row.get_r_by_index(0).unwrap();`),
		"rust.cdrs_tokio.row.get_r_by_index")
}

// ---------- Negative control ----------

// A constant value read from a typed row but never combined with attacker-
// influenced data is still treated as a source (second-order), but a query
// built from a hardcoded literal — no source involved — must NOT flow.
func TestRust_Cassandra_ConstantQuery_NoFlow(t *testing.T) {
	code := `
async fn handler(pool: &sqlx::PgPool) {
    let v = "fixed-value";
    let sql = format!("SELECT * FROM o WHERE c = '{}'", v);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/dao.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant literal must not produce a Cassandra second-order SQL flow")
	}
}

// ---------- Registration check ----------

func TestRust_Cassandra_Sources_Registered(t *testing.T) {
	want := []string{
		"rust.scylla.first_row",
		"rust.scylla.first_row_typed",
		"rust.scylla.single_row",
		"rust.scylla.single_row_typed",
		"rust.scylla.maybe_first_row",
		"rust.scylla.maybe_first_row_typed",
		"rust.scylla.rows_typed",
		"rust.scylla.rows_typed_or_empty",
		"rust.cdrs_tokio.row.get_by_name",
		"rust.cdrs_tokio.row.get_r_by_name",
		"rust.cdrs_tokio.row.get_by_index",
		"rust.cdrs_tokio.row.get_r_by_index",
	}
	cat := taint.GetCatalog(rules.LangRust)
	if cat == nil {
		t.Fatal("Rust catalog not loaded")
	}
	got := map[string]bool{}
	for _, s := range cat.Sources() {
		got[s.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected Rust source %q to be registered", id)
		}
	}
}

// ---------- Turbofish langconfig regression guard ----------

// Documents the rustConfig generic_function unwrap that ships with these
// sources: a turbofish METHOD call (`recv.method::<T>()`) must be visible to
// the matcher (here, first_row_typed fires as a source). Before the unwrap the
// walker stopped at `generic_function` and produced zero flows.
func TestRust_Turbofish_MethodCall_Detected(t *testing.T) {
	code := rustCassQuery(
		`    let (v,): (String,) = result.first_row_typed::<(String,)>().unwrap();`)
	flows := Analyze(code, "/app/dao.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatal("turbofish method call result.first_row_typed::<T>() should be matched as a source")
	}
	// Sanity: ensure the assertion is specific to method-call turbofish.
	if !strings.Contains(code, "::<(String,)>") {
		t.Fatal("fixture lost its turbofish form")
	}
}
