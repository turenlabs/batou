package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust vector database filter injection sinks (CWE-943 / CWE-89)
//
// Covers two crates:
//   - qdrant-client (https://docs.rs/qdrant-client) — Qdrant gRPC API.
//     The Filter field of SearchPoints / DeletePoints / RecommendPoints /
//     QueryBatchPoints is parsed server-side; tainted Filter content lets
//     an attacker read or mutate points outside the authenticated request's
//     intended tenant scope.
//   - lancedb (https://docs.rs/lancedb) — embedded analytical vector DB.
//     Table::delete / Table::count_rows / Query::only_if accept a SQL
//     predicate string evaluated by Lance/DataFusion; tainted predicate
//     enables row-level scope escape.
//
// Safe usage: build Filter / predicate from validated values, never
// concatenated user input.
// =========================================================================

// ---------- qdrant-client Qdrant::search_points (CWE-943) ----------

func TestRust_Qdrant_SearchPoints_FilterInjection(t *testing.T) {
	code := `
use qdrant_client::Qdrant;
use qdrant_client::qdrant::{SearchPoints, Filter, Condition};

async fn handler(client: Qdrant, input: String) {
    let filter_text = format!("user = '{}'", input);
    let req = SearchPoints {
        collection_name: "memories".to_string(),
        filter: Some(Filter::must([Condition::matches("user", filter_text)])),
        limit: 10,
        ..Default::default()
    };
    client.search_points(req).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "rust.qdrant.search_points" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected filter-injection finding for Qdrant::search_points; got flows: %+v", flows)
	}
}

// ---------- qdrant-client Qdrant::search_batch_points (CWE-943) ----------

func TestRust_Qdrant_SearchBatchPoints_FilterInjection(t *testing.T) {
	code := `
use qdrant_client::Qdrant;
use qdrant_client::qdrant::SearchBatchPoints;

async fn handler(client: Qdrant, input: String) {
    let req = format!("batch with tenant = '{}'", input);
    client.search_batch_points(req).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.qdrant.search_batch_points" {
			return
		}
	}
	t.Errorf("expected filter-injection finding for Qdrant::search_batch_points; got flows: %+v", flows)
}

// ---------- qdrant-client Qdrant::delete_points (CWE-943) ----------

func TestRust_Qdrant_DeletePoints_FilterInjection(t *testing.T) {
	code := `
use qdrant_client::Qdrant;
use qdrant_client::qdrant::{DeletePoints, Filter, Condition, PointsSelector};

async fn handler(client: Qdrant, input: String) {
    let filter_text = format!("owner = '{}'", input);
    let req = DeletePoints {
        collection_name: "memories".to_string(),
        points: Some(PointsSelector::from(Filter::must([Condition::matches("owner", filter_text)]))),
        wait: None,
        ordering: None,
        shard_key_selector: None,
    };
    client.delete_points(req).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.qdrant.delete_points" {
			return
		}
	}
	t.Errorf("expected filter-injection finding for Qdrant::delete_points; got flows: %+v", flows)
}

// ---------- qdrant-client Qdrant::recommend_batch (CWE-943) ----------

func TestRust_Qdrant_RecommendBatch_FilterInjection(t *testing.T) {
	code := `
use qdrant_client::Qdrant;

async fn handler(client: Qdrant, input: String) {
    let req = format!("batch with category = '{}'", input);
    client.recommend_batch(req).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.qdrant.recommend_batch" {
			return
		}
	}
	t.Errorf("expected filter-injection finding for Qdrant::recommend_batch; got flows: %+v", flows)
}

// ---------- qdrant-client Qdrant::query_batch (CWE-943) ----------

func TestRust_Qdrant_QueryBatch_FilterInjection(t *testing.T) {
	code := `
use qdrant_client::Qdrant;

async fn handler(client: Qdrant, input: String) {
    let req = format!("batch with user_id = '{}'", input);
    client.query_batch(req).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.qdrant.query_batch" {
			return
		}
	}
	t.Errorf("expected filter-injection finding for Qdrant::query_batch; got flows: %+v", flows)
}

// ---------- lancedb Table::delete predicate injection (CWE-89) ----------

func TestRust_LanceDB_TableDelete_PredicateInjection(t *testing.T) {
	code := `
use lancedb::Table;

async fn handler(table: Table, input: String) {
    let predicate = format!("user_id = '{}'", input);
    table.delete(&predicate).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.lancedb.table.delete" {
			return
		}
	}
	t.Errorf("expected predicate-injection finding for lancedb Table::delete; got flows: %+v", flows)
}

// ---------- lancedb Table::count_rows predicate injection (CWE-89) ----------

func TestRust_LanceDB_TableCountRows_PredicateInjection(t *testing.T) {
	code := `
use lancedb::Table;

async fn handler(table: Table, input: String) {
    let predicate = format!("tenant = '{}'", input);
    table.count_rows(Some(predicate)).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.lancedb.table.count_rows" {
			return
		}
	}
	t.Errorf("expected predicate-injection finding for lancedb Table::count_rows; got flows: %+v", flows)
}

// ---------- lancedb Query::only_if predicate injection (CWE-89) ----------

func TestRust_LanceDB_QueryOnlyIf_PredicateInjection(t *testing.T) {
	code := `
use lancedb::query::Query;

async fn handler(query: Query, input: String) {
    let predicate = format!("score > {}", input);
    query.only_if(predicate).execute().await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.lancedb.query.only_if" {
			return
		}
	}
	t.Errorf("expected predicate-injection finding for lancedb Query::only_if; got flows: %+v", flows)
}

// ---------- Negative test: constant filter strings produce no flow ----------

func TestRust_VectorDB_ConstantFilter_NoFlow(t *testing.T) {
	code := `
use qdrant_client::Qdrant;
use qdrant_client::qdrant::SearchPoints;
use lancedb::Table;

async fn handler(client: Qdrant, table: Table) {
    let req = SearchPoints {
        collection_name: "memories".to_string(),
        filter: None,
        limit: 10,
        ..Default::default()
    };
    client.search_points(req).await.unwrap();
    table.delete("status = 'archived'").await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.qdrant.search_points" || f.Sink.ID == "rust.lancedb.table.delete" {
			t.Errorf("unexpected flow on constant input: sink=%s", f.Sink.ID)
		}
	}
	_ = taint.SnkSQLQuery
}
