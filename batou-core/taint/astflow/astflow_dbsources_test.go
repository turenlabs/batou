package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog registration tests ---
// Verify new database source entries are indexed in the CatalogMatcher.

func TestCatalogMatcher_DatabaseSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	sinks := cat.Sinks()
	sanitizers := cat.Sanitizers()
	matcher := NewCatalogMatcher(sources, sinks, sanitizers, nil)

	expectedMethods := []string{
		"Scan",          // database/sql rows.Scan, row.Scan, GORM .Scan
		"First",         // GORM
		"Find",          // GORM, mongo
		"Last",          // GORM
		"Take",          // GORM
		"Pluck",         // GORM
		"Get",           // sqlx
		"Select",        // sqlx
		"CollectRows",   // pgx (indexed under final component of "pgx.CollectRows")
		"CollectOneRow", // pgx (indexed under final component of "pgx.CollectOneRow")
		"FindOne",       // mongo
		"Decode",        // mongo SingleResult
		"All",           // ent Query().All
		"Only",          // ent Query().Only
	}

	for _, method := range expectedMethods {
		if len(matcher.sourcesByMethod[method]) == 0 {
			t.Errorf("expected %q to be indexed as a database source", method)
		}
	}
}

func TestCatalogMatcher_RedisSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	for _, method := range []string{"Get", "HGet"} {
		found := false
		for _, src := range matcher.sourcesByMethod[method] {
			if src.Category == taint.SrcExternal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as SrcExternal (Redis)", method)
		}
	}
}

// --- End-to-end flow tests ---
// These test patterns where the return value carries database data directly.

func TestAnalyzeGo_MongoFindOne_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"go.mongodb.org/mongo-driver/mongo"
)

func handler(collection *mongo.Collection, db *sql.DB) {
	result := collection.FindOne(nil, nil)
	db.Query("SELECT * FROM logs WHERE id = '" + result + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongo FindOne → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDatabase) {
		t.Error("expected source category to be SrcDatabase")
	}
}

func TestAnalyzeGo_MongoFind_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"go.mongodb.org/mongo-driver/mongo"
)

func handler(collection *mongo.Collection, db *sql.DB) {
	cursor := collection.Find(nil, nil)
	db.Query("SELECT * FROM logs WHERE id = '" + cursor + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongo Find → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PgxCollectRows_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/jackc/pgx/v5"
)

func handler(db *sql.DB) {
	names := pgx.CollectRows(nil, nil)
	db.Query("SELECT * FROM logs WHERE name = '" + names + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: pgx.CollectRows → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PgxCollectOneRow_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/jackc/pgx/v5"
)

func handler(db *sql.DB) {
	name := pgx.CollectOneRow(nil, nil)
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: pgx.CollectOneRow → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_GormPluck_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"gorm.io/gorm"
)

func handler(gormDB *gorm.DB, db *sql.DB) {
	names := gormDB.Pluck("name", nil)
	db.Query("SELECT * FROM logs WHERE name = '" + names + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: GORM Pluck → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_DatabaseSource_Safe_Literal(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	name := "hardcoded_value"
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase {
			t.Error("should not detect database source when value is a literal string")
		}
	}
}

func TestAnalyzeGo_RedisGet_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.Get(nil, "user:name")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis Get → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
