package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog registration test ---
// Verify the new gomemcache (bradfitz) read-source entries are indexed
// in the CatalogMatcher under their method names.

func TestCatalogMatcher_MemcacheSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	for _, method := range []string{"Get", "GetMulti", "GetAndTouch"} {
		found := false
		for _, src := range matcher.sourcesByMethod[method] {
			if src.Category == taint.SrcExternal &&
				src.ObjectType == "*memcache.Client" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected method %q to be indexed as SrcExternal on *memcache.Client", method)
		}
	}
}

// --- End-to-end flow tests ---
// Each test verifies that data read from memcached can flow into a
// downstream sensitive sink (second-order taint).

func TestAnalyzeGo_MemcacheGet_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/bradfitz/gomemcache/memcache"
)

func handler(mc *memcache.Client, db *sql.DB) {
	val := mc.Get("user:name")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Memcache Get → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_MemcacheGetMulti_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/bradfitz/gomemcache/memcache"
)

func handler(mc *memcache.Client, db *sql.DB) {
	vals := mc.GetMulti([]string{"user:1", "user:2"})
	db.Query("SELECT * FROM logs WHERE id IN (" + vals + ")")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Memcache GetMulti → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_MemcacheGetAndTouch_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/bradfitz/gomemcache/memcache"
)

func handler(mc *memcache.Client, db *sql.DB) {
	val := mc.GetAndTouch("session:42", 60)
	db.Query("SELECT * FROM logs WHERE token = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Memcache GetAndTouch → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Receiver-name variant: matcher.go supports mc/memcache/memclient.
func TestAnalyzeGo_MemcacheGet_AlternateReceiverNames(t *testing.T) {
	for _, recv := range []string{"memcache", "memclient"} {
		code := `package main

import (
	"database/sql"
	"github.com/bradfitz/gomemcache/memcache"
)

func handler(` + recv + ` *memcache.Client, db *sql.DB) {
	val := ` + recv + `.Get("user")
	db.Query("SELECT * FROM logs WHERE id = '" + val + "'")
}
`
		flows := AnalyzeGo(code, "/app/handler.go")
		if !hasTaintFlow(flows, taint.SnkSQLQuery) {
			t.Errorf("receiver %q: expected SQL flow from Memcache Get", recv)
		}
	}
}

// Negative regression: a constant string written into the SQL must NOT
// trigger a Memcache-source flow. Guards against the source pattern
// over-firing on unrelated literals.
func TestAnalyzeGo_MemcacheGet_NegativeConstantQuery(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/bradfitz/gomemcache/memcache"
)

func handler(mc *memcache.Client, db *sql.DB) {
	_, _ = mc.Get("ignored")
	db.Query("SELECT * FROM logs WHERE id = 'static'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal && f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected second-order SQLi flow on constant query: %v", f)
		}
	}
}
