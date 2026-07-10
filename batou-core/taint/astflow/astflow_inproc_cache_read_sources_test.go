package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Catalog registration: each new in-process cache read source (allegro/bigcache
// and coocood/freecache) is indexed under its method name as SrcExternal.
func TestCatalogMatcher_InProcCacheReadSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	matcher := NewCatalogMatcher(cat.Sources(), nil, nil, nil)

	methods := []string{"GetWithInfo", "GetWithBuf", "Peek"}
	for _, method := range methods {
		found := false
		for _, src := range matcher.sourcesByMethod[method] {
			if src.Category == taint.SrcExternal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as SrcExternal (in-process cache read)", method)
		}
	}
}

// --- bigcache: typed-receiver path (TypeEnv resolves *bigcache.BigCache) ---

func TestAnalyzeGo_BigcacheGet_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/allegro/bigcache/v3"
)

func handler(cache *bigcache.BigCache, db *sql.DB) {
	val, _ := cache.Get("user:profile")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: bigcache Get → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_BigcacheGetWithInfo_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/allegro/bigcache/v3"
)

func handler(cache *bigcache.BigCache, db *sql.DB) {
	val, _, _ := cache.GetWithInfo("user:profile")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: bigcache GetWithInfo → db.Query")
	}
}

// --- freecache: typed-receiver path (TypeEnv resolves *freecache.Cache) ---

func TestAnalyzeGo_FreecacheGet_SecondOrderCommand(t *testing.T) {
	code := `package main

import (
	"os/exec"
	"github.com/coocood/freecache"
)

func handler(cache *freecache.Cache) {
	val, _ := cache.Get([]byte("cmd"))
	exec.Command("sh", "-c", "echo "+val)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command injection: freecache Get → exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_FreecacheGetWithBuf_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/coocood/freecache"
)

func handler(cache *freecache.Cache, db *sql.DB) {
	buf := make([]byte, 64)
	val, _ := cache.GetWithBuf([]byte("k"), buf)
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: freecache GetWithBuf → db.Query")
	}
}

func TestAnalyzeGo_FreecachePeek_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/coocood/freecache"
)

func handler(cache *freecache.Cache, db *sql.DB) {
	val, _ := cache.Peek([]byte("k"))
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: freecache Peek → db.Query")
	}
}

// --- heuristic path: untyped `:=` local resolved by receiver name in matcher.go ---

func TestAnalyzeGo_BigcacheGet_UntypedLocalHeuristic(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/allegro/bigcache/v3"
)

func handler(db *sql.DB) {
	cache := bigcache.New(bigcache.DefaultConfig(0))
	val, _ := cache.Get("user:profile")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection via untyped `cache :=` receiver heuristic")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- negative control: constant cache key value, no user-derived data ---

func TestAnalyzeGo_BigcacheGet_ConstantNoFlow(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	val := "static-label"
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a flow for a constant string assigned without a cache read")
	}
}
