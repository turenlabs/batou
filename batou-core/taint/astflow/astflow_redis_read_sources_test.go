package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Catalog registration: each new go-redis read source is indexed under its method name.
func TestCatalogMatcher_RedisReadSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	matcher := NewCatalogMatcher(cat.Sources(), nil, nil, nil)

	methods := []string{
		"HGetAll", "HKeys", "HVals", "HMGet",
		"MGet",
		"LRange", "LIndex", "LPop", "RPop",
		"SMembers", "SRandMember", "SPop",
		"ZRange", "ZRevRange", "ZRangeByScore",
	}
	for _, method := range methods {
		found := false
		for _, src := range matcher.sourcesByMethod[method] {
			if src.Category == taint.SrcExternal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as SrcExternal (Redis read)", method)
		}
	}
}

// End-to-end second-order flow tests: Redis read → SQL query.
// Each test mirrors the existing TestAnalyzeGo_RedisGet_SecondOrderSQLi pattern.

func TestAnalyzeGo_RedisHGetAll_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.HGetAll(nil, "user:profile")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis HGetAll → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_RedisHKeys_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.HKeys(nil, "user:profile")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis HKeys → db.Query")
	}
}

func TestAnalyzeGo_RedisHVals_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.HVals(nil, "user:profile")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis HVals → db.Query")
	}
}

func TestAnalyzeGo_RedisHMGet_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.HMGet(nil, "user:profile", "name", "email")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis HMGet → db.Query")
	}
}

func TestAnalyzeGo_RedisMGet_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.MGet(nil, "k1", "k2", "k3")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis MGet → db.Query")
	}
}

func TestAnalyzeGo_RedisLRange_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.LRange(nil, "queue:names", 0, -1)
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis LRange → db.Query")
	}
}

func TestAnalyzeGo_RedisLIndex_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.LIndex(nil, "queue:names", 0)
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis LIndex → db.Query")
	}
}

func TestAnalyzeGo_RedisLPop_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.LPop(nil, "queue:names")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis LPop → db.Query")
	}
}

func TestAnalyzeGo_RedisRPop_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.RPop(nil, "queue:names")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis RPop → db.Query")
	}
}

func TestAnalyzeGo_RedisSMembers_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.SMembers(nil, "set:tags")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis SMembers → db.Query")
	}
}

func TestAnalyzeGo_RedisSRandMember_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.SRandMember(nil, "set:tags")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis SRandMember → db.Query")
	}
}

func TestAnalyzeGo_RedisSPop_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.SPop(nil, "set:tags")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis SPop → db.Query")
	}
}

func TestAnalyzeGo_RedisZRange_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.ZRange(nil, "zset:scores", 0, -1)
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis ZRange → db.Query")
	}
}

func TestAnalyzeGo_RedisZRevRange_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.ZRevRange(nil, "zset:scores", 0, -1)
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis ZRevRange → db.Query")
	}
}

func TestAnalyzeGo_RedisZRangeByScore_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/redis/go-redis/v9"
)

func handler(rdb *redis.Client, db *sql.DB) {
	val := rdb.ZRangeByScore(nil, "zset:scores", nil)
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Redis ZRangeByScore → db.Query")
	}
}

// Negative test: hardcoded literal (not a Redis read) must NOT produce SrcExternal flow.
// Guards against the new entries being too broad and matching unrelated code.
func TestAnalyzeGo_RedisRead_Safe_Literal(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	name := "hardcoded_value"
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal {
			t.Errorf("should not detect SrcExternal source on literal-only code; got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
