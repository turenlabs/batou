package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// etcd clientv3 + HashiCorp Consul KV — second-order read sources
// =========================================================================
//
// Both stores hold shared config/data written by one actor and read back by
// another. A value (or key) that originated from user input is still tainted
// on read-back; feeding it into a query/command/template sink without
// re-validation is second-order injection. These tests verify the new sources
// fire and that their results flow into downstream sinks.

// --- Catalog registration test ---

func TestCatalogMatcher_EtcdConsulSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}
	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	want := []struct {
		method string
		obj    string
	}{
		{"Get", "*clientv3.Client"},
		{"Get", "*api.KV"},
		{"List", "*api.KV"},
		{"Keys", "*api.KV"},
	}
	for _, w := range want {
		found := false
		for _, src := range matcher.sourcesByMethod[w.method] {
			if src.Category == taint.SrcExternal && src.ObjectType == w.obj {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected method %q to be indexed as SrcExternal on %s", w.method, w.obj)
		}
	}
}

// --- End-to-end flow tests (typed receivers: precise TypeEnv match) ---

func TestAnalyzeGo_EtcdGet_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func handler(cli *clientv3.Client, db *sql.DB, ctx context.Context) {
	val := cli.Get(ctx, "user:name")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: etcd cli.Get → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_ConsulKVGet_SecondOrderCmdi(t *testing.T) {
	code := `package main

import (
	"os/exec"
	"github.com/hashicorp/consul/api"
)

func handler(kv *api.KV) {
	val := kv.Get("deploy/cmd")
	exec.Command("sh", "-c", "echo "+val)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command injection: Consul kv.Get → exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_ConsulKVList_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/hashicorp/consul/api"
)

func handler(kv *api.KV, db *sql.DB) {
	vals := kv.List("services/")
	db.Query("SELECT * FROM logs WHERE id IN (" + vals + ")")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Consul kv.List → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_ConsulKVKeys_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/hashicorp/consul/api"
)

func handler(kv *api.KV, db *sql.DB) {
	keys := kv.Keys("services/", "/")
	db.Query("SELECT * FROM logs WHERE k = '" + keys + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Consul kv.Keys → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Fallback-path test (untyped `:=` local: exercises the matcher case) ---
//
// Real etcd code binds the client via `cli, _ := clientv3.New(cfg)`, an
// untyped-to-TypeEnv local. This test would NOT match via the precise
// typeMatches path; it only fires because matchesReceiverType resolves the
// `cli` receiver for *clientv3.Client. It therefore proves the new matcher
// case is wired correctly.

func TestAnalyzeGo_EtcdGet_UntypedLocal_FallbackPath(t *testing.T) {
	code := `package main

import "database/sql"

func newCli() interface{ Get(k string) string } { return nil }

func handler(db *sql.DB) {
	cli := newCli()
	val := cli.Get("user:name")
	db.Query("SELECT * FROM logs WHERE name = '" + val + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection via receiver-name fallback: cli.Get → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative: constant key/value + constant SQL → no flow ---

func TestAnalyzeGo_EtcdConsul_NoFlow_OnConstant(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
	"github.com/hashicorp/consul/api"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func handler(cli *clientv3.Client, kv *api.KV, db *sql.DB, ctx context.Context) {
	_ = cli.Get(ctx, "k")
	_ = kv.Get("k")
	_ = kv.List("p")
	db.Query("SELECT * FROM logs WHERE id = 1")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect a SQL flow for discarded reads + constant SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
