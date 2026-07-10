package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// JavaScript/TypeScript — Prisma ORM read-method sources for second-order
// taint detection.
//
// Prisma is the most widely-adopted Node.js ORM. The catalog already covers
// Prisma's raw-SQL sinks ($queryRaw / $executeRaw / $queryRawUnsafe /
// $executeRawUnsafe) but had no source entries for the canonical typed
// read API (findUnique / findUniqueOrThrow / findFirst / findFirstOrThrow /
// findMany). Without these, attacker-stored data round-tripped through a
// Prisma model and reflected to a sink on a later request produced zero
// flows — the same second-order gap that the Sequelize, Mongoose, Knex,
// PG and Redis source families already cover.
//
// Method names are distinctive to Prisma: no other major JS ORM uses
// findUnique / findFirst / findMany as its read API.
// ===========================================================================

// --- Catalog verification ---

func TestJS_Prisma_SourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJavaScript)
	if cat == nil {
		t.Fatal("JavaScript catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		if s.Category == taint.SrcDatabase {
			found[s.ID] = true
		}
	}
	want := []string{
		"js.prisma.findunique",
		"js.prisma.finduniqueorthrow",
		"js.prisma.findfirst",
		"js.prisma.findfirstorthrow",
		"js.prisma.findmany",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected Prisma SrcDatabase source: %s", id)
		}
	}
}

// --- Second-order taint: each Prisma read method feeds a different sink ---

func TestJS_Prisma_FindUnique_XSS(t *testing.T) {
	code := `
function renderProfile(id) {
    const user = prisma.user.findUnique({ where: { id: id } });
    res.send("<h1>" + user.bio + "</h1>");
}
`
	flows := Analyze(code, "/app/routes/profile.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from prisma.user.findUnique() result -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestJS_Prisma_FindUniqueOrThrow_CommandInjection(t *testing.T) {
	code := `
function runTask(taskId) {
    const task = prisma.task.findUniqueOrThrow({ where: { id: taskId } });
    exec(task.script);
}
`
	flows := Analyze(code, "/app/tasks/runner.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from prisma.task.findUniqueOrThrow() result -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestJS_Prisma_FindFirst_Eval(t *testing.T) {
	code := `
function loadConfig() {
    const cfg = prisma.config.findFirst({ where: { active: true } });
    eval(cfg.body);
}
`
	flows := Analyze(code, "/app/config.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from prisma.config.findFirst() result -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestJS_Prisma_FindFirstOrThrow_SecondOrderSQL(t *testing.T) {
	code := `
function runReport(userId) {
    const filter = prisma.filter.findFirstOrThrow({ where: { userId: userId } });
    prisma.$queryRawUnsafe(filter.sql);
}
`
	flows := Analyze(code, "/app/reports.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection from prisma.filter.findFirstOrThrow() result -> $queryRawUnsafe()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestJS_Prisma_FindMany_XSS(t *testing.T) {
	code := `
function listPosts() {
    const posts = prisma.post.findMany({ where: { published: true } });
    res.send("<ul>" + posts.map(p => p.title).join("") + "</ul>");
}
`
	flows := Analyze(code, "/app/routes/posts.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from prisma.post.findMany() results -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- Safe pattern: findUnique result returned as JSON does not trigger XSS ---

func TestJS_Prisma_FindUnique_Safe_JSONResponse(t *testing.T) {
	code := `
function apiGetUser(id) {
    const user = prisma.user.findUnique({ where: { id: id } });
    res.json(user);
}
`
	flows := Analyze(code, "/app/api/user.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("res.json() should not trigger XSS, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
