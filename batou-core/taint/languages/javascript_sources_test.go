package languages

import (
	"regexp"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestJSFrameworkSources_PRBBjs pins the new framework-aware sources
// added by PR-BBjs. We assert each entry is registered on both the JS
// and TS catalogs (the catalog auto-mirrors via tsCatalog), that the
// pattern is a valid Go RE2 regex, and that the pattern actually
// matches its canonical shape (and rejects the obvious negatives where
// a per-framework receiver constraint is in play).
func TestJSFrameworkSources_PRBBjs(t *testing.T) {
	cases := []struct {
		id        string
		positives []string
		negatives []string
		category  taint.SourceCategory
	}{
		// --- Express extras ---
		{id: "js.express.req.originalurl", positives: []string{"const x = req.originalUrl"}, negatives: []string{"const x = config.originalUrl"}, category: taint.SrcUserInput},
		{id: "js.express.req.protocol", positives: []string{"req.protocol === 'https'"}, negatives: []string{}, category: taint.SrcUserInput},
		{id: "js.express.req.subdomains", positives: []string{"const sub = req.subdomains[0]"}, category: taint.SrcUserInput},
		{id: "js.express.req.baseurl", positives: []string{"const base = req.baseUrl"}, category: taint.SrcUserInput},
		{id: "js.express.req.header", positives: []string{"req.header('X-Foo')"}, category: taint.SrcUserInput},
		{id: "js.express.req.accepts", positives: []string{"req.acceptsLanguages()", "req.accepts('html')", "req.acceptsCharsets()", "req.acceptsEncodings()"}, category: taint.SrcUserInput},

		// --- Fastify extras ---
		{id: "js.fastify.request.cookies", positives: []string{"const c = request.cookies"}, category: taint.SrcUserInput},
		{id: "js.fastify.request.url", positives: []string{"const u = request.url"}, category: taint.SrcUserInput},
		{id: "js.fastify.request.hostname", positives: []string{"request.hostname"}, category: taint.SrcUserInput},
		{id: "js.fastify.request.ip", positives: []string{"request.ip", "request.ips"}, category: taint.SrcUserInput},
		{id: "js.fastify.request.protocol", positives: []string{"request.protocol === 'https'"}, category: taint.SrcUserInput},

		// --- Koa extras ---
		{id: "js.koa.ctx.request.headers", positives: []string{"const h = ctx.request.headers"}, category: taint.SrcUserInput},
		{id: "js.koa.ctx.request.url", positives: []string{"ctx.url", "ctx.request.url"}, category: taint.SrcUserInput},
		{id: "js.koa.ctx.request.path", positives: []string{"ctx.path", "ctx.request.path"}, category: taint.SrcUserInput},
		{id: "js.koa.ctx.request.querystring", positives: []string{"ctx.querystring", "ctx.request.querystring"}, category: taint.SrcUserInput},
		{id: "js.koa.ctx.request.host", positives: []string{"ctx.host", "ctx.hostname", "ctx.request.host", "ctx.request.hostname"}, category: taint.SrcUserInput},
		{id: "js.koa.ctx.request.origin", positives: []string{"ctx.origin", "ctx.href", "ctx.request.origin", "ctx.request.href"}, category: taint.SrcUserInput},
		{id: "js.koa.ctx.request.ip", positives: []string{"ctx.ip", "ctx.ips", "ctx.request.ip"}, category: taint.SrcUserInput},

		// --- Hapi extras ---
		{id: "js.hapi.request.url", positives: []string{"request.url.pathname"}, category: taint.SrcUserInput},
		{id: "js.hapi.request.path", positives: []string{"request.path === '/x'"}, category: taint.SrcUserInput},
		{id: "js.hapi.request.info", positives: []string{"request.info.remoteAddress", "request.info.host"}, category: taint.SrcUserInput},
		{id: "js.hapi.request.mime", positives: []string{"const m = request.mime"}, category: taint.SrcUserInput},
		{id: "js.hapi.request.orig", positives: []string{"request.orig.payload", "request.orig.params"}, category: taint.SrcUserInput},

		// --- Next.js extras ---
		{id: "js.nextjs.api.req.headers", positives: []string{"const h = req.headers"}, category: taint.SrcUserInput},
		{id: "js.nextjs.api.req.cookies", positives: []string{"const c = req.cookies"}, category: taint.SrcUserInput},
		{id: "js.nextjs.nextrequest.headers.get", positives: []string{"request.headers.get('x-foo')", "req.headers.get('authorization')"}, category: taint.SrcUserInput},
		{id: "js.nextjs.nextrequest.cookies.get", positives: []string{"request.cookies.get('token')", "req.cookies.get('sid')"}, category: taint.SrcUserInput},
		{id: "js.nextjs.nextrequest.formdata", positives: []string{"await request.formData()", "await req.formData()"}, category: taint.SrcUserInput},

		// --- NestJS extras ---
		{id: "js.nestjs.req", positives: []string{"async getX(@Req() req) {}", "async getY(@Request() request) {}"}, category: taint.SrcUserInput},
		{id: "js.nestjs.session", positives: []string{"async getX(@Session() session) {}"}, category: taint.SrcUserInput},
		{id: "js.nestjs.hostparam", positives: []string{"async getX(@HostParam('tenant') tenant: string) {}"}, category: taint.SrcUserInput},
		{id: "js.nestjs.ip", positives: []string{"async getX(@Ip() ip) {}"}, category: taint.SrcUserInput},
		{id: "js.nestjs.uploadedfile", positives: []string{"async getX(@UploadedFile() file) {}", "async getY(@UploadedFiles() files) {}"}, category: taint.SrcUserInput},
	}

	jsByID := map[string]taint.SourceDef{}
	for _, s := range taint.SourcesForLanguage(rules.LangJavaScript) {
		jsByID[s.ID] = s
	}
	tsByID := map[string]taint.SourceDef{}
	for _, s := range taint.SourcesForLanguage(rules.LangTypeScript) {
		tsByID[s.ID] = s
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got, ok := jsByID[c.id]
			if !ok {
				t.Fatalf("JS source %s not registered", c.id)
			}
			if got.Category != c.category {
				t.Errorf("JS source %s: category=%v, want %v", c.id, got.Category, c.category)
			}
			// Mirror onto TypeScript: the catalog rewrites "js." to "ts.".
			tsID := "ts." + c.id[3:]
			if _, ok := tsByID[tsID]; !ok {
				t.Errorf("TS source %s not registered (catalog mirror)", tsID)
			}
			// Regex compiles and matches positives.
			re, err := regexp.Compile(got.Pattern)
			if err != nil {
				t.Fatalf("JS source %s: regex compile error: %v", c.id, err)
			}
			for _, p := range c.positives {
				if !re.MatchString(p) {
					t.Errorf("JS source %s: expected pattern %q to match %q", c.id, got.Pattern, p)
				}
			}
			for _, n := range c.negatives {
				if re.MatchString(n) {
					t.Errorf("JS source %s: expected pattern %q to NOT match %q", c.id, got.Pattern, n)
				}
			}
		})
	}
}

// TestJSClientStorageSources pins that localStorage/sessionStorage reads are
// categorised as SrcClientStorage (same-origin client-persisted app state), not
// SrcExternal. Combined with confidence.go's genuineExternalSourceCategories
// (which excludes client_storage) this demotes them from the block lane while
// still seeding taint flows for hint-tier second-order (persisted-XSS) findings.
// Anchoring is receiver-specific: a bare `.getItem()` on some other object
// (e.g. an app cache) does NOT match these patterns, so it is not a source.
func TestJSClientStorageSources(t *testing.T) {
	jsByID := map[string]taint.SourceDef{}
	for _, s := range taint.SourcesForLanguage(rules.LangJavaScript) {
		jsByID[s.ID] = s
	}
	cases := []struct {
		id       string
		positive string
		negative string
	}{
		{"js.localstorage.getitem", "JSON.parse(localStorage.getItem('k'))", "cache.getItem('k')"},
		{"js.sessionstorage.getitem", "sessionStorage.getItem('k')", "myMap.getItem('k')"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got, ok := jsByID[c.id]
			if !ok {
				t.Fatalf("JS source %s not registered", c.id)
			}
			if got.Category != taint.SrcClientStorage {
				t.Errorf("%s: category=%v, want SrcClientStorage", c.id, got.Category)
			}
			re := regexp.MustCompile(got.Pattern)
			if !re.MatchString(c.positive) {
				t.Errorf("%s: pattern %q should match %q", c.id, got.Pattern, c.positive)
			}
			// Bare `.getItem()` on an unrelated receiver must NOT be seeded as a
			// client-storage source (receiver-anchored, not receiver-blind).
			if re.MatchString(c.negative) {
				t.Errorf("%s: pattern %q should NOT match unrelated receiver %q", c.id, got.Pattern, c.negative)
			}
		})
	}
}

// TestJSSanitizers_PRBBjs verifies the validator.isEmail /
// validator.normalizeEmail sanitizers landed.
func TestJSSanitizers_PRBBjs(t *testing.T) {
	sans := taint.SanitizersForLanguage(rules.LangJavaScript)
	want := []string{"js.validator.isemail", "js.validator.normalizeemail"}
	idx := map[string]bool{}
	for _, s := range sans {
		idx[s.ID] = true
	}
	for _, id := range want {
		if !idx[id] {
			t.Errorf("expected JS sanitizer %s in catalog", id)
		}
	}
}
