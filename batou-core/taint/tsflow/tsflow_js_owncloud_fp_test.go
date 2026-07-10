package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// owncloud/web false-positive regression tests (E6-T6)
//
// A 2026-04-24 scan of owncloud/web produced ~94% FP. Two classes traced to
// the JS/TS taint catalog:
//
//   (a) CWE-943 (NoSQL injection) on Vue Test Utils chains like
//       `wrapper.findAll('.row').find(r => r.text() === x)` in .spec.ts —
//       `.find()` here is Array.prototype.find, not MongoCollection.find().
//       (The bare `.find(` Mongo CRUD sink and the bare `.findAll(` Sequelize
//       source were already tightened on 2026-04-25; these tests lock in that
//       the chain stays quiet while the real `$where` NoSQL vector keeps
//       firing.)
//
//   (b) CWE-918 (SSRF) on URLs built from admin config —
//       `new URL('/api', config.serverUrl); axios.get(url.toString())` —
//       caused by `new URL(...)` / `URLSearchParams(...)` being modeled as
//       taint *sources*. Removed: those constructors only re-package their
//       argument; taint already on the argument still propagates, so
//       request-tainted URLs still flow to the SSRF sinks.
// =========================================================================

func hasFlowCWE(flows []taint.TaintFlow, cwe string) bool {
	for _, f := range flows {
		if f.Sink.CWEID == cwe {
			return true
		}
	}
	return false
}

// --- (a) FP killed: Vue Test Utils findAll().find() in a .spec.ts file ---

func TestJS_OwncloudFP_VueTestUtils_FindAll_Find_NoNoSQL(t *testing.T) {
	code := `
import { mount } from '@vue/test-utils'
import Component from '../Component.vue'

describe('Component', () => {
  it('renders matching row', () => {
    const wrapper = mount(Component)
    const rows = wrapper.findAll('.oc-table-data-cell')
    const target = rows.find(r => r.text() === 'expected')
    expect(target).toBeDefined()
  })
})
`
	flows := Analyze(code, "/web/packages/web-app-files/tests/unit/components/Table.spec.ts", rules.LangTypeScript)
	if hasFlowCWE(flows, "CWE-943") {
		t.Error("expected NO CWE-943 (NoSQL) flow for Vue Test Utils wrapper.findAll(...).find(predicate)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// Same chain, but rooted in request-tainted input, so the FP isn't merely
// hiding behind "no source": Array.prototype.find on a wrapper array still
// must not be CWE-943.
func TestJS_OwncloudFP_ArrayFind_TaintedArray_NoNoSQL(t *testing.T) {
	code := `
import Component from '../Component.vue'

app.get('/rows', (req, res) => {
  const wrapper = createWrapper(Component, { props: { filter: req.query.filter } })
  const rows = wrapper.findAll('.row')
  const hit = rows.find(r => r.attributes('data-id') === req.query.id)
  res.json({ found: !!hit })
})
`
	flows := Analyze(code, "/web/packages/web-app-files/src/components/Table.spec.ts", rules.LangTypeScript)
	if hasFlowCWE(flows, "CWE-943") {
		t.Error("expected NO CWE-943 (NoSQL) flow for Array.prototype.find on a Vue Test Utils wrapper array")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- (a) TP kept: real Mongo $where injection still flags CWE-943 ---
//
// The `js.mongoose.where` sink (ObjectType "MongooseQuery") binds when the
// `.$where(...)` receiver names a Mongoose query — this is the genuine
// server-side-JS-eval NoSQL vector and must keep firing on user-tainted input.

func TestJS_Mongo_WhereInjection_StillNoSQL(t *testing.T) {
	code := `
app.get('/users/search', async (req, res) => {
  const term = req.query.term
  const mongooseQuery = UserModel.find()
  const docs = await mongooseQuery.$where('this.name == "' + term + '"')
  res.json(docs)
})
`
	flows := Analyze(code, "/app/routes/users.js", rules.LangJavaScript)
	if !hasFlowCWE(flows, "CWE-943") || !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CWE-943 (NoSQL) flow for req.query -> Mongoose .$where()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- (b) FP killed: URL/URLSearchParams built from admin config -> fetcher ---

func TestJS_OwncloudFP_URLFromConfig_AxiosGet_NoSSRF(t *testing.T) {
	code := `
import axios from 'axios'
import { config } from './config'

async function fetchData() {
  const url = new URL('/api/v1/data', config.serverUrl)
  const res = await axios.get(url.toString())
  return res.data
}
`
	flows := Analyze(code, "/web/packages/web-runtime/src/services/data.ts", rules.LangTypeScript)
	if hasFlowCWE(flows, "CWE-918") || hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO CWE-918 (SSRF) flow for new URL('/x', config.serverUrl) -> axios.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestJS_OwncloudFP_URLSearchParamsFromConfig_Fetch_NoSSRF(t *testing.T) {
	code := `
import { settings } from './settings'

async function load() {
  const qs = new URLSearchParams({ token: settings.apiToken })
  const res = await fetch(settings.apiBase + '?' + qs.toString())
  return res.json()
}
`
	flows := Analyze(code, "/web/packages/web-runtime/src/services/load.ts", rules.LangTypeScript)
	if hasFlowCWE(flows, "CWE-918") || hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO CWE-918 (SSRF) flow for new URLSearchParams({...settings...}) -> fetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// A bare module-level constant base URL is not user input either.
func TestJS_OwncloudFP_URLFromConstant_Fetch_NoSSRF(t *testing.T) {
	code := `
const API_BASE = 'https://service.example.com'

async function ping() {
  const url = new URL('/health', API_BASE)
  const res = await fetch(url)
  return res.ok
}
`
	flows := Analyze(code, "/web/packages/web-runtime/src/services/ping.ts", rules.LangTypeScript)
	if hasFlowCWE(flows, "CWE-918") || hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO CWE-918 (SSRF) flow for new URL('/health', API_BASE) -> fetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- (b) TP kept: request-tainted URL still flags CWE-918 ---

func TestJS_SSRF_URLFromRequest_AxiosGet_StillSSRF(t *testing.T) {
	code := `
import axios from 'axios'

app.get('/proxy', async (req, res) => {
  const target = req.query.target
  const upstream = await axios.get(new URL(target).toString())
  res.send(upstream.data)
})
`
	flows := Analyze(code, "/app/routes/proxy.js", rules.LangJavaScript)
	if !hasFlowCWE(flows, "CWE-918") || !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected CWE-918 (SSRF) flow for req.query.target -> new URL(...) -> axios.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestJS_SSRF_RequestUrl_Fetch_StillSSRF(t *testing.T) {
	code := `
app.get('/relay', async (req, res) => {
  const target = req.query.url
  const upstream = await fetch(new URL(target).toString())
  res.send(await upstream.text())
})
`
	flows := Analyze(code, "/app/routes/relay.js", rules.LangJavaScript)
	if !hasFlowCWE(flows, "CWE-918") || !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected CWE-918 (SSRF) flow for req.query.url -> new URL(...) -> fetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// And direct without the URL wrapper at all: `const u = req.query.x; fetch(u)`.
func TestJS_SSRF_RequestUrl_FetchDirect_StillSSRF(t *testing.T) {
	code := `
app.get('/relay', async (req, res) => {
  const target = req.query.url
  const upstream = await fetch(target)
  res.send(await upstream.text())
})
`
	flows := Analyze(code, "/app/routes/relay-direct.js", rules.LangJavaScript)
	if !hasFlowCWE(flows, "CWE-918") || !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected CWE-918 (SSRF) flow for req.query.url -> fetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}
