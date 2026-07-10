package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- H3/Nitro sources ---

func TestJS_H3_GetQuery_SQLInjection(t *testing.T) {
	code := `
import { defineEventHandler, getQuery } from 'h3'

export default defineEventHandler(async (event) => {
    const query = getQuery(event)
    const results = await db.query("SELECT * FROM users WHERE name = '" + query.name + "'")
    return results
})
`
	flows := Analyze(code, "/app/server/api/users.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from getQuery -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_H3_ReadBody_SQLInjection(t *testing.T) {
	code := `
import { defineEventHandler, readBody } from 'h3'

export default defineEventHandler(async (event) => {
    const body = readBody(event)
    const name = body.name
    await db.query("INSERT INTO users (name) VALUES ('" + name + "')")
})
`
	flows := Analyze(code, "/app/server/api/create.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from readBody -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_H3_GetRouterParam_CommandInjection(t *testing.T) {
	code := `
import { defineEventHandler, getRouterParam } from 'h3'
const { exec } = require('child_process')

export default defineEventHandler(async (event) => {
    const id = getRouterParam(event, 'id')
    exec("process_user " + id)
})
`
	flows := Analyze(code, "/app/server/api/process.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from getRouterParam -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_H3_ReadFormData_SQLInjection(t *testing.T) {
	code := `
import { defineEventHandler, readFormData } from 'h3'

export default defineEventHandler(async (event) => {
    const formData = readFormData(event)
    const username = formData.get('username')
    await db.query("SELECT * FROM users WHERE name = '" + username + "'")
})
`
	flows := Analyze(code, "/app/server/api/login.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from readFormData -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_H3_GetRequestHeaders_LogInjection(t *testing.T) {
	code := `
import { defineEventHandler, getRequestHeaders } from 'h3'

export default defineEventHandler(async (event) => {
    const headers = getRequestHeaders(event)
    console.log("User-Agent: " + headers['user-agent'])
})
`
	flows := Analyze(code, "/app/server/api/log.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow from getRequestHeaders -> console.log")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- H3/Nitro sinks ---

func TestJS_H3_SendRedirect(t *testing.T) {
	code := `
import { defineEventHandler, getQuery, sendRedirect } from 'h3'

export default defineEventHandler(async (event) => {
    const query = getQuery(event)
    return sendRedirect(event, query.url)
})
`
	flows := Analyze(code, "/app/server/api/redirect.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow from getQuery -> sendRedirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_H3_SetResponseHeader(t *testing.T) {
	code := `
import { defineEventHandler, getQuery, setResponseHeader } from 'h3'

export default defineEventHandler(async (event) => {
    const query = getQuery(event)
    setResponseHeader(event, 'X-Custom', query.value)
})
`
	flows := Analyze(code, "/app/server/api/header.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow from getQuery -> setResponseHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- H3 safe patterns (no false positives) ---

func TestJS_H3_GetQuery_Sanitized_ParseInt(t *testing.T) {
	code := `
import { defineEventHandler, getQuery } from 'h3'

export default defineEventHandler(async (event) => {
    const query = getQuery(event)
    const id = parseInt(query.id, 10)
    await db.query("SELECT * FROM users WHERE id = " + id)
})
`
	flows := Analyze(code, "/app/server/api/safe.ts", rules.LangTypeScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection when parseInt sanitizes the input")
		}
	}
}

// --- AdonisJS sources ---

func TestJS_Adonis_RequestAll_SQLInjection(t *testing.T) {
	code := `
async function store(request) {
    const data = request.all()
    await db.query("INSERT INTO users (name) VALUES ('" + data + "')")
}
`
	flows := Analyze(code, "/app/controllers/UsersController.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.all() -> rawQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Adonis_RequestInput_CommandInjection(t *testing.T) {
	code := `
const { exec } = require('child_process')

export default class ToolController {
    async run({ request }) {
        const cmd = request.input('command')
        exec(cmd)
    }
}
`
	flows := Analyze(code, "/app/controllers/ToolController.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from request.input() -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Adonis_RequestOnly_SQLInjection(t *testing.T) {
	code := `
async function index(request) {
    const filters = request.only(['name', 'email'])
    await db.query("SELECT * FROM users WHERE name = '" + filters + "'")
}
`
	flows := Analyze(code, "/app/controllers/SearchController.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.only() -> rawQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Adonis_RequestQs_SQLInjection(t *testing.T) {
	code := `
async function search(request) {
    const qs = request.qs()
    await db.query("SELECT * FROM products WHERE category = '" + qs + "'")
}
`
	flows := Analyze(code, "/app/controllers/SearchController.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.qs() -> rawQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
