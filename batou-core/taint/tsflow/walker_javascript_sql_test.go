package tsflow

// PR-CATjs-5: SQL query-builder safe-form gate. Bookshelf/Knex .query() /
// .where() / .andWhere() / .orWhere() / .whereRaw() accept several safe
// parameter-binding shapes — only raw-string-with-interpolation /
// string-concat shapes are SQL injection vectors. Real-world Ghost scans
// produced ~9 FPs on `model.related('foo').query({...})` etc.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

func hasJSSqlFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			return true
		}
	}
	return false
}

// Bookshelf `model.related('foo').query({...})` — object-form
// parameter binding. Safe.
func TestJS_SQL_BookshelfRelatedQuery_ObjectArg_NotFlagged(t *testing.T) {
	code := `
function handler(req, res) {
    const id = req.params.id;
    Model.where({id: id}).related('foo').query({where: {col: id}});
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasJSSqlFlow(flows) {
		t.Errorf("Bookshelf model.related('foo').query({...}) should NOT fire SQL sink")
	}
}

// Knex `.where({col: val})` — object form, parameter binding. Safe.
func TestJS_SQL_KnexWhereObject_NotFlagged(t *testing.T) {
	code := `
function handler(req) {
    const userId = req.params.id;
    knex('users').where({user_id: userId}).first();
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasJSSqlFlow(flows) {
		t.Errorf("knex('users').where({col: val}) should NOT fire SQL sink")
	}
}

// Knex comparator form `.where('col', op, val)` — string literal +
// extra args = parameter binding. Safe.
func TestJS_SQL_KnexWhereComparator_NotFlagged(t *testing.T) {
	code := `
function handler(req) {
    const userId = req.params.id;
    knex('users').where('user_id', '=', userId).first();
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasJSSqlFlow(flows) {
		t.Errorf("knex.where('col', op, val) should NOT fire SQL sink")
	}
}

// Knex `.whereRaw('id = ?', [id])` — parameterized raw, bind array. Safe.
func TestJS_SQL_KnexWhereRawParameterized_NotFlagged(t *testing.T) {
	code := `
function handler(req) {
    const userId = req.params.id;
    knex('users').whereRaw('user_id = ?', [userId]).first();
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasJSSqlFlow(flows) {
		t.Errorf("knex.whereRaw('id = ?', [id]) parameterized form should NOT fire SQL sink")
	}
}

// `.query(`SELECT * FROM x WHERE id = ${userId}`)` on a plain receiver
// (NOT `.related()`) with template-substitution arg — real SQL
// injection. SHOULD flag.
func TestJS_SQL_QueryTemplateInterpolation_StillFlagged(t *testing.T) {
	code := `
function handler(req) {
    const userId = req.params.id;
    db.query(` + "`" + `SELECT * FROM users WHERE id = ${userId}` + "`" + `);
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if !hasJSSqlFlow(flows) {
		t.Errorf("db.query(`SELECT ... ${tainted}`) template-interpolation form SHOULD fire SQL sink")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s", f.Sink.ID, f.Sink.Category)
		}
	}
}

// Ember adapter `super.query(store, type, params)` — class hierarchy
// dispatch, not SQL.
func TestJS_SQL_SuperQuery_NotFlagged(t *testing.T) {
	code := `
class MyAdapter {
    query(store, type, params) {
        return super.query(store, type, params);
    }
}
`
	flows := Analyze(code, "/app/adapter.js", rules.LangJavaScript)
	if hasJSSqlFlow(flows) {
		t.Errorf("super.query(...) Ember adapter call should NOT fire SQL sink")
	}
}

// Callback subquery `.where(qb => qb.where(...))` — safe (the inner
// where on the qb is still a parameter-binding context).
func TestJS_SQL_WhereCallback_NotFlagged(t *testing.T) {
	code := `
function handler(req) {
    const userId = req.params.id;
    knex('users').where(qb => qb.where('user_id', userId)).first();
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasJSSqlFlow(flows) {
		t.Errorf("knex.where(qb => qb.where(...)) callback subquery should NOT fire SQL sink")
	}
}
