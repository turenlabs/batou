package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// Android SQLiteDatabase structured-query methods (query/delete/update) take an
// SQL-injectable WHERE-clause/selection string argument. Only rawQuery/execSQL
// (full-SQL-string sinks) were previously modeled; these cover the selection arg.

func TestKotlin_AndroidSQLite_Query_Selection(t *testing.T) {
	code := `
import android.database.sqlite.SQLiteDatabase

fun handler(request: HttpServletRequest) {
    val name = request.getParameter("name")
    val selection = "name = '" + name + "'"
    val cursor = db.query("users", arrayOf("id"), selection, null, null, null, null)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> SQLiteDatabase.query() selection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_AndroidSQLite_Delete_WhereClause(t *testing.T) {
	code := `
import android.database.sqlite.SQLiteDatabase

fun handler(request: HttpServletRequest) {
    val id = request.getParameter("id")
    val where = "id = " + id
    db.delete("users", where, null)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> SQLiteDatabase.delete() whereClause")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_AndroidSQLite_Update_WhereClause(t *testing.T) {
	code := `
import android.database.sqlite.SQLiteDatabase

fun handler(request: HttpServletRequest) {
    val id = request.getParameter("id")
    val where = "id = " + id
    db.update("users", values, where, null)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> SQLiteDatabase.update() whereClause")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: parameterized selection (constant WHERE + selectionArgs) is
// safe — the tainted value flows to selectionArgs (arg 3), not the selection
// string (arg 2), so no flow should be reported.
func TestKotlin_AndroidSQLite_Query_Parameterized_NoFlow(t *testing.T) {
	code := `
import android.database.sqlite.SQLiteDatabase

fun handler(request: HttpServletRequest) {
    val name = request.getParameter("name")
    val cursor = db.query("users", arrayOf("id"), "name = ?", arrayOf(name), null, null, null)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL injection flow for parameterized query (selectionArgs placeholder)")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
