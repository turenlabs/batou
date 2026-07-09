// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Python strings for taint-flow unit tests
package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python Google BigQuery SQL injection sinks (CWE-89)
//
// Covers:
//   - google-cloud-bigquery: Client.query() / Client.query_and_wait()
//   - pandas_gbq.read_gbq()
//   - bigframes.pandas.read_gbq_query()
// =========================================================================

func TestPython_BigQuery_ClientQuery_SQLi(t *testing.T) {
	code := `
from flask import request
from google.cloud import bigquery

def endpoint():
    user_id = request.args.get("id")
    client = bigquery.Client()
    sql = "SELECT * FROM mydata.users WHERE id = " + user_id
    job = client.query(sql)
    return [dict(r) for r in job.result()]
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_BigQuery_ClientQueryAndWait_SQLi(t *testing.T) {
	code := `
from flask import request
from google.cloud import bigquery

def endpoint():
    name = request.form.get("name")
    client = bigquery.Client()
    sql = "DELETE FROM mydata.audit WHERE owner = '" + name + "'"
    rows = client.query_and_wait(sql)
    return "ok"
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.form -> client.query_and_wait()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_BigQuery_PandasGbqReadGbq_SQLi(t *testing.T) {
	code := `
from flask import request
import pandas_gbq

def endpoint():
    term = request.args.get("q")
    query = "SELECT * FROM mydata.products WHERE name LIKE '%" + term + "%'"
    df = pandas_gbq.read_gbq(query, project_id="my-project")
    return df.to_dict("records")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> pandas_gbq.read_gbq()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_BigQuery_BigframesReadGbqQuery_SQLi(t *testing.T) {
	code := `
from flask import request
import bigframes.pandas as bpd

def endpoint():
    region = request.args.get("region")
    sql = "SELECT id, total FROM mydata.sales WHERE region = '" + region + "'"
    df = bpd.read_gbq_query(sql)
    return df.to_pandas().to_dict("records")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> bigframes.pandas.read_gbq_query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: a constant SQL string with no tainted input should not produce
// a SnkSQLQuery flow. Guards against pattern over-broadness — the entry must
// trigger on tainted data, not on the call shape alone.
func TestPython_BigQuery_ConstantSQL_NoFlow(t *testing.T) {
	code := `
from google.cloud import bigquery

def report():
    client = bigquery.Client()
    job = client.query("SELECT COUNT(*) FROM mydata.users")
    return list(job.result())
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect a SnkSQLQuery flow for constant SQL with no tainted input")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
