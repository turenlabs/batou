// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Python strings for taint-flow unit tests
package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python pandas I/O + Keras model-loading sinks
//
// pandas.read_pickle / read_html / read_xml / read_sql* and
// keras.models.load_model all take a user-facing first argument
// (path / URL / raw bytes / SQL string). A tainted argument becomes:
//   - RCE via pickle / Lambda-layer deserialization  (read_pickle, load_model)
//     real CVEs: CVE-2024-3660 (Keras Lambda, CVSS 9.8),
//                CVE-2024-37052 .. CVE-2024-37060 (MLflow pickle)
//   - SSRF — read_html / read_xml fetch arbitrary URLs server-side  (CWE-918)
//   - SQL injection — read_sql / read_sql_query run a raw query      (CWE-89)
//
// read_sql / read_sql_query also keep their existing python_sources.go
// second-order DB-source role; here we exercise the *sink* direction.
//
// Python tsflow note: the walker only descends into function bodies, so
// every fixture wraps the call site in `def handler():`.
// =========================================================================

func TestPython_Pandas_ReadPickle_Deserialization(t *testing.T) {
	code := `
import pandas as pd
from flask import request

def handler():
    path = request.args.get("model")
    df = pd.read_pickle(path)
    return df.to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow: request.args -> pd.read_pickle()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Keras_LoadModel_Deserialization(t *testing.T) {
	code := `
from tensorflow import keras
from flask import request

def handler():
    model_path = request.args.get("path")
    model = keras.models.load_model(model_path)
    return model.summary()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow: request.args -> keras.models.load_model()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_MLflow_LoadModel_Deserialization(t *testing.T) {
	code := `
import mlflow.pyfunc
from flask import request

def handler():
    uri = request.args.get("uri")
    model = mlflow.pyfunc.load_model(uri)
    return str(model)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow: request.args -> mlflow.pyfunc.load_model()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Pandas_ReadHtml_SSRF(t *testing.T) {
	code := `
import pandas as pd
from flask import request

def handler():
    url = request.args.get("source")
    tables = pd.read_html(url)
    return tables[0].to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch flow: request.args -> pd.read_html()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Pandas_ReadXml_SSRF(t *testing.T) {
	code := `
import pandas
from flask import request

def handler():
    url = request.args.get("feed")
    df = pandas.read_xml(url)
    return df.to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch flow: request.args -> pandas.read_xml()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Pandas_ReadSqlQuery_SQLi(t *testing.T) {
	code := `
import pandas as pd
from flask import request

def handler(conn):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    df = pd.read_sql_query(query, conn)
    return df.to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow: request.args -> pd.read_sql_query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Pandas_ReadSql_SQLi(t *testing.T) {
	code := `
import pandas as pd
from flask import request

def handler(conn):
    table = request.args.get("table")
    df = pd.read_sql(table, conn)
    return df.to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow: request.args -> pd.read_sql()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative cases: constant first argument must NOT produce a flow ---

func TestPython_Pandas_ReadPickle_Constant_NoFlow(t *testing.T) {
	code := `
import pandas as pd

def handler():
    df = pd.read_pickle("data/cache.pkl")
    return df.to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("did NOT expect SnkDeserialize flow for constant path; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Keras_LoadModel_Constant_NoFlow(t *testing.T) {
	code := `
from tensorflow import keras

def handler():
    model = keras.models.load_model("models/prod.keras", safe_mode=True)
    return model.summary()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("did NOT expect SnkDeserialize flow for constant model path; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Pandas_ReadSqlQuery_Constant_NoFlow(t *testing.T) {
	code := `
import pandas as pd

def handler(conn):
    df = pd.read_sql_query("SELECT COUNT(*) FROM users", conn)
    return df.to_json()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did NOT expect SnkSQLQuery flow for constant query; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// batou:ignore-end
