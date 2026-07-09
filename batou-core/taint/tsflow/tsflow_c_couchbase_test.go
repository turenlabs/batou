package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C libcouchbase N1QL / Analytics / FTS injection tests (SnkSQLQuery / CWE-943)
// =========================================================================

func TestC_Couchbase_CmdQueryStatement_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_user_query(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDQUERY *cmd;
    lcb_cmdquery_create(&cmd);
    lcb_cmdquery_statement(cmd, qs, strlen(qs));
    lcb_query(instance, NULL, cmd);
    lcb_cmdquery_destroy(cmd);
}
`
	flows := Analyze(code, "/app/cb_query.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected N1QL injection flow for getenv -> lcb_cmdquery_statement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_CmdAnalyticsStatement_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_user_analytics(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDANALYTICS *cmd;
    lcb_cmdanalytics_create(&cmd);
    lcb_cmdanalytics_statement(cmd, qs, strlen(qs));
    lcb_analytics(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_analytics.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SQL++ analytics injection flow for getenv -> lcb_cmdanalytics_statement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_CmdQueryPayload_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_raw_query(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDQUERY *cmd;
    lcb_cmdquery_create(&cmd);
    lcb_cmdquery_payload(cmd, qs, strlen(qs));
    lcb_query(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_payload.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected N1QL DSL injection flow for getenv -> lcb_cmdquery_payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_CmdAnalyticsPayload_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_raw_analytics(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDANALYTICS *cmd;
    lcb_cmdanalytics_create(&cmd);
    lcb_cmdanalytics_payload(cmd, qs, strlen(qs));
    lcb_analytics(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_analytics_payload.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SQL++ DSL injection flow for getenv -> lcb_cmdanalytics_payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_CmdSearchPayload_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_user_fts(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDSEARCH *cmd;
    lcb_cmdsearch_create(&cmd);
    lcb_cmdsearch_payload(cmd, qs, strlen(qs));
    lcb_search(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_search.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected FTS DSL injection flow for getenv -> lcb_cmdsearch_payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_N1qlSetquery_V2_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/n1ql.h>
#include <stdlib.h>

void run_v2_query(lcb_t instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDN1QL cmd = {0};
    lcb_n1ql_setquery(&cmd, qs, strlen(qs), LCB_N1P_QUERY_STATEMENT);
    lcb_n1ql_query(instance, NULL, &cmd);
}
`
	flows := Analyze(code, "/app/cb_v2_query.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected v2 N1QL injection flow for getenv -> lcb_n1ql_setquery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_N1pSetstmt_V2_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/n1ql.h>
#include <stdlib.h>

void run_v2_params(void) {
    const char *qs = getenv("QUERY_STRING");
    lcb_N1QLPARAMS *params = lcb_n1p_new();
    lcb_n1p_setstmt(params, qs, strlen(qs));
}
`
	flows := Analyze(code, "/app/cb_v2_params.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected v2 N1QL params injection flow for getenv -> lcb_n1p_setstmt")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_N1pSetstmtz_V2_FromCGI(t *testing.T) {
	code := `
#include <libcouchbase/n1ql.h>
#include <stdlib.h>

void run_v2_paramsz(void) {
    const char *qs = getenv("QUERY_STRING");
    lcb_N1QLPARAMS *params = lcb_n1p_new();
    lcb_n1p_setstmtz(params, qs);
}
`
	flows := Analyze(code, "/app/cb_v2_paramsz.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected v2 N1QL params (z) injection flow for getenv -> lcb_n1p_setstmtz")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sanitizer tests: parameterized binding must NOT trigger ---

func TestC_Couchbase_NamedParam_Safe(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_safe_query(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDQUERY *cmd;
    lcb_cmdquery_create(&cmd);
    lcb_cmdquery_statement(cmd, "SELECT * FROM users WHERE name = $name", 39);
    lcb_cmdquery_named_param(cmd, "name", 4, qs, strlen(qs));
    lcb_query(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect N1QL injection flow when value is bound via lcb_cmdquery_named_param")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_PositionalParam_Safe(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_safe_pos(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDQUERY *cmd;
    lcb_cmdquery_create(&cmd);
    lcb_cmdquery_statement(cmd, "SELECT * FROM users WHERE name = $1", 36);
    lcb_cmdquery_positional_param(cmd, qs, strlen(qs));
    lcb_query(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_safe_pos.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect N1QL injection flow when value is bound via lcb_cmdquery_positional_param")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Couchbase_AnalyticsNamedParam_Safe(t *testing.T) {
	code := `
#include <libcouchbase/couchbase.h>
#include <stdlib.h>

void run_safe_ana(lcb_INSTANCE *instance) {
    const char *qs = getenv("QUERY_STRING");
    lcb_CMDANALYTICS *cmd;
    lcb_cmdanalytics_create(&cmd);
    lcb_cmdanalytics_statement(cmd, "SELECT * FROM ds WHERE id = $id", 32);
    lcb_cmdanalytics_named_param(cmd, "id", 2, qs, strlen(qs));
    lcb_analytics(instance, NULL, cmd);
}
`
	flows := Analyze(code, "/app/cb_safe_ana.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL++ injection flow when value is bound via lcb_cmdanalytics_named_param")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
