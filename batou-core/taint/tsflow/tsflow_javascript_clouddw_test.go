package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// JavaScript/TypeScript — Cloud Data Warehouse SQL/PartiQL injection
// (CWE-89 / CWE-943) tests.
//
// Covers cloud-DW sink entries added to javascript_sinks.go:
//   - js.bigquery.client.createqueryjob          (Google Cloud BigQuery)
//   - js.aws.athena.startqueryexecutioncommand   (AWS Athena, SDK v3)
//   - js.aws.executestatementcommand             (Redshift Data / RDS Data /
//                                                 DynamoDB PartiQL)
//   - js.aws.batchexecutestatementcommand        (Redshift Data, DynamoDB)
//   - js.elasticsearch.searchtemplate            (Mustache template DSL)
//
// AWS SDK v3 uses the canonical Command-constructor pattern:
//     const cmd = new XxxCommand({Sql: tainted, ...})
//     await client.send(cmd)
// — so the constructor itself is the sink. tsflow handles new_expression in
// jsConfig.callTypes (langconfig.go:260), and the matcher fires on the bare
// constructor name when ObjectType is empty (matcher.go:197-199), so both
// `new Cmd(...)` and `new pkg.Cmd(...)` forms are detected.
// =========================================================================

// --- Google BigQuery -------------------------------------------------------

func TestJS_BigQuery_CreateQueryJob_PositionalSQLInjection(t *testing.T) {
	code := `
const {BigQuery} = require('@google-cloud/bigquery');
const bigquery = new BigQuery();

async function reportFor(req, res) {
    const corpus = req.query.corpus;
    const sql = "SELECT word FROM dataset.shakespeare WHERE corpus = '" + corpus + "'";
    const [job] = await bigquery.createQueryJob(sql);
    return await job.getQueryResults();
}
`
	flows := Analyze(code, "/app/handlers/bq_report.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.bigquery.client.createqueryjob") {
		t.Error("expected js.bigquery.client.createqueryjob flow from req.query -> bigquery.createQueryJob(sql)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_BigQuery_CreateQueryJob_OptionsObjectSQLInjection(t *testing.T) {
	code := `
const {BigQuery} = require('@google-cloud/bigquery');
const bigquery = new BigQuery();

async function search(req, res) {
    const term = req.body.term;
    const options = {
        query: "SELECT id FROM ds.items WHERE name LIKE '%" + term + "%'",
        location: 'US',
    };
    const [job] = await bigquery.createQueryJob(options);
    return await job.getQueryResults();
}
`
	flows := Analyze(code, "/app/handlers/bq_search.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.bigquery.client.createqueryjob") {
		t.Error("expected js.bigquery.client.createqueryjob flow from req.body -> bigquery.createQueryJob({query})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS Athena (SDK v3) ---------------------------------------------------

func TestJS_AWS_Athena_StartQueryExecutionCommand_SQLInjection(t *testing.T) {
	code := `
const { AthenaClient, StartQueryExecutionCommand } = require('@aws-sdk/client-athena');
const client = new AthenaClient({ region: 'us-east-1' });

async function runReport(req, res) {
    const tableName = req.query.table;
    const sql = "SELECT firstname, lastname FROM " + tableName + " WHERE state = 'CA'";
    const cmd = new StartQueryExecutionCommand({
        QueryString: sql,
        ResultConfiguration: { OutputLocation: 's3://results/' },
    });
    return await client.send(cmd);
}
`
	flows := Analyze(code, "/app/handlers/athena_report.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.aws.athena.startqueryexecutioncommand") {
		t.Error("expected js.aws.athena.startqueryexecutioncommand flow from req.query -> new StartQueryExecutionCommand({QueryString})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS Redshift Data API (SDK v3) ----------------------------------------

func TestJS_AWS_RedshiftData_ExecuteStatementCommand_SQLInjection(t *testing.T) {
	code := `
const { RedshiftDataClient, ExecuteStatementCommand } = require('@aws-sdk/client-redshift-data');
const client = new RedshiftDataClient({ region: 'us-west-2' });

async function loadOrders(req, res) {
    const userId = req.params.userId;
    const cmd = new ExecuteStatementCommand({
        ClusterIdentifier: 'analytics-prod',
        Database: 'orders',
        Sql: "SELECT * FROM orders WHERE user_id = '" + userId + "'",
    });
    return await client.send(cmd);
}
`
	flows := Analyze(code, "/app/handlers/redshift_orders.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.aws.executestatementcommand") {
		t.Error("expected js.aws.executestatementcommand flow from req.params -> new ExecuteStatementCommand({Sql})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS DynamoDB PartiQL (also matches js.aws.executestatementcommand) ----

func TestJS_AWS_DynamoDB_PartiQL_ExecuteStatementCommand_Injection(t *testing.T) {
	// @aws-sdk/client-dynamodb's ExecuteStatementCommand uses `Statement` (not
	// Sql) for the PartiQL string. The shared sink entry is intentionally
	// scoped to the constructor name so it covers both Redshift and DynamoDB
	// PartiQL — both are SQL/PartiQL injection (CWE-89/CWE-943).
	code := `
const { DynamoDBClient, ExecuteStatementCommand } = require('@aws-sdk/client-dynamodb');
const client = new DynamoDBClient({ region: 'us-east-1' });

async function loadAccount(req, res) {
    const accountId = req.body.accountId;
    const cmd = new ExecuteStatementCommand({
        Statement: "SELECT * FROM Accounts WHERE id = '" + accountId + "'",
    });
    return await client.send(cmd);
}
`
	flows := Analyze(code, "/app/handlers/ddb_account.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.aws.executestatementcommand") {
		t.Error("expected js.aws.executestatementcommand flow from req.body -> new ExecuteStatementCommand({Statement})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_AWS_RedshiftData_BatchExecuteStatementCommand_SQLInjection(t *testing.T) {
	code := `
const { RedshiftDataClient, BatchExecuteStatementCommand } = require('@aws-sdk/client-redshift-data');
const client = new RedshiftDataClient({ region: 'us-east-1' });

async function bulkPurge(req, res) {
    const tag = req.query.tag;
    const cmd = new BatchExecuteStatementCommand({
        ClusterIdentifier: 'analytics-prod',
        Database: 'logs',
        Sqls: [
            "DELETE FROM events WHERE tag = '" + tag + "'",
            "VACUUM events",
        ],
    });
    return await client.send(cmd);
}
`
	flows := Analyze(code, "/app/handlers/redshift_purge.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.aws.batchexecutestatementcommand") {
		t.Error("expected js.aws.batchexecutestatementcommand flow from req.query -> new BatchExecuteStatementCommand({Sqls})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Elasticsearch / OpenSearch search template ----------------------------

func TestJS_Elasticsearch_SearchTemplate_DSLInjection(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function runTemplate(req, res) {
    const tmpl = req.body.source;
    return await client.searchTemplate({
        index: 'items',
        body: {
            source: tmpl,
            params: { name: 'widget' },
        },
    });
}
`
	flows := Analyze(code, "/app/handlers/es_template.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.searchtemplate") {
		t.Error("expected js.elasticsearch.searchtemplate flow from req.body -> client.searchTemplate({body: {source}})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_OpenSearch_SearchTemplate_DSLInjection(t *testing.T) {
	// @opensearch-project/opensearch ships the same Client API as
	// @elastic/elasticsearch — the same sink entry covers both packages.
	code := `
const { Client } = require('@opensearch-project/opensearch');
const client = new Client({ node: 'http://localhost:9200' });

async function runTemplate(req, res) {
    const tmpl = req.query.tmpl;
    return await client.searchTemplate({
        body: { source: tmpl, params: { q: 'x' } },
    });
}
`
	flows := Analyze(code, "/app/handlers/os_template.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.searchtemplate") {
		t.Error("expected js.elasticsearch.searchtemplate flow on OpenSearch client (shared sink set)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative / safe-usage tests (over-broadness regression guards) -------

func TestJS_BigQuery_CreateQueryJob_HardcodedSQL_NoFlow(t *testing.T) {
	code := `
const {BigQuery} = require('@google-cloud/bigquery');
const bigquery = new BigQuery();

async function dailyReport() {
    const sql = "SELECT COUNT(*) FROM ds.events WHERE day = CURRENT_DATE()";
    const [job] = await bigquery.createQueryJob(sql);
    return await job.getQueryResults();
}
`
	flows := Analyze(code, "/app/jobs/bq_daily.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.bigquery.client.createqueryjob") {
		t.Error("expected NO js.bigquery.client.createqueryjob flow for fully hardcoded SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_AWS_Athena_HardcodedQueryString_NoFlow(t *testing.T) {
	code := `
const { AthenaClient, StartQueryExecutionCommand } = require('@aws-sdk/client-athena');
const client = new AthenaClient({ region: 'us-east-1' });

async function listTables() {
    const cmd = new StartQueryExecutionCommand({
        QueryString: "SHOW TABLES",
        ResultConfiguration: { OutputLocation: 's3://results/' },
    });
    return await client.send(cmd);
}
`
	flows := Analyze(code, "/app/jobs/athena_list.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.aws.athena.startqueryexecutioncommand") {
		t.Error("expected NO js.aws.athena.startqueryexecutioncommand flow for hardcoded QueryString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_AWS_Athena_Parameterized_NoFlow(t *testing.T) {
	// Athena prepared-statement form: user input flows into ExecutionParameters
	// (an array of literals) instead of being concatenated into QueryString.
	// QueryString is a constant template with `?` placeholders. The constructor
	// arg as a whole still contains tainted data, so this test serves as a
	// known-FP guardrail rather than a "must not fire" assertion: we still
	// flag the call (it is technically tainted) — the user is expected to
	// confirm the binding pattern and suppress with a reason.
	//
	// We assert the SAFE form does NOT trigger when there is no taint at all.
	code := `
const { AthenaClient, StartQueryExecutionCommand } = require('@aws-sdk/client-athena');
const client = new AthenaClient({ region: 'us-east-1' });

async function fixedReport() {
    const cmd = new StartQueryExecutionCommand({
        QueryString: "SELECT name FROM employees WHERE state = ? AND companyname = ?",
        ExecutionParameters: ["CA", "Acme"],
        ResultConfiguration: { OutputLocation: 's3://results/' },
    });
    return await client.send(cmd);
}
`
	flows := Analyze(code, "/app/jobs/athena_fixed.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.aws.athena.startqueryexecutioncommand") {
		t.Error("expected NO js.aws.athena.startqueryexecutioncommand flow for fully constant args")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_SearchTemplate_StoredID_NoFlow(t *testing.T) {
	// Safe form: reference a stored template by `id`, bind user input via
	// `params` only. The `source` field is absent, so even if params holds
	// tainted values, those values render into typed parameter slots in the
	// stored template (not into the DSL structure). We assert no sink fires
	// when the constructor arg has no taint (tainted params alone aren't a
	// sink, only tainted source is).
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function listByOwner() {
    return await client.searchTemplate({
        index: 'items',
        body: {
            id: 'find-by-owner',
            params: { owner: 'system' },
        },
    });
}
`
	flows := Analyze(code, "/app/jobs/es_stored.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.elasticsearch.searchtemplate") {
		t.Error("expected NO js.elasticsearch.searchtemplate flow for hardcoded stored-template body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
