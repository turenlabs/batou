package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// analyzeShellScript runs the tsflow engine over a bash snippet.
func analyzeShellScript(code string) []taint.TaintFlow {
	return Analyze(code, "/app/deploy.sh", rules.LangShell)
}

// shellFlowHasSink reports whether any flow ends at the given sink ID with the
// expected sink category.
func shellFlowHasSink(flows []taint.TaintFlow, sinkID string, cat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.Category == cat {
			return true
		}
	}
	return false
}

// Each case wires an untrusted `read` value into a CLI database client and
// asserts the matching SQL/NoSQL-injection sink fires. The `read` builtin is
// the canonical tsflow-native shell source (positional $1 is regex-only).
func TestShellDBClientSinks_Positive(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		sinkID string
		cat    taint.SinkCategory
	}{
		{
			name:   "mysql -e inline query",
			code:   "read row\nmysql -e \"SELECT * FROM t WHERE id = $row\"\n",
			sinkID: "shell.sql.mysql",
			cat:    taint.SnkSQLQuery,
		},
		{
			name:   "mariadb -e inline query",
			code:   "read row\nmariadb -e \"DELETE FROM t WHERE k='$row'\"\n",
			sinkID: "shell.sql.mysql",
			cat:    taint.SnkSQLQuery,
		},
		{
			name:   "psql -c inline command",
			code:   "read name\npsql -c \"SELECT * FROM u WHERE name = '$name'\"\n",
			sinkID: "shell.sql.psql",
			cat:    taint.SnkSQLQuery,
		},
		{
			name:   "sqlite3 positional SQL",
			code:   "read q\nsqlite3 app.db \"SELECT * FROM t WHERE c='$q'\"\n",
			sinkID: "shell.sql.sqlite3",
			cat:    taint.SnkSQLQuery,
		},
		{
			name:   "cqlsh -e inline CQL",
			code:   "read id\ncqlsh -e \"SELECT * FROM ks.t WHERE id=$id\"\n",
			sinkID: "shell.sql.cqlsh",
			cat:    taint.SnkSQLQuery,
		},
		{
			name:   "clickhouse-client --query",
			code:   "read q\nclickhouse-client --query \"SELECT * FROM t WHERE c='$q'\"\n",
			sinkID: "shell.sql.clickhouse",
			cat:    taint.SnkSQLQuery,
		},
		{
			name:   "mongosh --eval",
			code:   "read j\nmongosh --eval \"db.u.find({name: '$j'})\"\n",
			sinkID: "shell.nosql.mongo",
			cat:    taint.SnkNoSQL,
		},
		{
			name:   "redis-cli eval tainted script",
			code:   "read s\nredis-cli eval \"$s\" 0\n",
			sinkID: "shell.nosql.redis_cli",
			cat:    taint.SnkNoSQL,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := analyzeShellScript(tc.code)
			if !shellFlowHasSink(flows, tc.sinkID, tc.cat) {
				t.Errorf("expected flow to sink %q (%s); got %d flows: %+v",
					tc.sinkID, tc.cat, len(flows), flowSummaries(flows))
			}
		})
	}
}

// A constant query with no tainted argument must not produce a DB-injection
// flow, even when an unrelated `read` source exists in the script.
func TestShellDBClientSinks_NegativeConstantQuery(t *testing.T) {
	code := "read x\n" +
		"mysql -e \"SELECT 1\"\n" +
		"psql -c \"SELECT now()\"\n" +
		"sqlite3 app.db \"SELECT count(*) FROM t\"\n" +
		"echo \"$x\"\n"
	flows := analyzeShellScript(code)
	for _, f := range flows {
		switch f.Sink.ID {
		case "shell.sql.mysql", "shell.sql.psql", "shell.sql.sqlite3",
			"shell.sql.cqlsh", "shell.sql.clickhouse",
			"shell.nosql.mongo", "shell.nosql.redis_cli":
			t.Errorf("constant query must not fire DB-injection sink %q; got: %+v",
				f.Sink.ID, flowSummaries(flows))
		}
	}
}

// flowSummaries renders flows compactly for failure messages.
func flowSummaries(flows []taint.TaintFlow) []string {
	out := make([]string, 0, len(flows))
	for _, f := range flows {
		out = append(out, f.Source.ID+"->"+f.Sink.ID)
	}
	return out
}
