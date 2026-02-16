package nosql

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-NOSQL-001: MongoDB $where Injection
// ---------------------------------------------------------------------------

func TestNOSQL001_Where_TemplateLiteral(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/nosql_where_injection.ts")
	result := testutil.ScanContent(t, "/app/routes/orders.ts", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-001")
}

func TestNOSQL001_Where_StringConcat(t *testing.T) {
	content := `db.collection.find({ "$where": "this.name == '" + userInput + "'" });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-001")
}

func TestNOSQL001_Where_Python_FString(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/nosql_injection.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-001")
}

func TestNOSQL001_Where_Ruby_Interpolation(t *testing.T) {
	content := testutil.LoadFixture(t, "ruby/vulnerable/nosql_injection.rb")
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-001")
}

func TestNOSQL001_Where_Eval(t *testing.T) {
	content := `db.users.find({ "$where": "eval('return this.age > ' + minAge)" });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-001")
}

func TestNOSQL001_Safe_NoWhere(t *testing.T) {
	content := `db.users.find({ name: "admin" });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-NOSQL-001")
}

func TestNOSQL001_Safe_StaticWhere(t *testing.T) {
	content := `db.users.find({ role: "admin", active: true });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-NOSQL-001")
}

// ---------------------------------------------------------------------------
// BATOU-NOSQL-002: MongoDB Operator Injection
// ---------------------------------------------------------------------------

func TestNOSQL002_DirectPassthrough(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/nosql_operator_injection.ts")
	result := testutil.ScanContent(t, "/app/routes/users.ts", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_JSONParse(t *testing.T) {
	content := `db.users.find(JSON.parse(req.body.filter));`
	result := testutil.ScanContent(t, "/app/api.js", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_ReqBodyDirect(t *testing.T) {
	content := `const user = await User.findOne(req.body);`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_Pymongo(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/nosql_injection.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_Mongoid(t *testing.T) {
	content := testutil.LoadFixture(t, "ruby/vulnerable/nosql_injection.rb")
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_AggPassthrough(t *testing.T) {
	content := `db.orders.aggregate(req.body.pipeline);`
	result := testutil.ScanContent(t, "/app/routes/analytics.ts", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_Safe_TypeCast(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/nosql_safe.ts")
	result := testutil.ScanContent(t, "/app/routes/users.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-NOSQL-002")
}

func TestNOSQL002_Safe_StaticQuery(t *testing.T) {
	content := `db.users.find({ name: "admin" });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-NOSQL-002")
}

// ---------------------------------------------------------------------------
// BATOU-NOSQL-003: Raw Query with User Input
// ---------------------------------------------------------------------------

func TestNOSQL003_Regex_UserInput(t *testing.T) {
	content := `db.users.find({ name: { "$regex": req.body.pattern } });`
	result := testutil.ScanContent(t, "/app/search.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-NOSQL-002", "BATOU-NOSQL-003")
}

func TestNOSQL003_MapReduce(t *testing.T) {
	content := `db.orders.mapReduce(function() { emit(this.status, 1); }, function(k, v) { return Array.sum(v); });`
	result := testutil.ScanContent(t, "/app/analytics.js", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-003")
}

func TestNOSQL003_AggLookup(t *testing.T) {
	content := `const pipeline = [{ "$lookup": { "from": req.body.collection, localField: "userId", foreignField: "_id", as: "details" } }];`
	result := testutil.ScanContent(t, "/app/routes/orders.ts", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-003")
}

func TestNOSQL003_AggMerge(t *testing.T) {
	content := `const pipeline = [{ "$merge": req.body.targetCollection }];`
	result := testutil.ScanContent(t, "/app/routes/export.ts", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-003")
}

func TestNOSQL003_ServerEval(t *testing.T) {
	content := `db.eval("return db.users.count()");`
	result := testutil.ScanContent(t, "/app/admin.js", content)
	testutil.MustFindRule(t, result, "BATOU-NOSQL-003")
}

func TestNOSQL003_Safe_StaticRegex(t *testing.T) {
	content := `db.users.find({ name: { "$regex": "^admin" } });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-NOSQL-003")
}

func TestNOSQL003_Severity_Check(t *testing.T) {
	// Verify severity levels are set correctly
	whereRule := WhereInjection{}
	if whereRule.DefaultSeverity() != rules.Critical {
		t.Errorf("WhereInjection should be Critical, got %s", whereRule.DefaultSeverity())
	}

	opRule := OperatorInjection{}
	if opRule.DefaultSeverity() != rules.High {
		t.Errorf("OperatorInjection should be High, got %s", opRule.DefaultSeverity())
	}

	rawRule := RawQueryInjection{}
	if rawRule.DefaultSeverity() != rules.High {
		t.Errorf("RawQueryInjection should be High, got %s", rawRule.DefaultSeverity())
	}
}
