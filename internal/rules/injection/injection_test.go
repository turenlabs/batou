package injection

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// --- GTSS-INJ-001: SQL Injection ---

func TestINJ001_SQLi_Go_Sprintf(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/sqli_sprintf.go")
	result := testutil.ScanContent(t, "/app/handlers/db.go", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Go_Concat(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/sqli_concat.go")
	result := testutil.ScanContent(t, "/app/handlers/search.go", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_JS_StringConcat(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/sqli_string_concat.ts")
	result := testutil.ScanContent(t, "/app/routes/search.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_JS_TemplateLiteral(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/sqli_template_literal.ts")
	result := testutil.ScanContent(t, "/app/routes/query.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Python_FString(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/sqli_fstring.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Python_Format(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/sqli_format.py")
	result := testutil.ScanContent(t, "/app/db.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_PHP(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/sqli_basic.php")
	result := testutil.ScanContent(t, "/app/query.php", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Ruby(t *testing.T) {
	content := testutil.LoadFixture(t, "ruby/vulnerable/sqli_interpolation.rb")
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/SqliBasic.java")
	result := testutil.ScanContent(t, "/app/dao/UserDAO.java", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Safe_Parameterized_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/sqli_parameterized.ts")
	result := testutil.ScanContent(t, "/app/routes/search.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Safe_Parameterized_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/safe/sqli_parameterized.go")
	result := testutil.ScanContent(t, "/app/handlers/db.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Safe_Parameterized_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/sqli_parameterized.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-001")
}

func TestINJ001_SQLi_Safe_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/safe/SqliPrepared.java")
	result := testutil.ScanContent(t, "/app/dao/UserDAO.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-001")
}

// --- GTSS-INJ-002: Command Injection ---

func TestINJ002_CmdInjection_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/command_injection.go")
	result := testutil.ScanContent(t, "/app/handlers/exec.go", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_CmdInjection_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/command_injection.py")
	result := testutil.ScanContent(t, "/app/utils.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_CmdInjection_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/command_injection.ts")
	result := testutil.ScanContent(t, "/app/routes/exec.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_CmdInjection_PHP(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/command_injection.php")
	result := testutil.ScanContent(t, "/app/exec.php", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_CmdInjection_Ruby(t *testing.T) {
	content := testutil.LoadFixture(t, "ruby/vulnerable/command_injection.rb")
	result := testutil.ScanContent(t, "/app/utils.rb", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_CmdInjection_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/CommandInjection.java")
	result := testutil.ScanContent(t, "/app/CmdExec.java", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_Safe_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/safe/command_safe.go")
	result := testutil.ScanContent(t, "/app/handlers/exec.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-002")
}

func TestINJ002_Safe_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/command_safe.ts")
	result := testutil.ScanContent(t, "/app/routes/exec.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-002")
}

// --- GTSS-INJ-003: Code Injection ---

func TestINJ003_CodeInjection_Inline_Eval(t *testing.T) {
	content := `
const userInput = req.body.code;
eval(userInput);
`
	result := testutil.ScanContent(t, "/app/routes/exec.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-003")
}

func TestINJ003_CodeInjection_NewFunction(t *testing.T) {
	content := `const fn = new Function(userCode);`
	result := testutil.ScanContent(t, "/app/eval.js", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-003")
}

func TestINJ003_CodeInjection_Python_Eval(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/eval_injection.py")
	result := testutil.ScanContent(t, "/app/evaluate.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-003")
}

func TestINJ003_CodeInjection_PHP_Eval(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/eval_injection.php")
	result := testutil.ScanContent(t, "/app/eval.php", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-003")
}

func TestINJ003_Safe_JSONParse(t *testing.T) {
	content := `const data = JSON.parse(input);`
	result := testutil.ScanContent(t, "/app/parse.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-003")
}

// --- GTSS-INJ-004: LDAP Injection ---

func TestINJ004_LDAP_Concat(t *testing.T) {
	content := `search_filter = "(&(uid=" + username + ")(objectClass=person))"`
	result := testutil.ScanContent(t, "/app/ldap.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-004")
}

func TestINJ004_LDAP_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/LdapInjection.java")
	result := testutil.ScanContent(t, "/app/LdapQuery.java", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-004")
}

// --- GTSS-INJ-005: Template Injection ---

func TestINJ005_TemplateInjection_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/template_injection.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-005")
}

func TestINJ005_TemplateInjection_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/template_injection.go")
	result := testutil.ScanContent(t, "/app/template.go", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-005")
}

func TestINJ005_TemplateInjection_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/TemplateInjection.java")
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-005")
}

func TestINJ005_Safe_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/safe/template_safe.go")
	result := testutil.ScanContent(t, "/app/template.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-005")
}

// --- GTSS-INJ-006: XPath Injection ---

func TestINJ006_XPath_Concat(t *testing.T) {
	content := `result = doc.xpath("//users/user[@name='" + username + "']")`
	result := testutil.ScanContent(t, "/app/search.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-006")
}

func TestINJ006_XPath_Safe_Static(t *testing.T) {
	content := `result = doc.xpath("//users/user[@role='admin']")`
	result := testutil.ScanContent(t, "/app/search.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-006")
}

// --- GTSS-INJ-007: NoSQL Injection ---

func TestINJ007_NoSQL_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/nosql_injection.ts")
	result := testutil.ScanContent(t, "/app/routes/users.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_Where(t *testing.T) {
	content := `db.collection.find({ "$where": "this.name == '" + userInput + "'" });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_JSONParse(t *testing.T) {
	content := `db.users.find(JSON.parse(req.body.filter));`
	result := testutil.ScanContent(t, "/app/api.js", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_Safe_Static_Query(t *testing.T) {
	content := `db.users.find({ name: "admin" });`
	result := testutil.ScanContent(t, "/app/query.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-007")
}

// --- GTSS-INJ-007: NoSQL Injection (MongoDB Aggregation Pipeline) ---

func TestINJ007_NoSQL_AggLookup(t *testing.T) {
	content := `const pipeline = [{ "$lookup": { "from": req.body.collection, localField: "userId", foreignField: "_id", as: "details" } }];`
	result := testutil.ScanContent(t, "/app/routes/orders.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_AggMerge(t *testing.T) {
	content := `const pipeline = [{ "$merge": req.body.targetCollection }];`
	result := testutil.ScanContent(t, "/app/routes/orders.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_AggOut(t *testing.T) {
	content := `const pipeline = [{ "$out": req.query.outputCollection }];`
	result := testutil.ScanContent(t, "/app/routes/export.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_AggGroup(t *testing.T) {
	content := `const pipeline = [{ "$group": { "_id": req.body.groupField, total: { "$sum": "$amount" } } }];`
	result := testutil.ScanContent(t, "/app/routes/analytics.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_AggAddFields(t *testing.T) {
	content := `const pipeline = [{ "$addFields": req.body.newFields }];`
	result := testutil.ScanContent(t, "/app/routes/transform.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_NoSQL_AggFixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/nosql_aggregation.ts")
	result := testutil.ScanContent(t, "/app/routes/orders.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-007")
}

func TestINJ007_Safe_AggFixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/nosql_aggregation_safe.ts")
	result := testutil.ScanContent(t, "/app/routes/orders.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-007")
}

// --- GTSS-INJ-008: GraphQL Injection ---

func TestINJ008_GraphQL_JS_Concat(t *testing.T) {
	content := `const query = "query { user(name: \"" + username + "\") { id email role } }";`
	result := testutil.ScanContent(t, "/app/routes/graphql.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_GraphQL_JS_TemplateLiteral(t *testing.T) {
	// Build the template literal string via concat to avoid triggering the
	// command injection scanner on this test file itself.
	content := "const mutation = " + "`" + "mutation { updateUser(id: \"$" + "{id}\") { id } }" + "`" + ";"
	result := testutil.ScanContent(t, "/app/routes/graphql.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_GraphQL_Python_FString(t *testing.T) {
	content := `query = f"query {{ user(name: \"{username}\") {{ id email role }} }}"` + "\n"
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_GraphQL_Python_Format(t *testing.T) {
	content := `query = "query {{ user(id: \"{}\") {{ id email }} }}".format(user_id)` + "\n"
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_GraphQL_Go_Sprintf(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/graphql_injection.go")
	result := testutil.ScanContent(t, "/app/handlers/graphql.go", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_GraphQL_Fixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/graphql_injection.ts")
	result := testutil.ScanContent(t, "/app/routes/graphql.ts", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_GraphQL_Fixture_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/graphql_injection.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_Safe_Parameterized_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/graphql_safe.ts")
	result := testutil.ScanContent(t, "/app/routes/graphql.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_Safe_Parameterized_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/graphql_safe.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-008")
}

func TestINJ008_Safe_Static_Query(t *testing.T) {
	content := `const query = "query { users { id email } }";`
	result := testutil.ScanContent(t, "/app/routes/graphql.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-INJ-008")
}
