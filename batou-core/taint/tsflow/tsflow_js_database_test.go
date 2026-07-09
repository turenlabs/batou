package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog verification ---

func TestJS_DB_SourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJavaScript)
	if cat == nil {
		t.Fatal("JavaScript catalog not loaded")
	}
	sources := cat.Sources()
	found := map[string]bool{}
	for _, s := range sources {
		if s.Category == taint.SrcDatabase {
			found[s.ID] = true
		}
	}
	want := []string{
		"js.mongodb.findone", "js.mongoose.findbyid", "js.mongodb.aggregate",
		"js.mongodb.distinct", "js.sequelize.findall", "js.sequelize.findbypk",
		"js.sequelize.findandcountall", "js.pg.pool.query",
		"js.mysql.connection.query", "js.knex.raw",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SrcDatabase source: %s", id)
		}
	}
}

// --- MongoDB / Mongoose ---

func TestJS_MongoDB_FindOne_XSS(t *testing.T) {
	code := `
function renderProfile(id) {
    const user = User.findOne({ _id: id });
    res.send("<h1>" + user.name + "</h1>");
}
`
	flows := Analyze(code, "/app/routes/profile.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from MongoDB findOne() result -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Mongoose_FindById_XSS(t *testing.T) {
	code := `
function renderPost(postId) {
    const post = Post.findById(postId);
    res.send("<div>" + post.content + "</div>");
}
`
	flows := Analyze(code, "/app/routes/post.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Mongoose findById() result -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_MongoDB_Aggregate_CommandInjection(t *testing.T) {
	code := `
function runPipeline() {
    const results = Comment.aggregate([{ $group: { _id: "$author" } }]);
    const first = results[0];
    exec(first.cmd);
}
`
	flows := Analyze(code, "/app/pipeline.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from MongoDB aggregate() result -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_MongoDB_Distinct_Eval(t *testing.T) {
	code := `
function loadPlugins() {
    const plugins = collection.distinct("pluginCode");
    eval(plugins[0]);
}
`
	flows := Analyze(code, "/app/plugins.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from MongoDB distinct() result -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sequelize ORM ---

func TestJS_Sequelize_FindAll_XSS(t *testing.T) {
	code := `
function listUsers() {
    const users = User.findAll({ where: { role: "admin" } });
    res.send("<ul>" + users.map(u => u.name).join("") + "</ul>");
}
`
	flows := Analyze(code, "/app/routes/users.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Sequelize findAll() result -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Sequelize_FindByPk_CommandInjection(t *testing.T) {
	code := `
function runTask(configId) {
    const config = Config.findByPk(configId);
    exec(config.command);
}
`
	flows := Analyze(code, "/app/tasks/runner.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Sequelize findByPk() result -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Sequelize_FindAndCountAll_XSS(t *testing.T) {
	code := `
function paginatedList() {
    const result = Order.findAndCountAll({ limit: 10 });
    res.send("<p>" + result.name + "</p>");
}
`
	flows := Analyze(code, "/app/routes/orders.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Sequelize findAndCountAll() result -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- PostgreSQL (pg) ---

func TestJS_PG_Pool_Query_XSS(t *testing.T) {
	code := `
function getUser(id) {
    const result = pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    res.send("<h1>" + user.bio + "</h1>");
}
`
	flows := Analyze(code, "/app/routes/user.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from pool.query() result -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MySQL ---

func TestJS_MySQL_Connection_Query_Eval(t *testing.T) {
	code := `
function processTemplate(templateId) {
    const rows = connection.query("SELECT template FROM templates WHERE id = ?", [templateId]);
    eval(rows.template);
}
`
	flows := Analyze(code, "/app/process.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from connection.query() result -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Knex ---

func TestJS_Knex_Raw_SecondOrder_SQLInjection(t *testing.T) {
	code := `
function buildReport(userId) {
    const result = knex.raw("SELECT filter_query FROM user_filters WHERE user_id = ?", [userId]);
    const filterQuery = result.filter_query;
    knex.raw(filterQuery);
}
`
	flows := Analyze(code, "/app/reports.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow from knex.raw() result -> knex.raw()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe patterns (sanitized database results) ---

func TestJS_MongoDB_FindOne_Safe_EscapeHtml(t *testing.T) {
	code := `
function renderProfile(id) {
    const user = User.findOne({ _id: id });
    const safeName = escapeHtml(user.name);
    res.send("<h1>" + safeName + "</h1>");
}
`
	flows := Analyze(code, "/app/routes/profile.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected escapeHtml() to sanitize MongoDB result, but got flow with confidence %.2f", f.Confidence)
		}
	}
}

func TestJS_Sequelize_FindAll_Safe_JSONResponse(t *testing.T) {
	code := `
function apiListUsers() {
    const users = User.findAll();
    res.json(users);
}
`
	flows := Analyze(code, "/app/routes/api.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected res.json() to not trigger XSS flow, but got: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
