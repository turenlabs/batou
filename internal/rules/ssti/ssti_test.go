package ssti

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-SSTI-001: Jinja2 render_template_string ---

func TestSSTI001_Jinja2_RenderStr_Request(t *testing.T) {
	content := `return render_template_string(request.form["template"])`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-001")
}

func TestSSTI001_Jinja2_RenderStr_Variable(t *testing.T) {
	content := `return render_template_string(user_template, name=name)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-001")
}

func TestSSTI001_Safe_RenderTemplate(t *testing.T) {
	content := `return render_template("page.html", data=user_input)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-001")
}

// --- BATOU-SSTI-002: Mako Template from string ---

func TestSSTI002_Mako_Template_UserInput(t *testing.T) {
	content := `tmpl = Template(user_input)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-002")
}

func TestSSTI002_Mako_FromString(t *testing.T) {
	content := `tmpl = mako.template.Template(template_str)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-002")
}

func TestSSTI002_Safe_Mako_File(t *testing.T) {
	content := `tmpl = Template(filename="page.html")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-002")
}

// --- BATOU-SSTI-003: Twig/Smarty user input (PHP) ---

func TestSSTI003_Twig_CreateTemplate(t *testing.T) {
	content := `$twig->createTemplate($_POST["template"]);`
	result := testutil.ScanContent(t, "/app/render.php", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-003")
}

func TestSSTI003_Twig_Render_UserInput(t *testing.T) {
	content := `$twig->render($input);`
	result := testutil.ScanContent(t, "/app/render.php", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-003")
}

func TestSSTI003_Smarty_Fetch(t *testing.T) {
	content := `$smarty->fetch("string:" . $userTemplate);`
	result := testutil.ScanContent(t, "/app/render.php", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-003")
}

func TestSSTI003_Safe_Twig_File(t *testing.T) {
	content := `$twig->render("page.html.twig", ["data" => $input]);`
	result := testutil.ScanContent(t, "/app/render.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-003")
}

// --- BATOU-SSTI-004: Velocity evaluate ---

func TestSSTI004_Velocity_Eval(t *testing.T) {
	content := `engine.evaluate(context, writer, "tag", request.getParameter("template"));`
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-004")
}

func TestSSTI004_Velocity_Merge(t *testing.T) {
	content := `Velocity.evaluate(ctx, out, "log", request.getParameter("tmpl"));`
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-004")
}

func TestSSTI004_Safe_Velocity_File(t *testing.T) {
	content := `Template t = engine.getTemplate("template.vm");`
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-004")
}

// --- BATOU-SSTI-005: Thymeleaf expression injection ---

func TestSSTI005_Thymeleaf_PreProcess(t *testing.T) {
	content := `<div th:text="__${request.getParameter('name')}__"></div>`
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-005")
}

func TestSSTI005_Thymeleaf_ViewReturn(t *testing.T) {
	content := `return "welcome/" + request.getParameter("section");`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-005")
}

func TestSSTI005_Safe_Thymeleaf_Static(t *testing.T) {
	content := `return "welcome/index";`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-005")
}

// --- BATOU-SSTI-007: Freemarker Template from user string ---

func TestSSTI007_Freemarker_New(t *testing.T) {
	content := `Template tmpl = new Template("name", new StringReader(request.getParameter("tmpl")), cfg);`
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-007")
}

func TestSSTI007_Safe_Freemarker_File(t *testing.T) {
	content := `Template tmpl = cfg.getTemplate("page.ftl");`
	result := testutil.ScanContent(t, "/app/Template.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-007")
}

// --- BATOU-SSTI-008: ERB template (Ruby) ---

func TestSSTI008_ERB_UserInput(t *testing.T) {
	content := `template = ERB.new(params[:template]).result(binding)`
	result := testutil.ScanContent(t, "/app/views.rb", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-008")
}

func TestSSTI008_ERB_Concat(t *testing.T) {
	content := `template = ERB.new("<h1>" + title).result(binding)`
	result := testutil.ScanContent(t, "/app/views.rb", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-008")
}

func TestSSTI008_Safe_ERB_File(t *testing.T) {
	content := `template = ERB.new(File.read("page.erb")).result(binding)`
	result := testutil.ScanContent(t, "/app/views.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-008")
}

// --- BATOU-SSTI-009: Handlebars.compile ---

func TestSSTI009_Handlebars_Compile(t *testing.T) {
	content := `const template = Handlebars.compile(req.body.template);`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-009")
}

func TestSSTI009_Safe_Handlebars_Static(t *testing.T) {
	content := `const template = Handlebars.compile("<h1>{{title}}</h1>");`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-009")
}

// --- BATOU-SSTI-010: Nunjucks renderString ---

func TestSSTI010_Nunjucks_RenderStr(t *testing.T) {
	content := `nunjucks.renderString(req.body.template, context);`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-010")
}

func TestSSTI010_Safe_Nunjucks_Render(t *testing.T) {
	content := `nunjucks.render("page.html", context);`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-010")
}

// --- BATOU-SSTI-011: Pug/Jade compile ---

func TestSSTI011_Pug_Compile(t *testing.T) {
	content := `const fn = pug.compile(req.body.template);`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-011")
}

func TestSSTI011_Jade_Render(t *testing.T) {
	content := `const html = jade.render(req.body.template);`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-011")
}

func TestSSTI011_Safe_Pug_RenderFile(t *testing.T) {
	content := `const html = pug.renderFile("page.pug", locals);`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-011")
}

// --- BATOU-SSTI-012: Go template.Parse ---

func TestSSTI012_Go_TemplateParse_UserInput(t *testing.T) {
	content := `tmpl, _ := template.New("t").Parse(r.FormValue("tmpl"))`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-SSTI-012")
}

func TestSSTI012_Safe_Go_ParseFiles(t *testing.T) {
	content := `tmpl, _ := template.ParseFiles("page.html")`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSTI-012")
}
