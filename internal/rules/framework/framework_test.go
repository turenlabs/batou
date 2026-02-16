package framework

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ==========================================================================
// BATOU-FW-DJANGO-001: Django Settings Misconfiguration
// ==========================================================================

func TestDjango001_Settings_Vulnerable(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/django_settings.py")
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_DebugTrue(t *testing.T) {
	content := `DEBUG = True`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_AllowedHostsStar(t *testing.T) {
	content := `ALLOWED_HOSTS = ['*']`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_SessionCookieInsecure(t *testing.T) {
	content := `SESSION_COOKIE_SECURE = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_CsrfCookieInsecure(t *testing.T) {
	content := `CSRF_COOKIE_SECURE = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_SSLRedirectFalse(t *testing.T) {
	content := `SECURE_SSL_REDIRECT = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_SessionHTTPOnlyFalse(t *testing.T) {
	content := `SESSION_COOKIE_HTTPONLY = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_CorsAllowAll(t *testing.T) {
	content := `CORS_ALLOW_ALL_ORIGINS = True`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_Safe_Settings(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/django_settings_safe.py")
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_Safe_DebugFalse(t *testing.T) {
	content := `DEBUG = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-001")
}

func TestDjango001_Safe_AllowedHostsSpecific(t *testing.T) {
	content := `ALLOWED_HOSTS = ['example.com', 'www.example.com']`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-001")
}

// ==========================================================================
// BATOU-FW-DJANGO-002: Django ORM SQL Injection
// ==========================================================================

func TestDjango002_ORM_SQLi_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/django_orm_sqli.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-002")
}

func TestDjango002_ObjectsRaw_FString(t *testing.T) {
	content := `users = User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-FW-DJANGO-002", "BATOU-FW-FASTAPI-004")
}

func TestDjango002_ObjectsRaw_Format(t *testing.T) {
	content := `users = User.objects.raw("SELECT * FROM users WHERE name = '{}'".format(name))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-002")
}

func TestDjango002_CursorExec_FString(t *testing.T) {
	content := `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-FW-DJANGO-002", "BATOU-FW-FASTAPI-004")
}

func TestDjango002_CursorExec_Format(t *testing.T) {
	content := `cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-002")
}

func TestDjango002_ObjectsExtra(t *testing.T) {
	content := `users = User.objects.extra(where=["id = %s" % user_id])`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-002")
}

func TestDjango002_Safe_Parameterized(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/django_orm_safe.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-002")
}

func TestDjango002_Safe_ORM_Filter(t *testing.T) {
	content := `users = User.objects.filter(name=name)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-002")
}

// ==========================================================================
// BATOU-FW-DJANGO-003: Django Template XSS
// ==========================================================================

func TestDjango003_SafeFilter(t *testing.T) {
	content := `template_str = '{{ user_input|safe }}'`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-003")
}

func TestDjango003_MarkSafe_FString(t *testing.T) {
	content := `html = mark_safe(f"<div>{user_input}</div>")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-003")
}

func TestDjango003_MarkSafe_Concat(t *testing.T) {
	content := `html = mark_safe("<p>" + comment + "</p>")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-003")
}

func TestDjango003_MarkSafe_Request(t *testing.T) {
	content := `html = mark_safe(request.POST.get('bio'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-003")
}

func TestDjango003_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/django_template_xss.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-003")
}

func TestDjango003_Safe_Escaped(t *testing.T) {
	content := `template_str = '{{ user_input }}'`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-003")
}

// ==========================================================================
// BATOU-FW-DJANGO-004: Django CSRF Exemption
// ==========================================================================

func TestDjango004_CsrfExempt(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/django_csrf_exempt.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-004")
}

func TestDjango004_CsrfExempt_Inline(t *testing.T) {
	content := `@csrf_exempt
def my_view(request):
    pass`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-004")
}

func TestDjango004_Safe_NoCsrfExempt(t *testing.T) {
	content := `def my_view(request):
    return HttpResponse("ok")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-004")
}

// ==========================================================================
// BATOU-FW-DJANGO-005: Django Mass Assignment
// ==========================================================================

func TestDjango005_MassAssign_POST(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/django_mass_assignment.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-005")
}

func TestDjango005_MassAssign_Create(t *testing.T) {
	content := `user = User.objects.create(**request.POST)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-005")
}

func TestDjango005_MassAssign_Data(t *testing.T) {
	content := `profile = Profile.objects.create(**request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-DJANGO-005")
}

func TestDjango005_Safe_ExplicitFields(t *testing.T) {
	content := `user = User.objects.create(name=request.POST['name'], email=request.POST['email'])`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-DJANGO-005")
}

// ==========================================================================
// BATOU-FW-FLASK-001: Flask Misconfiguration
// ==========================================================================

func TestFlask001_Misconfig_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/flask_misconfig.py")
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_DebugTrue(t *testing.T) {
	content := `app.run(debug=True)`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_DebugTrue_WithOtherArgs(t *testing.T) {
	content := `app.run(host='0.0.0.0', debug=True, port=5000)`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_HardcodedSecretKey(t *testing.T) {
	content := `app.secret_key = 'my-super-secret-key-123'`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_HardcodedSecretKeyConfig(t *testing.T) {
	content := `app.config['SECRET_KEY'] = 'hardcoded-secret'`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_SessionCookieInsecure(t *testing.T) {
	content := `app.config['SESSION_COOKIE_SECURE'] = False`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_Safe_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/flask_safe.py")
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_Safe_EnvSecretKey(t *testing.T) {
	content := `app.secret_key = os.environ.get('SECRET_KEY')`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-001")
}

func TestFlask001_Safe_NoDebug(t *testing.T) {
	content := `app.run(host='0.0.0.0', port=5000)`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-001")
}

// ==========================================================================
// BATOU-FW-FLASK-002: Flask SSTI
// ==========================================================================

func TestFlask002_SSTI_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/flask_ssti.py")
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-002")
}

func TestFlask002_SSTI_Variable(t *testing.T) {
	content := `return render_template_string(template)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-002")
}

func TestFlask002_SSTI_RequestInput(t *testing.T) {
	content := `return render_template_string(request.args.get('template'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-002")
}

func TestFlask002_SSTI_FString(t *testing.T) {
	content := `return render_template_string(f"<h1>{name}</h1>")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-002")
}

func TestFlask002_Safe_StaticTemplate(t *testing.T) {
	content := `return render_template('greet.html', name=name)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-002")
}

func TestFlask002_Safe_RenderTemplate(t *testing.T) {
	content := `return render_template('index.html')`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-002")
}

// ==========================================================================
// BATOU-FW-FLASK-003: Flask Path Traversal
// ==========================================================================

func TestFlask003_Traversal_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/flask_traversal.py")
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-003")
}

func TestFlask003_SendFile_Variable(t *testing.T) {
	content := `return send_file(filename)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-003")
}

func TestFlask003_SendFile_Request(t *testing.T) {
	content := `return send_file(request.args.get('file'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-003")
}

func TestFlask003_SendFromDir_Request(t *testing.T) {
	content := `return send_from_directory('/uploads', request.args.get('name'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-003")
}

func TestFlask003_Safe_SecureFilename(t *testing.T) {
	content := `return send_from_directory(app.config['UPLOAD_DIR'], secure_filename(filename))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-003")
}

func TestFlask003_Safe_StaticFile(t *testing.T) {
	content := `return send_file('static/logo.png')`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-003")
}

// ==========================================================================
// BATOU-FW-FLASK-004: Flask Markup XSS
// ==========================================================================

func TestFlask004_Markup_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/flask_markup_xss.py")
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-004")
}

func TestFlask004_Markup_Variable(t *testing.T) {
	content := `html = Markup(user_input)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-004")
}

func TestFlask004_Markup_Request(t *testing.T) {
	content := `html = Markup(request.args.get('text'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-004")
}

func TestFlask004_Markup_FString(t *testing.T) {
	content := `html = Markup(f"<div>{bio}</div>")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FLASK-004")
}

func TestFlask004_Safe_Escape(t *testing.T) {
	content := `safe_text = Markup.escape(user_input)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-004")
}

func TestFlask004_Safe_StaticString(t *testing.T) {
	content := `html = Markup('<br>')`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FLASK-004")
}

// ==========================================================================
// Rails Rules Tests
// ==========================================================================

// --- BATOU-FW-RAILS-001: html_safe on dynamic content ---

func TestRails001_HTMLSafe_Variable(t *testing.T) {
	content := `user_input.html_safe`
	result := testutil.ScanContent(t, "/app/views/show.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-001")
}

func TestRails001_HTMLSafe_Interpolation(t *testing.T) {
	content := `"<div>#{user_name}</div>".html_safe`
	result := testutil.ScanContent(t, "/app/views/show.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-001")
}

func TestRails001_HTMLSafe_StringLiteral_Safe(t *testing.T) {
	// String literal without interpolation is safe
	content := `"<br>".html_safe`
	result := testutil.ScanContent(t, "/app/views/show.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-001")
}

// --- BATOU-FW-RAILS-002: render inline SSTI ---

func TestRails002_RenderInline_Variable(t *testing.T) {
	content := `render inline: user_template`
	result := testutil.ScanContent(t, "/app/controllers/page_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-002")
}

func TestRails002_RenderInline_Interpolation(t *testing.T) {
	content := `render inline: "Hello #{params[:name]}"`
	result := testutil.ScanContent(t, "/app/controllers/page_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-002")
}

// --- BATOU-FW-RAILS-003: constantize RCE ---

func TestRails003_Constantize_Params(t *testing.T) {
	content := `params[:type].constantize.new`
	result := testutil.ScanContent(t, "/app/controllers/api_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-003")
}

func TestRails003_SafeConstantize(t *testing.T) {
	content := `user_input.safe_constantize`
	result := testutil.ScanContent(t, "/app/services/loader.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-003")
}

// --- BATOU-FW-RAILS-004: params.permit! ---

func TestRails004_PermitBang(t *testing.T) {
	content := `params.permit!`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-004")
}

func TestRails004_PermitWithFields_Safe(t *testing.T) {
	content := `params.require(:user).permit(:name, :email)`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-004")
}

// --- BATOU-FW-RAILS-005: Rails misconfigurations ---

func TestRails005_DebugTrue(t *testing.T) {
	content := `config.consider_all_requests_local = true`
	result := testutil.ScanContent(t, "/config/environments/production.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-005")
}

func TestRails005_ForceSSLFalse(t *testing.T) {
	content := `config.force_ssl = false`
	result := testutil.ScanContent(t, "/config/environments/production.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-005")
}

func TestRails005_NullSession(t *testing.T) {
	content := `protect_from_forgery with: :null_session`
	result := testutil.ScanContent(t, "/app/controllers/api_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-005")
}

func TestRails005_SkipCSRF(t *testing.T) {
	content := `skip_before_action :verify_authenticity_token`
	result := testutil.ScanContent(t, "/app/controllers/webhooks_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-005")
}

// --- BATOU-FW-RAILS-006: ActiveRecord SQL injection ---

func TestRails006_WhereParamsInterp(t *testing.T) {
	content := `User.where("name = '#{params[:name]}'")`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-006")
}

func TestRails006_WhereParamsHash(t *testing.T) {
	content := `User.where(params[:conditions])`
	result := testutil.ScanContent(t, "/app/controllers/search_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-006")
}

func TestRails006_OrderParams(t *testing.T) {
	content := `User.order(params[:sort])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-006")
}

func TestRails006_WhereHash_Safe(t *testing.T) {
	content := `User.where(name: params[:name])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-006")
}

// ==========================================================================
// Laravel Rules Tests
// ==========================================================================

// --- BATOU-FW-LARAVEL-001: DB::raw() SQL injection ---

func TestLaravel001_DBRawVariable(t *testing.T) {
	content := `$results = DB::raw($userInput);`
	result := testutil.ScanContent(t, "/app/Http/Controllers/SearchController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-001")
}

func TestLaravel001_DBRawConcat(t *testing.T) {
	content := `$results = DB::raw("SELECT * FROM users WHERE id = " . $id);`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-001")
}

func TestLaravel001_DBSelectInterp(t *testing.T) {
	content := `$results = DB::select("SELECT * FROM users WHERE id = $id");`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-001")
}

// --- BATOU-FW-LARAVEL-002: Blade unescaped output ---

func TestLaravel002_BladeUnescaped(t *testing.T) {
	content := `{!! $userContent !!}`
	result := testutil.ScanContent(t, "/resources/views/profile.blade.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-002")
}

func TestLaravel002_BladeEscaped_Safe(t *testing.T) {
	content := `{{ $userContent }}`
	result := testutil.ScanContent(t, "/resources/views/profile.blade.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-002")
}

// --- BATOU-FW-LARAVEL-003: Mass assignment ---

func TestLaravel003_CreateAll(t *testing.T) {
	content := `User::create($request->all());`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-003")
}

func TestLaravel003_UpdateAll(t *testing.T) {
	content := `$user->update($request->all());`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-003")
}

func TestLaravel003_CreateOnly_Safe(t *testing.T) {
	content := `User::create($request->only(['name', 'email']));`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-003")
}

// --- BATOU-FW-LARAVEL-004: APP_DEBUG ---

func TestLaravel004_DebugTrue(t *testing.T) {
	content := `APP_DEBUG=true`
	result := testutil.ScanContent(t, "/project/.env", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-004")
}

func TestLaravel004_DebugFalse_Safe(t *testing.T) {
	content := `APP_DEBUG=false`
	result := testutil.ScanContent(t, "/project/.env", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-004")
}

// --- BATOU-FW-LARAVEL-005: APP_KEY committed ---

func TestLaravel005_AppKeyInEnv(t *testing.T) {
	content := `APP_KEY=base64:abc123def456ghi789jkl012mno345pqr678stu=`
	result := testutil.ScanContent(t, "/project/.env", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-005")
}

func TestLaravel005_AppKeyHardcoded(t *testing.T) {
	content := `'APP_KEY' => 'base64:abc123def456ghi789jkl012mno345pqr678stu='`
	result := testutil.ScanContent(t, "/config/app.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-005")
}

// --- BATOU-FW-LARAVEL-006: Unserialize ---

func TestLaravel006_UnserializeRequest(t *testing.T) {
	content := `$data = unserialize($request->input('data'));`
	result := testutil.ScanContent(t, "/app/Http/Controllers/DataController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-006")
}

// --- BATOU-FW-LARAVEL-007: Storage traversal ---

func TestLaravel007_StorageGet(t *testing.T) {
	content := `$file = Storage::get($request->input('path'));`
	result := testutil.ScanContent(t, "/app/Http/Controllers/FileController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-007")
}

// ==========================================================================
// React Rules Tests
// ==========================================================================

// --- BATOU-FW-REACT-001: SSR with user input ---

func TestReact001_RenderToString_UserInput(t *testing.T) {
	content := `
const name = req.query.name;
const html = renderToString(<App userName={name} />);
res.send(html);
`
	result := testutil.ScanContent(t, "/app/server.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-FW-REACT-001")
}

func TestReact001_RenderToString_NoUserInput_Safe(t *testing.T) {
	content := `
const html = renderToString(<App title="Hello" />);
res.send(html);
`
	result := testutil.ScanContent(t, "/app/server.tsx", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-REACT-001")
}

func TestReact001_RenderToString_WithSanitizer_Safe(t *testing.T) {
	content := `
const name = req.query.name;
const safeName = DOMPurify.sanitize(name);
const html = renderToString(<App userName={safeName} />);
res.send(html);
`
	result := testutil.ScanContent(t, "/app/server.tsx", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-REACT-001")
}

// --- BATOU-FW-REACT-002: ref innerHTML ---

func TestReact002_RefInnerHTML(t *testing.T) {
	content := `divRef.current.innerHTML = userContent;`
	result := testutil.ScanContent(t, "/app/components/Widget.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-FW-REACT-002")
}

// --- BATOU-FW-REACT-003: Prop spreading ---

func TestReact003_SpreadUserInput(t *testing.T) {
	content := `<Component {...userInput} />`
	result := testutil.ScanContent(t, "/app/components/Form.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-FW-REACT-003")
}

func TestReact003_SpreadParams(t *testing.T) {
	content := `<Component {...params} />`
	result := testutil.ScanContent(t, "/app/components/Form.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-FW-REACT-003")
}

// --- BATOU-FW-REACT-004: Dynamic script/iframe ---

func TestReact004_CreateElementScript(t *testing.T) {
	content := `React.createElement("script", { src: userUrl })`
	result := testutil.ScanContent(t, "/app/components/Loader.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-FW-REACT-004")
}

func TestReact004_IframeDynamicSrc(t *testing.T) {
	content := `<iframe src={userUrl} sandbox="allow-scripts" />`
	result := testutil.ScanContent(t, "/app/components/Embed.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-FW-REACT-004")
}
