package framework

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-FW-LARAVEL-003 (extended): request()->all() helper + new Model(...)
// ==========================================================================

func TestLaravel003_RequestHelperAll(t *testing.T) {
	content := `<?php
$user = User::create(request()->all());`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-003")
}

func TestLaravel003_NewModelRequestAll(t *testing.T) {
	content := `<?php
$post = new Post($request->all());
$post->save();`
	result := testutil.ScanContent(t, "/app/Http/Controllers/PostController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-003")
}

func TestLaravel003_OnlyFields_Safe(t *testing.T) {
	content := `<?php
$user = User::create($request->only(['name', 'email']));
$post = new Post($request->validated());`
	result := testutil.ScanContent(t, "/app/Http/Controllers/UserController.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-003")
}

// ==========================================================================
// BATOU-FW-LARAVEL-008: insecure cookie/session flags (CWE-1004/614/1275)
// ==========================================================================

func TestLaravel008_HttpOnlyFalse(t *testing.T) {
	content := `<?php
return [
    'http_only' => false,
];`
	result := testutil.ScanContent(t, "/config/session.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-008")
}

func TestLaravel008_SecureFalse(t *testing.T) {
	content := `<?php
return [
    'secure' => false,
];`
	result := testutil.ScanContent(t, "/config/session.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-008")
}

func TestLaravel008_SameSiteNone(t *testing.T) {
	content := `<?php
return [
    'same_site' => 'none',
];`
	result := testutil.ScanContent(t, "/config/session.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-008")
}

func TestLaravel008_CookieMakeNoHttpOnly(t *testing.T) {
	content := `<?php
use Illuminate\Support\Facades\Cookie;
$cookie = Cookie::make('token', $value, 60, '/', null, false, false);`
	result := testutil.ScanContent(t, "/app/Http/Controllers/AuthController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-008")
}

func TestLaravel008_SecureFlags_Safe(t *testing.T) {
	content := `<?php
return [
    'http_only' => true,
    'secure' => env('SESSION_SECURE_COOKIE', true),
    'same_site' => 'lax',
];`
	result := testutil.ScanContent(t, "/config/session.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-008")
}

// ==========================================================================
// BATOU-FW-LARAVEL-009: non-literal validator rules (CWE-89)
// ==========================================================================

func TestLaravel009_ValidatorVarRules(t *testing.T) {
	content := `<?php
$rules = $this->buildRules($input);
$validator = Validator::make($data, $rules);`
	result := testutil.ScanContent(t, "/app/Http/Controllers/FormController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-009")
}

func TestLaravel009_ValidatorMergeRules(t *testing.T) {
	content := `<?php
$validator = Validator::make($data, array_merge($base, $extra));`
	result := testutil.ScanContent(t, "/app/Http/Controllers/FormController.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-009")
}

func TestLaravel009_LiteralRules_Safe(t *testing.T) {
	content := `<?php
$validator = Validator::make($data, ['age' => 'required|integer']);
$validator2 = Validator::make($input, [
    'email' => 'required|email',
]);`
	result := testutil.ScanContent(t, "/app/Http/Controllers/FormController.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-009")
}

// A bare ->validate($x) method call (Symfony validator, hasher, entity
// validator) must NOT fire — it is not the Laravel facade.
func TestLaravel009_BareValidateMethod_Safe(t *testing.T) {
	content := `<?php
$errors = $this->validator->validate($entity, $constraints);
$ok = $hasher->validate($passwordHash);`
	result := testutil.ScanContent(t, "/app/Service/Foo.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-009")
}

// ==========================================================================
// BATOU-FW-LARAVEL-010: Blade form missing @csrf (CWE-352)
// ==========================================================================

func TestLaravel010_FormNoCsrf(t *testing.T) {
	content := `<form method="POST" action="/profile">
    <input type="text" name="name">
    <button type="submit">Save</button>
</form>`
	result := testutil.ScanContent(t, "/resources/views/profile.blade.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-010")
}

func TestLaravel010_MethodSpoofNoCsrf(t *testing.T) {
	content := `<form method="POST" action="/posts/1">
    @method('DELETE')
    <button>Delete</button>
</form>`
	result := testutil.ScanContent(t, "/resources/views/post.blade.php", content)
	testutil.MustFindRule(t, result, "BATOU-FW-LARAVEL-010")
}

func TestLaravel010_FormWithCsrf_Safe(t *testing.T) {
	content := `<form method="POST" action="/profile">
    @csrf
    <input type="text" name="name">
    <button type="submit">Save</button>
</form>`
	result := testutil.ScanContent(t, "/resources/views/profile.blade.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-010")
}

func TestLaravel010_GetForm_Safe(t *testing.T) {
	content := `<form method="GET" action="/search">
    <input type="text" name="q">
    <button type="submit">Search</button>
</form>`
	result := testutil.ScanContent(t, "/resources/views/search.blade.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-LARAVEL-010")
}
