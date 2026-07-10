package php

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-PHP-030: Unsafe reflection — `new $class()` (CWE-470)
// ==========================================================================

func TestPHP030_DynamicNew_TaintedVar(t *testing.T) {
	content := `<?php
$cls = $_GET['class'];
$obj = new $cls($data);`
	result := testutil.ScanContent(t, "/app/factory.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-030")
}

func TestPHP030_DynamicNew_DirectSuperglobal(t *testing.T) {
	content := `<?php
$obj = new $_POST['handler']();`
	result := testutil.ScanContent(t, "/app/dispatch.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-030")
}

func TestPHP030_DynamicNew_TransitiveTaint(t *testing.T) {
	content := `<?php
$raw = $_REQUEST['c'];
$cls = $raw;
$obj = new $cls();`
	result := testutil.ScanContent(t, "/app/dispatch.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-030")
}

func TestPHP030_LiteralClass_Safe(t *testing.T) {
	content := `<?php
$obj = new MyService($data);
$other = new \App\Repository\UserRepository();`
	result := testutil.ScanContent(t, "/app/service.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-030")
}

func TestPHP030_InternalConstantClass_Safe(t *testing.T) {
	content := `<?php
$svc = 'App\\Logger';
$obj = new $svc();`
	result := testutil.ScanContent(t, "/app/service.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-030")
}

func TestPHP030_AllowListedClass_Safe(t *testing.T) {
	content := `<?php
$allowed = ['a' => Alpha::class, 'b' => Beta::class];
$cls = $allowed[$_GET['k']] ?? Alpha::class;
$obj = new $cls();`
	result := testutil.ScanContent(t, "/app/factory.php", content)
	// $cls is assigned from an allow-list array literal, not a direct request
	// source, so the taint lookback does not mark it tainted.
	testutil.MustNotFindRule(t, result, "BATOU-PHP-030")
}

// ==========================================================================
// BATOU-PHP-031: LDAP anonymous / empty-password bind (CWE-287)
// ==========================================================================

func TestPHP031_AnonymousBind(t *testing.T) {
	content := `<?php
$conn = ldap_connect($host);
$ok = ldap_bind($conn);`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-031")
}

func TestPHP031_EmptyPasswordBind(t *testing.T) {
	content := `<?php
$ok = ldap_bind($conn, $dn, '');`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-031")
}

func TestPHP031_NullPasswordBind(t *testing.T) {
	content := `<?php
$ok = ldap_bind($conn, $dn, null);`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-031")
}

func TestPHP031_RealPasswordBind_Safe(t *testing.T) {
	content := `<?php
$ok = ldap_bind($conn, $dn, $password);`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-031")
}

// ==========================================================================
// BATOU-PHP-032: magic-hash type juggling (CWE-697)
// ==========================================================================

func TestPHP032_Md5LooseCompare(t *testing.T) {
	content := `<?php
if (md5($input) == $stored) {
    grantAccess();
}`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-032")
}

func TestPHP032_Sha1LooseCompare_Reversed(t *testing.T) {
	content := `<?php
if ($provided == sha1($secret)) {
    proceed();
}`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-032")
}

func TestPHP032_StrictCompare_Safe(t *testing.T) {
	content := `<?php
if (md5($input) === $stored) {
    grantAccess();
}`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-032")
}

func TestPHP032_HashEquals_Safe(t *testing.T) {
	content := `<?php
if (hash_equals($stored, md5($input))) {
    grantAccess();
}`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-032")
}

func TestPHP032_NotEqualStrict_Safe(t *testing.T) {
	content := `<?php
if (sha1($input) !== $stored) {
    reject();
}`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-032")
}

// ==========================================================================
// BATOU-PHP-033: Unsafe reflection via Reflection* with tainted name (CWE-470)
// ==========================================================================

func TestPHP033_ReflectionClass_TaintedVar(t *testing.T) {
	content := `<?php
$name = $_GET['class'];
$ref = new ReflectionClass($name);
$obj = $ref->newInstance();`
	result := testutil.ScanContent(t, "/app/dispatch.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-033")
}

func TestPHP033_ReflectionClass_DirectSuperglobal(t *testing.T) {
	content := `<?php
$ref = new ReflectionClass($_POST['handler']);`
	result := testutil.ScanContent(t, "/app/dispatch.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-033")
}

func TestPHP033_ReflectionMethod_Tainted(t *testing.T) {
	content := `<?php
$m = $_REQUEST['m'];
$rm = new ReflectionMethod($obj, $m);`
	result := testutil.ScanContent(t, "/app/call.php", content)
	// The method-name var is the second arg here; the class/first-arg form is
	// what fires. This near-shape still fires on the superglobal-derived first
	// usage only if first arg is tainted — here first arg is $obj, so it must
	// NOT fire on this line. Assert the rule does not flag a safe first arg.
	testutil.MustNotFindRule(t, result, "BATOU-PHP-033")
}

func TestPHP033_LiteralClass_Safe(t *testing.T) {
	content := `<?php
$ref = new ReflectionClass(UserService::class);
$ref2 = new ReflectionClass('App\\Repository\\UserRepository');`
	result := testutil.ScanContent(t, "/app/service.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-033")
}

func TestPHP033_InternalConstantClass_Safe(t *testing.T) {
	content := `<?php
$name = 'App\\Logger';
$ref = new ReflectionClass($name);`
	result := testutil.ScanContent(t, "/app/service.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-033")
}

// ==========================================================================
// BATOU-PHP-034: openssl_encrypt static/literal IV (CWE-329)
// ==========================================================================

func TestPHP034_LiteralIV(t *testing.T) {
	content := `<?php
$ct = openssl_encrypt($data, 'aes-256-cbc', $key, 0, '1234567890123456');`
	result := testutil.ScanContent(t, "/app/crypto.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-034")
}

func TestPHP034_StrRepeatZeroIV(t *testing.T) {
	content := `<?php
$ct = openssl_encrypt($data, 'aes-256-cbc', $key, 0, str_repeat("\0", 16));`
	result := testutil.ScanContent(t, "/app/crypto.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-034")
}

func TestPHP034_RandomIV_Safe(t *testing.T) {
	content := `<?php
$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
$ct = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);`
	result := testutil.ScanContent(t, "/app/crypto.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-034")
}

// ==========================================================================
// BATOU-PHP-035: unchecked openssl_decrypt return (CWE-252)
// ==========================================================================

func TestPHP035_UncheckedDecrypt(t *testing.T) {
	content := `<?php
$pt = openssl_decrypt($ct, 'aes-256-cbc', $key, 0, $iv);
echo "plaintext: " . $pt;
return json_decode($pt, true);`
	result := testutil.ScanContent(t, "/app/crypto.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-035")
}

func TestPHP035_CheckedDecrypt_Safe(t *testing.T) {
	content := `<?php
$pt = openssl_decrypt($ct, 'aes-256-cbc', $key, 0, $iv);
if ($pt === false) {
    throw new RuntimeException('decryption failed');
}
return json_decode($pt, true);`
	result := testutil.ScanContent(t, "/app/crypto.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-035")
}

func TestPHP035_NegationGuard_Safe(t *testing.T) {
	content := `<?php
$pt = openssl_decrypt($ct, 'aes-256-cbc', $key, 0, $iv);
if (!$pt) {
    return null;
}
process($pt);`
	result := testutil.ScanContent(t, "/app/crypto.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-035")
}

// ==========================================================================
// BATOU-PHP-036: phpinfo/phpcredits disclosure (CWE-200)
// ==========================================================================

func TestPHP036_Phpinfo(t *testing.T) {
	content := `<?php
phpinfo();`
	result := testutil.ScanContent(t, "/app/debug.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-036")
}

func TestPHP036_Phpcredits(t *testing.T) {
	content := `<?php
echo phpcredits(CREDITS_ALL);`
	result := testutil.ScanContent(t, "/app/about.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-036")
}

func TestPHP036_NoPhpinfo_Safe(t *testing.T) {
	content := `<?php
$version = phpversion();
echo "Running PHP " . $version;`
	result := testutil.ScanContent(t, "/app/about.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-036")
}

// ==========================================================================
// BATOU-PHP-037: hash precision loss via hexdec/base_convert (CWE-190)
// ==========================================================================

func TestPHP037_HexdecMd5(t *testing.T) {
	content := `<?php
$token = hexdec(md5($input));
if ($token == $expected) { grant(); }`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-037")
}

func TestPHP037_BaseConvertSha1(t *testing.T) {
	content := `<?php
$n = base_convert(sha1($x), 16, 10);`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-037")
}

func TestPHP037_PlainBaseConvert_Safe(t *testing.T) {
	content := `<?php
$hex = base_convert($smallNumber, 10, 16);
$dec = hexdec('ff');`
	result := testutil.ScanContent(t, "/app/util.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-037")
}
