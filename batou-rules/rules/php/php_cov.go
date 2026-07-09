// Coverage-expansion PHP rules (cov/php). These add detection classes the
// existing PHP rules + taint catalog lacked, each anchored tightly so the
// secure idiom never matches:
//
//   BATOU-PHP-030  CWE-470  unsafe reflection: `new $var(...)` (variable class
//                           name) where the class string traces to a request
//                           source — PHP object injection / gadget trigger.
//   BATOU-PHP-031  CWE-287  LDAP anonymous / empty-password bind — auth bypass.
//   BATOU-PHP-032  CWE-697  magic-hash type juggling at the HASH level:
//                           md5()/sha1() compared with loose `==`.
//
// IDs continue from BATOU-PHP-029 (php_strict.go).

package php

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// BATOU-PHP-030: Unsafe reflection — `new $class(...)` with a tainted class
// name (CWE-470). Anchored on the literal `new $` token (a class name held in
// a variable). `new ClassName()` with a literal class never matches. Only the
// variable-class form fires, AND only when that variable traces back to a
// request source (or is a direct superglobal), so static factory maps that are
// not request-derived do not flag.
// ---------------------------------------------------------------------------

// phpDynamicNewRe captures `new $varname(` — the class is a variable. The
// trailing `(` (optionally with preceding whitespace) excludes `new $this`
// member reads and similar non-instantiation uses. Captures the class
// variable name so we can run the taint lookback on it.
var phpDynamicNewRe = regexp.MustCompile(`\bnew\s+\$(\w+)\s*\(`)

// phpDynamicNewSuperglobalRe captures the direct form where the class name is
// read inline from a superglobal: `new $_GET['c']()`, `new $_POST[...]()`.
// This is unconditionally request-controlled — no lookback needed.
var phpDynamicNewSuperglobalRe = regexp.MustCompile(`\bnew\s+\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[`)

type PHPDynamicInstantiation struct{}

func (r *PHPDynamicInstantiation) ID() string   { return "BATOU-PHP-030" }
func (r *PHPDynamicInstantiation) Name() string { return "PHPDynamicInstantiation" }
func (r *PHPDynamicInstantiation) Description() string {
	return "Detects `new $class(...)` where the class name is a variable that traces back to a request source — unsafe reflection / PHP object injection (CWE-470)."
}
func (r *PHPDynamicInstantiation) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPDynamicInstantiation) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *PHPDynamicInstantiation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	if !strings.Contains(ctx.Content, "new $") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		// Direct superglobal class name — always tainted.
		if m := rules.GFindLower(phpDynamicNewSuperglobalRe, line, lowered[i]); m != "" {
			matched = m
		} else if m := rules.GFindSubmatchLower(phpDynamicNewRe, line, lowered[i]); m != nil {
			// Variable class name — require the variable to trace to a request
			// source within the same function (else it is a legitimate
			// factory-map dispatch on a validated/internal value).
			clsVar := m[1]
			if strings.HasPrefix(clsVar, "_") {
				// `new $_GET` is handled by the superglobal regex; a bare
				// `$_x` here is not a superglobal so skip.
				continue
			}
			if phpVarTaintedTransitive(lines, i, clsVar, 0) {
				matched = m[0]
			}
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Unsafe reflection: `new $class()` with attacker-controlled class name",
			Description:   "Instantiating a class whose name comes from a request source lets an attacker construct any class the autoloader can reach. This is a primary trigger for PHP object-injection / property-oriented-programming (POP) gadget chains, and can invoke destructive constructors or __wakeup/__destruct side effects.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(matched), 120),
			Suggestion:    "Never instantiate a class from raw user input. Map the request value through an explicit allow-list of permitted class names (e.g. `$cls = $allowed[$key] ?? throw ...;`) before `new`, or use a fixed factory switch.",
			CWEID:         "CWE-470",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "unsafe-reflection", "object-injection", "rce"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-031: LDAP anonymous / empty-password bind (CWE-287). Matches ONLY
// the anonymous form (single-arg ldap_bind) or an explicit empty/null password
// third argument. A normal `ldap_bind($c, $dn, $pw)` with a variable password
// never matches.
// ---------------------------------------------------------------------------

// phpLdapAnonBindRe: `ldap_bind($conn)` — only the connection resource, no DN
// or password (anonymous bind). The `[^,)]*` ensures there is no comma inside
// the single argument.
var phpLdapAnonBindRe = regexp.MustCompile(`\bldap_bind(?:_ext)?\s*\(\s*[^,()]*\s*\)`)

// phpLdapEmptyPwBindRe: ldap_bind with an empty-string / null third (password)
// password (third) argument is an empty string or null literal. Anchored on
// the literal empty/null value so a variable password is not matched.
var phpLdapEmptyPwBindRe = regexp.MustCompile(`\bldap_bind(?:_ext)?\s*\([^,]+,[^,]+,\s*(?:''|""|[Nn][Uu][Ll][Ll])\s*[,)]`)

type PHPLdapAnonymousBind struct{}

func (r *PHPLdapAnonymousBind) ID() string   { return "BATOU-PHP-031" }
func (r *PHPLdapAnonymousBind) Name() string { return "PHPLdapAnonymousBind" }
func (r *PHPLdapAnonymousBind) Description() string {
	return "Detects ldap_bind() performed anonymously or with an empty/null password — an authentication bypass when the bind result gates access (CWE-287)."
}
func (r *PHPLdapAnonymousBind) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPLdapAnonymousBind) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PHPLdapAnonymousBind) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	if !strings.Contains(ctx.Content, "ldap_bind") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched, why string
		if m := rules.GFindLower(phpLdapEmptyPwBindRe, line, lowered[i]); m != "" {
			matched = m
			why = "ldap_bind() with an empty/null password performs an unauthenticated (anonymous) bind"
		} else if m := rules.GFindLower(phpLdapAnonBindRe, line, lowered[i]); m != "" {
			matched = m
			why = "ldap_bind() called with only the connection handle performs an anonymous bind"
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "LDAP anonymous / empty-password bind (authentication bypass)",
			Description:   why + ". If the application treats a successful bind as proof of valid credentials, an attacker can authenticate without a password — most LDAP servers accept an empty-password bind as anonymous and still return success.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(matched), 120),
			Suggestion:    "Require a non-empty password and reject empty/whitespace before binding. After ldap_bind(), confirm the bind was performed with the supplied credentials (not anonymously). Never treat an anonymous-bind success as authentication.",
			CWEID:         "CWE-287",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "ldap", "authentication-bypass", "anonymous-bind"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-032: magic-hash type juggling (CWE-697). md5()/sha1() result used
// as an operand of a loose `==`/`!=` comparison. Distinct from PHP-001/PHP-013
// (which key on password/token VARIABLE names): this anchors on the hash
// FUNCTION CALL adjacent to the loose operator, catching
// `if (md5($input) == $stored)` regardless of variable naming. `===`/`!==` and
// hash_equals() never match.
// ---------------------------------------------------------------------------

// phpMagicHashRe: a hash call (`md5(...)`/`sha1(...)`/`crc32(...)`) immediately
// followed by a loose `==` or `!=` — but NOT `===`/`!==`. The negative
// lookahead is emulated by requiring the operator NOT be followed by another
// `=`: in RE2 (no lookahead) we capture `==` / `!=` and then a non-`=`
// character. We allow `crc32` too — it is an even weaker (32-bit, non-crypto)
// hash and its loose comparison is equally exploitable.
var phpMagicHashRe = regexp.MustCompile(`\b(?:md5|sha1|crc32)\s*\([^()]*\)\s*(?:==|!=)[^=]`)

// phpMagicHashRevRe: the reverse operand order, `== md5(...)`. We require the
// operator be preceded by a non-`=` (so `=== md5(...)` is excluded) — captured
// by matching a character that is not `=`/`!` immediately before `==`.
var phpMagicHashRevRe = regexp.MustCompile(`[^=!](?:==|!=)\s*(?:md5|sha1|crc32)\s*\(`)

type PHPMagicHashComparison struct{}

func (r *PHPMagicHashComparison) ID() string   { return "BATOU-PHP-032" }
func (r *PHPMagicHashComparison) Name() string { return "PHPMagicHashComparison" }
func (r *PHPMagicHashComparison) Description() string {
	return "Detects md5()/sha1()/crc32() results compared with loose == / != — PHP magic-hash type juggling allows authentication bypass when two hashes coincidentally both cast to the float-0 (0e...) form (CWE-697)."
}
func (r *PHPMagicHashComparison) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPMagicHashComparison) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PHPMagicHashComparison) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	c := ctx.Content
	if !strings.Contains(c, "md5") && !strings.Contains(c, "sha1") && !strings.Contains(c, "crc32") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := rules.GFindLower(phpMagicHashRe, line, lowered[i]); m != "" {
			matched = m
		} else if m := rules.GFindLower(phpMagicHashRevRe, line, lowered[i]); m != "" {
			matched = m
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Magic-hash type juggling: hash compared with loose ==",
			Description:   "Comparing md5()/sha1() output with == lets PHP type-juggle two hashes that both look like '0e' followed by digits — both cast to float 0 and compare equal. An attacker can find an input whose hash is a '0e...' magic hash and bypass the check (e.g. password reset tokens, signature comparison).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(matched), 120),
			Suggestion:    "Use hash_equals($known, $given) for hash/MAC comparison (constant-time and type-safe), or strict comparison (===). Never compare hashes with == or !=.",
			CWEID:         "CWE-697",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "type-juggling", "magic-hash", "authentication-bypass"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-033: Unsafe reflection via ReflectionClass / ReflectionMethod /
// ReflectionFunction with a tainted class/method/function name (CWE-470).
// Anchored on the literal Reflection* construction whose FIRST argument
// (the class/method name) traces to a request source. The taint sinks
// php.reflection.* cover the dataflow case; this regex rule catches the
// dominant direct/var-indirected shapes the receiver-name heuristic misses
// (`$r = new ReflectionClass($_GET['c']); $r->newInstance();`).
//
// A literal class string (`new ReflectionClass(SomeService::class)`,
// `new ReflectionClass('App\\Foo')`) never matches because the arg is not a
// $variable. A $variable arg only fires when the taint lookback marks it
// request-derived, so reflection over a validated/internal name stays clean.
// ---------------------------------------------------------------------------

// phpReflectionCtorRe captures `new ReflectionClass($var` / `ReflectionMethod`
// / `ReflectionFunction` / `ReflectionObject` where the first argument is a
// PHP variable. Captures group 1 = the reflected-name variable so we can run
// the taint lookback.
var phpReflectionCtorRe = regexp.MustCompile(`\bnew\s+\\?Reflection(?:Class|Method|Function|Object)\s*\(\s*\$(\w+)`)

// phpReflectionCtorSuperglobalRe captures the inline-superglobal form:
// `new ReflectionClass($_GET['c'])`. Unconditionally request-controlled.
var phpReflectionCtorSuperglobalRe = regexp.MustCompile(`\bnew\s+\\?Reflection(?:Class|Method|Function|Object)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[`)

type PHPUnsafeReflection struct{}

func (r *PHPUnsafeReflection) ID() string   { return "BATOU-PHP-033" }
func (r *PHPUnsafeReflection) Name() string { return "PHPUnsafeReflection" }
func (r *PHPUnsafeReflection) Description() string {
	return "Detects ReflectionClass/ReflectionMethod/ReflectionFunction constructed with a class/method name that traces back to a request source — unsafe reflection / arbitrary class instantiation (CWE-470)."
}
func (r *PHPUnsafeReflection) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPUnsafeReflection) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PHPUnsafeReflection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	if !strings.Contains(ctx.Content, "Reflection") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := rules.GFindLower(phpReflectionCtorSuperglobalRe, line, lowered[i]); m != "" {
			matched = m
		} else if m := rules.GFindSubmatchLower(phpReflectionCtorRe, line, lowered[i]); m != nil {
			nameVar := m[1]
			if strings.HasPrefix(nameVar, "_") {
				// bare $_x is not a superglobal (the direct form is handled
				// by the superglobal regex above) — skip.
				continue
			}
			if phpVarTaintedTransitive(lines, i, nameVar, 0) {
				matched = m[0]
			}
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Unsafe reflection: Reflection* built from attacker-controlled name",
			Description:   "Constructing a ReflectionClass/ReflectionMethod/ReflectionFunction from a request-derived name lets an attacker reflect over (and via newInstance/invoke realise) any class, method, or function the autoloader can reach — arbitrary object construction and a primary POP-gadget / object-injection trigger.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(matched), 120),
			Suggestion:    "Map the request value through an explicit allow-list of permitted class/method names before reflecting, or use a fixed dispatch table. Never pass raw user input to a Reflection* constructor.",
			CWEID:         "CWE-470",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "unsafe-reflection", "object-injection", "rce"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-034: openssl_encrypt() with a static / literal / reused IV
// (CWE-329). The cross-language BATOU-CRY-020 only matches IVs assigned to a
// variable literally NAMED iv/nonce (`$iv = "..."`); it does NOT match the PHP
// idiom where the IV is the 5th positional argument of openssl_encrypt:
//
//   openssl_encrypt($data, 'aes-256-cbc', $key, 0, '1234567890123456')  // literal IV
//   openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv)                  // reused/static $iv
//
// We fire on the LITERAL-IV form (a quoted string in the 5th slot, or an
// all-zero / str_repeat IV) which is unambiguously static. A random IV via
// openssl_random_pseudo_bytes()/random_bytes() in the same expression is never
// matched, and a sanitizer entry below clears the flow when a fresh random IV
// is generated on the line.
// ---------------------------------------------------------------------------

// phpOpensslLiteralIVRe matches openssl_encrypt(...) whose 5th argument (the
// IV) is a quoted string literal. The first four args are matched non-greedily
// up to the 4th comma, then a quote opens the IV. Because openssl_encrypt's
// own arguments rarely contain commas-in-strings before the IV in real code,
// this conservative shape keeps FPs minimal.
var phpOpensslLiteralIVRe = regexp.MustCompile(`\bopenssl_encrypt\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(?:'[^']*'|"[^"]*")`)

// phpOpensslZeroIVRe matches an IV built from str_repeat() of a single byte or
// an explicit all-zero literal in the 5th slot — a classic "static IV".
var phpOpensslZeroIVRe = regexp.MustCompile(`\bopenssl_encrypt\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(?:str_repeat\s*\(|"\\0|'\\0)`)

type PHPOpensslStaticIV struct{}

func (r *PHPOpensslStaticIV) ID() string   { return "BATOU-PHP-034" }
func (r *PHPOpensslStaticIV) Name() string { return "PHPOpensslStaticIV" }
func (r *PHPOpensslStaticIV) Description() string {
	return "Detects openssl_encrypt() called with a literal / static initialization vector (5th argument) — deterministic encryption enabling chosen-plaintext attacks (CBC) or catastrophic nonce reuse (GCM) (CWE-329)."
}
func (r *PHPOpensslStaticIV) DefaultSeverity() rules.Severity { return rules.High }
func (r *PHPOpensslStaticIV) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PHPOpensslStaticIV) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	if !strings.Contains(ctx.Content, "openssl_encrypt") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := rules.GFindLower(phpOpensslLiteralIVRe, line, lowered[i]); m != "" {
			matched = m
		} else if m := rules.GFindLower(phpOpensslZeroIVRe, line, lowered[i]); m != "" {
			matched = m
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "openssl_encrypt() with a static/literal IV",
			Description:   "A literal or constant initialization vector makes encryption deterministic: identical plaintexts produce identical ciphertexts. For AES-CBC this enables chosen-plaintext / BEAST-style attacks; for AES-GCM, IV reuse is catastrophic (authentication-key recovery, full plaintext compromise).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(matched), 120),
			Suggestion:    "Generate a fresh random IV per encryption with openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher)) (or random_bytes), prepend it to the ciphertext, and read it back for decryption. Never hardcode or reuse the IV.",
			CWEID:         "CWE-329",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "crypto", "static-iv", "openssl"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-035: openssl_decrypt() whose boolean-false return is never checked
// before the plaintext is used (CWE-252, unchecked return / silent decryption
// failure). openssl_decrypt() returns `false` on failure (bad key, tampered
// ciphertext, wrong IV). Code that assigns the result and immediately uses it
// without an `=== false` / `if (!$x)` guard treats a failed decryption as a
// valid empty/false plaintext — a silent auth/integrity bypass.
//
// We fire ONLY when an assignment `$x = openssl_decrypt(...)` is NOT followed
// (within a short window) by a check of `$x` against false/null/empty or a
// guard. This deliberately conservative window keeps the safe idiom
// (`$pt = openssl_decrypt(...); if ($pt === false) { ... }`) clean.
// ---------------------------------------------------------------------------

// phpOpensslDecryptAssignRe captures `$var = openssl_decrypt(`.
var phpOpensslDecryptAssignRe = regexp.MustCompile(`\$(\w+)\s*=\s*(?:@\s*)?openssl_decrypt\s*\(`)

type PHPOpensslDecryptUnchecked struct{}

func (r *PHPOpensslDecryptUnchecked) ID() string   { return "BATOU-PHP-035" }
func (r *PHPOpensslDecryptUnchecked) Name() string { return "PHPOpensslDecryptUnchecked" }
func (r *PHPOpensslDecryptUnchecked) Description() string {
	return "Detects openssl_decrypt() whose boolean-false return value is not checked before the decrypted result is used — a failed decryption is silently treated as valid plaintext (CWE-252)."
}
func (r *PHPOpensslDecryptUnchecked) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PHPOpensslDecryptUnchecked) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *PHPOpensslDecryptUnchecked) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	if !strings.Contains(ctx.Content, "openssl_decrypt") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindSubmatchLower(phpOpensslDecryptAssignRe, line, lowered[i])
		if m == nil {
			continue
		}
		v := m[1]
		// Look in the next few lines (and the rest of this line after the
		// call) for a check of $v against false/null/empty or a negation guard.
		if phpReturnChecked(lines, i, v) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Unchecked openssl_decrypt() return value",
			Description:   "openssl_decrypt() returns boolean false when decryption fails (wrong key, tampered ciphertext, bad IV). Using the result without a strict `=== false` check treats a failed decryption as a valid (empty/false) plaintext — an attacker who corrupts the ciphertext silently downgrades the value rather than triggering an error.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Check the return strictly before use: `$pt = openssl_decrypt(...); if ($pt === false) { /* reject */ }`. Combine with an authenticated cipher (AES-GCM) or a verified HMAC so tampering is detected, not silently absorbed.",
			CWEID:         "CWE-252",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"php", "crypto", "unchecked-return", "openssl"},
		})
	}
	return findings
}

// phpReturnChecked reports whether variable v assigned at lineIdx is checked
// against false/null/empty (or guarded by a negation / short-circuit) anywhere
// in a generous window after the assignment. It is deliberately CONSERVATIVE
// (biased toward "checked" → no finding): the openssl_decrypt() call frequently
// spans several physical lines, and the `if ($pt !== false)` guard can sit a
// dozen lines below, so under-reporting a guard would create false positives on
// correct code. The window is 18 lines and ANY line mentioning $v together with
// a falsiness check counts as a guard.
func phpReturnChecked(lines []string, lineIdx int, v string) bool {
	vTok := "$" + v
	// Same-line short-circuit / inline guard on the assignment line itself:
	// `$x = openssl_decrypt(...) ?: handle();` / `... or die()` / `=== false`.
	if assign := lines[lineIdx]; true {
		seg := assign
		if idx := strings.Index(assign, "openssl_decrypt"); idx >= 0 {
			seg = assign[idx:]
		}
		if strings.Contains(seg, "?:") || strings.Contains(seg, "??") ||
			strings.Contains(seg, "===") || strings.Contains(seg, "!==") ||
			strings.Contains(seg, " or ") || strings.Contains(seg, " ?? ") {
			return true
		}
	}
	end := lineIdx + 18
	if end > len(lines) {
		end = len(lines)
	}
	vLower := strings.ToLower(vTok)
	for j := lineIdx + 1; j < end; j++ {
		l := lines[j]
		if isComment(l) {
			continue
		}
		ll := strings.ToLower(l)
		// Only lines that reference the decrypted variable can be its guard.
		if !strings.Contains(ll, vLower) {
			continue
		}
		// Falsiness / null / strict-comparison / negation / type guard on $v.
		if strings.Contains(ll, "false") || strings.Contains(ll, "null") ||
			strings.Contains(l, "===") || strings.Contains(l, "!==") ||
			strings.Contains(ll, "empty("+vLower) ||
			strings.Contains(ll, "is_string("+vLower) ||
			strings.Contains(ll, "is_bool("+vLower) ||
			strings.Contains(ll, "!"+vLower) ||
			strings.Contains(ll, "if ("+vLower) || strings.Contains(ll, "if("+vLower) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-PHP-036: phpinfo() / phpcredits() / phpversion()-dump in application
// code (CWE-200, information disclosure). phpinfo() dumps the full PHP
// environment — loaded extensions, absolute paths, environment variables
// (often including DB passwords / API keys), and the exact PHP/OS version —
// which is reconnaissance gold and frequently a direct secret leak. It belongs
// only in throwaway diagnostics, never a reachable code path.
//
// Anchored on the literal call. We do NOT flag `phpinfo` inside a comment, and
// we skip files that look like a CLI entrypoint marker is irrelevant here —
// the call itself in shipped web code is the finding.
// ---------------------------------------------------------------------------

var phpInfoCallRe = regexp.MustCompile(`\b(?:phpinfo|phpcredits)\s*\(`)

type PHPInfoDisclosure struct{}

func (r *PHPInfoDisclosure) ID() string   { return "BATOU-PHP-036" }
func (r *PHPInfoDisclosure) Name() string { return "PHPInfoDisclosure" }
func (r *PHPInfoDisclosure) Description() string {
	return "Detects phpinfo()/phpcredits() calls — they dump the full PHP environment (paths, extensions, env vars including secrets, exact versions), a serious information-disclosure / reconnaissance exposure (CWE-200)."
}
func (r *PHPInfoDisclosure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PHPInfoDisclosure) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PHPInfoDisclosure) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	c := ctx.Content
	if !strings.Contains(c, "phpinfo") && !strings.Contains(c, "phpcredits") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindLower(phpInfoCallRe, line, lowered[i])
		if m == "" {
			continue
		}
		// A function/method DEFINITION named phpinfo (rare, but `function
		// phpinfo_section()` would be a substring) is excluded by the `(` anchor
		// requiring the call form; a `function phpinfo(` definition shape is
		// also excluded because real code never redefines the builtin.
		if strings.Contains(line, "function ") {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Information disclosure via phpinfo()/phpcredits()",
			Description:   "phpinfo() renders the entire PHP configuration: absolute filesystem paths, every loaded extension and its version, the exact PHP and OS build, and the full environment (which commonly contains database credentials, API keys, and APP_KEY). Any reachable phpinfo() hands an attacker a complete recon dump and often live secrets.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Remove phpinfo()/phpcredits() from shipped code. If diagnostics are needed, gate them behind an authenticated admin-only path that is disabled in production, and never expose environment variables.",
			CWEID:         "CWE-200",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "information-disclosure", "phpinfo"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-037: integer/precision loss when a hash output is reduced through
// base_convert()/intval($x, $base)/hexdec()/octdec() and the result feeds a
// security comparison (CWE-190). PHP integers are 64-bit; base_convert() and
// hexdec() on a long hash string overflow to a float and lose precision, so
// many distinct hashes collapse to the same number — letting an attacker find
// a colliding value and bypass the check. Anchored on the conversion call
// applied DIRECTLY to a hash()/md5()/sha1()/hash_hmac() output (so generic
// base_convert on small numbers never fires).
// ---------------------------------------------------------------------------

// phpHashPrecisionRe: a precision-losing numeric conversion wrapping a hash
// call — e.g. `hexdec(md5($x))`, `base_convert(sha1($x), 16, 10)`,
// `intval(hash('sha256', $x), 16)`.
var phpHashPrecisionRe = regexp.MustCompile(`\b(?:hexdec|octdec|base_convert|intval)\s*\(\s*(?:@\s*)?(?:md5|sha1|crc32|hash|hash_hmac)\s*\(`)

type PHPHashPrecisionLoss struct{}

func (r *PHPHashPrecisionLoss) ID() string   { return "BATOU-PHP-037" }
func (r *PHPHashPrecisionLoss) Name() string { return "PHPHashPrecisionLoss" }
func (r *PHPHashPrecisionLoss) Description() string {
	return "Detects a hash output reduced through hexdec()/base_convert()/intval(.., base) — 64-bit integer/float precision loss collapses distinct hashes to the same number, enabling a comparison-bypass collision (CWE-190)."
}
func (r *PHPHashPrecisionLoss) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PHPHashPrecisionLoss) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PHPHashPrecisionLoss) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	c := ctx.Content
	if !strings.Contains(c, "hexdec") && !strings.Contains(c, "octdec") &&
		!strings.Contains(c, "base_convert") && !strings.Contains(c, "intval") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindLower(phpHashPrecisionRe, line, lowered[i])
		if m == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Integer precision loss on hash output (collision bypass)",
			Description:   "Passing a hash() / md5() / sha1() string through hexdec(), base_convert(), or intval(.., base) reduces it to a PHP integer, which silently overflows to a float beyond 2^53 and loses precision. Many distinct hashes then map to the same numeric value, so an attacker can craft an input whose reduced hash equals the expected one and bypass the comparison.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(m), 120),
			Suggestion:    "Compare the full hash string with hash_equals($expected, $actual) (constant-time). Never reduce a cryptographic hash to an integer for comparison or as a token.",
			CWEID:         "CWE-190",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"php", "integer-overflow", "hash", "precision-loss"},
		})
	}
	return findings
}

func init() {
	rules.Register(&PHPDynamicInstantiation{})
	rules.Register(&PHPLdapAnonymousBind{})
	rules.Register(&PHPMagicHashComparison{})
	rules.Register(&PHPUnsafeReflection{})
	rules.Register(&PHPOpensslStaticIV{})
	rules.Register(&PHPOpensslDecryptUnchecked{})
	rules.Register(&PHPInfoDisclosure{})
	rules.Register(&PHPHashPrecisionLoss{})
}
