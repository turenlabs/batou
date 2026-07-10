package crypto

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// --- Compiled regex patterns ---

// BATOU-CRY-001: Weak hashing
var (
	reGoMD5  = regexp.MustCompile(`\bmd5\.(New|Sum)\b`)
	reGoSHA1 = regexp.MustCompile(`\bsha1\.(New|Sum)\b`)
	rePyMD5  = regexp.MustCompile(`\bhashlib\.md5\s*\(`)
	rePySHA1 = regexp.MustCompile(`\bhashlib\.sha1\s*\(`)
	// hashlib.new() with weak algorithm specified as string argument
	rePyHashlibNew = regexp.MustCompile(`\bhashlib\.new\s*\(\s*["'](?:md5|sha1)["']`)
	reJSMD5        = regexp.MustCompile(`crypto\.createHash\s*\(\s*['"]md5['"]`)
	reJSSHA1       = regexp.MustCompile(`crypto\.createHash\s*\(\s*['"]sha1['"]`)
	reJavaMD5      = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"MD5"`)
	reJavaSHA1     = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"SHA-?1"`)
	// Indirect: MessageDigest.getInstance(variable) — algorithm from external source
	reJavaDigestVar = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*([a-zA-Z_]\w*)[\s,)]`)
	reSecurityCtx   = regexp.MustCompile(`(?i)(password|secret|token|auth|sign|hmac|credential|cert)`)
	// reNonSecurityCtx markers that strongly suggest the hash is used as
	// an identifier / cache key / protocol primitive, not a security
	// primitive. When detected on the line OR the surrounding ±5 lines,
	// the rule is suppressed because the algorithm choice is dictated by
	// protocol (e.g. Git's SHA-1 commit IDs, HIBP's SHA-1 hashprefix
	// API) or non-security purpose (Etag, avatar fingerprint, cache key).
	// Note: deliberately omitting common words like `identifier`, `digest`,
	// `id` — they collide with security contexts ("session identifier",
	// "message digest"). Stick to terms that are strongly non-security.
	reNonSecurityCtx = regexp.MustCompile(`(?i)(?:\bgit[/_.]|\bcommit\b|\bblob\b|\btree\b|\bobject_format\b|\bavatar\b|\bgravatar\b|\bcache_key\b|\bcacheKey\b|\betag\b|\bfingerprint\b|\bhibp\b|haveibeenpwned)`)
)

// BATOU-CRY-002: Insecure random
var (
	reGoMathRand   = regexp.MustCompile(`\bmath/rand\b`)
	reGoRandCall   = regexp.MustCompile(`\brand\.(Int|Intn|Float|Read|New)\b`)
	rePyRandom     = regexp.MustCompile(`\brandom\.(random|randint|choice|randrange|getrandbits|normalvariate|randbytes|gauss|uniform|sample|shuffle|expovariate|gammavariate|lognormvariate|vonmisesvariate|paretovariate|weibullvariate|betavariate|triangular)\s*\(`)
	reJSMathRandom = regexp.MustCompile(`\bMath\.random\s*\(`)
	reSecRandCtx   = regexp.MustCompile(`(?i)(token|password|key|secret|nonce|salt|otp|csrf|session|uuid|auth|cookie|remember)`)
)

// BATOU-CRY-003: Weak cipher
var (
	reGoDES      = regexp.MustCompile(`\bdes\.(NewCipher|NewTripleDESCipher)\b`)
	reGoRC4      = regexp.MustCompile(`\brc4\.NewCipher\b`)
	rePyDES      = regexp.MustCompile(`\bDES(3)?\.new\s*\(`)
	rePyARC4     = regexp.MustCompile(`\bARC4\.new\s*\(`)
	rePyBlowfish = regexp.MustCompile(`\bBlowfish\.new\s*\(`)
	reJavaDES    = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"DES`)
	reJavaRC4    = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"(RC4|ARCFOUR)`)
	reECBMode    = regexp.MustCompile(`(?i)(?:\b|_)ECB\b`)
	reWeakCipher = regexp.MustCompile(`(?i)\b(DES|3DES|TripleDES|RC4|RC2|Blowfish|ARCFOUR)\b`)
	// The generic reWeakCipher fallback matches a bare `des`/`rc4` token — which the
	// French article "des" in l10n JSON bundles and the `browserify-des` / `des.js`
	// dependency lines in `pnpm-lock.yaml` trip (10 FPs in owncloud/web). Only fire
	// the fallback when a crypto-API context is present on the same line, and never
	// inside dependency lockfiles or string-pair data bundles.
	reWeakCipherCryptoCtx = regexp.MustCompile(`(?i)(cipher|crypto|encrypt|decrypt|getInstance|new\s+\w*(?:DES|RC4|RC2|Blowfish)|KeySpec|EVP_|MODE_|/ECB|/CBC|PKCS\d|padding|secret_?key|algorithm\b|\balgo\b)`)
	// File paths where CRY-003's generic token fallback must not fire: dependency
	// lockfiles (transitive package names mention `des`/`rc4`) and data bundles.
	reWeakCipherSkipPath = regexp.MustCompile(`(?i)(?:^|/)(?:[^/]*-lock\.(?:ya?ml|json)|package-lock\.json|pnpm-lock\.ya?ml|yarn\.lock|composer\.lock|Cargo\.lock|Gemfile\.lock|poetry\.lock|go\.sum|go\.mod)$`)
)

// BATOU-CRY-004: Hardcoded IV / nonce
var (
	reGoByteIV     = regexp.MustCompile(`(?i)\b(iv|nonce)\s*[:=]+\s*\[\]byte\s*\{`)
	reStringIV     = regexp.MustCompile(`(?i)\b(iv|nonce|initialization.?vector)\s*[:=]\s*["']`)
	reFixedIVBytes = regexp.MustCompile(`(?i)\b(iv|nonce)\s*[:=]\s*(b["']|bytes\s*\(|new\s+byte\s*\[)`)
	reByteArrayIV  = regexp.MustCompile(`(?i)\b(iv|nonce)\s*=\s*\[\s*0x`)
)

// BATOU-CRY-005: Insecure TLS
var (
	reGoInsecureSkip   = regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)
	rePyVerifyFalse    = regexp.MustCompile(`verify\s*=\s*False`)
	reNodeRejectUnauth = regexp.MustCompile(`rejectUnauthorized\s*:\s*false`)
	reNodeTLSEnv       = regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?`)
	reTLS10            = regexp.MustCompile(`(?:MinVersion|min_version|minVersion)\s*[:=]\s*(?:tls\.VersionTLS10|tls\.VersionTLS11|['"]TLSv1(?:\.0|\.1)?['"]|0x0301|0x0302)`)
	rePySSlNoVerify    = regexp.MustCompile(`ssl\._create_unverified_context|CERT_NONE`)
)

// BATOU-CRY-006: Weak key size
var (
	reGoRSAKeySize   = regexp.MustCompile(`rsa\.GenerateKey\s*\([^,]+,\s*(512|768|1024)\s*\)`)
	reRSASmallKey    = regexp.MustCompile(`(?i)(?:key[_\s-]?(?:size|length|bits)|bits)\s*[:=]\s*(512|768|1024)\b`)
	reWeakCurve      = regexp.MustCompile(`(?i)\b(P-?192|secp192r1|prime192v1)\b`)
	reJavaRSAKeySize = regexp.MustCompile(`(?:initialize|KeyPairGenerator)\s*\(\s*(512|768|1024)\s*\)`)
)

// BATOU-CRY-007: Plaintext protocol
var (
	reHTTPURL       = regexp.MustCompile(`["']http://[^"'\s]+["']`)
	reHTTPLocalhost = regexp.MustCompile(`http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`)
	reHTTPExample   = regexp.MustCompile(`http://(example\.com|example\.org|test\.)`)
	reHTTPSensitive = regexp.MustCompile(`(?i)http://[^"'\s]*(api|auth|login|webhook|payment|token|oauth|callback)`)
	// reCryptoTestFile mirrors rules/secrets/secrets.go:reTestFile so we
	// can skip CRY-007 (and other crypto FPs) on test fixtures. Test
	// files routinely use throwaway `'http://some-image.jpg'`-style URLs
	// as DOM-attribute fixtures — those produced 18 FPs in owncloud/web.
	reCryptoTestFile = regexp.MustCompile(`(?i)(_test\.go|_test\.py|\.test\.[jt]sx?|\.spec\.[jt]sx?|test_.*\.py|tests?/|__tests__/|spec/|fixtures?/|mock|fake|stub|example)`)
)

// BATOU-CRY-008: Math.random() in security context (JS/TS specific, broader than CRY-002)
var (
	reJSMathRandomBroad = regexp.MustCompile(`\bMath\.random\s*\(`)
	reJSSecurityCtx     = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|api[_\-]?key|encrypt)`)
)

// BATOU-CRY-009: Python random module in security context
var (
	rePyRandomBroad = regexp.MustCompile(`\brandom\.(random|randint|choice|sample|randrange|getrandbits|shuffle|uniform|normalvariate|randbytes|gauss|expovariate|gammavariate|lognormvariate|vonmisesvariate|paretovariate|weibullvariate|betavariate|triangular)\s*\(`)
	rePySecurityCtx = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|api[_\-]?key|encrypt|hash|cookie|remember)`)
)

// BATOU-CRY-010: Weak PRNG across languages
var (
	// Java
	reJavaUtilRandom   = regexp.MustCompile(`\bnew\s+Random\s*\(`)
	reJavaRandomImport = regexp.MustCompile(`\bjava\.util\.Random\b`)
	// PHP
	rePHPRand  = regexp.MustCompile(`\b(rand|mt_rand|srand|mt_srand)\s*\(`)
	rePHPArray = regexp.MustCompile(`\barray_rand\s*\(`)
	// Ruby
	reRubyRand    = regexp.MustCompile(`\brand\s*\(`)
	reRubyRandObj = regexp.MustCompile(`\bRandom\.(new|rand|srand)\b`)
	// C#
	reCSharpRandom = regexp.MustCompile(`\bnew\s+Random\s*\(`)
	// Go (broader: any math/rand usage in security context)
	reGoMathRandImport = regexp.MustCompile(`"math/rand`)
	// Weak PRNG security context (shared across languages in CRY-010)
	reWeakPRNGSecCtx = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|encrypt|hash|credential|certificate)`)
)

// BATOU-CRY-011: Predictable seeds
var (
	rePySeedTime     = regexp.MustCompile(`\brandom\.seed\s*\(\s*(time|int\s*\(\s*time|datetime)`)
	rePySeedFixed    = regexp.MustCompile(`\brandom\.seed\s*\(\s*\d+\s*\)`)
	reCSeedTime      = regexp.MustCompile(`\bsrand\s*\(\s*time\s*\(`)
	reJavaSeedTime   = regexp.MustCompile(`\.setSeed\s*\(\s*(System\.currentTimeMillis|System\.nanoTime|new\s+Date)`)
	reJavaSeedFixed  = regexp.MustCompile(`\.setSeed\s*\(\s*\d+L?\s*\)`)
	reJavaFixedSeed  = regexp.MustCompile(`\bnew\s+Random\s*\(\s*\d+L?\s*\)`)
	reGoSeedTime     = regexp.MustCompile(`\brand\.Seed\s*\(\s*time\.`)
	reGoSeedFixed    = regexp.MustCompile(`\brand\.Seed\s*\(\s*\d+\s*\)`)
	reGoNewSource    = regexp.MustCompile(`\brand\.NewSource\s*\(\s*\d+\s*\)`)
	rePHPSrandTime   = regexp.MustCompile(`\b(srand|mt_srand)\s*\(\s*time\s*\(`)
	rePHPSrandFixed  = regexp.MustCompile(`\b(srand|mt_srand)\s*\(\s*\d+\s*\)`)
	reRubySrandFixed = regexp.MustCompile(`\bsrand\s*\(\s*\d+\s*\)`)
)

// BATOU-CRY-012: Hardcoded cryptographic keys
var (
	// Go: key-like variable assigned []byte("literal") — [:=]+ handles both = and :=
	reGoByteStringKey = regexp.MustCompile(`(?i)\b(key|secret)\s*[:=]+\s*\[\]byte\s*\(\s*["']`)
	// Python: b"literal" or "literal" assigned to key-like variable
	rePyHardcodedKey = regexp.MustCompile(`(?i)\b(key|secret|aes_key|encryption_key|secret_key|private_key)\s*=\s*(b?["'][^"']{4,}["'])`)
	// JS/TS: Buffer.from("literal") or string literal assigned to key var
	reJSBufferFromKey = regexp.MustCompile(`Buffer\.from\s*\(\s*["'][^"']{4,}["']`)
	reJSHardcodedKey  = regexp.MustCompile(`(?i)\b(key|secret|aes_key|encryption_key|secret_key|private_key)\s*=\s*["'][^"']{4,}["']`)
	// Java: SecretKeySpec with inline bytes or .getBytes()
	reJavaSecretKeySpec = regexp.MustCompile(`new\s+SecretKeySpec\s*\(\s*["']`)
	reJavaGetBytesKey   = regexp.MustCompile(`["'][^"']{4,}["']\s*\.getBytes\s*\(`)
	// Generic: variable name clearly indicates crypto key, assigned string literal
	reGenericHardcodedKey = regexp.MustCompile(`(?i)\b(aes_key|encryption_key|secret_key|cipher_key|crypto_key|hmac_key|signing_key)\s*[:=]\s*["'][^"']{4,}["']`)
	// Context: near crypto operations
	reCryptoKeyCtx = regexp.MustCompile(`(?i)(encrypt|decrypt|cipher|aes|hmac|sign|SecretKey|crypto|seal|open)`)

	// Vue/HTML/JSX template-attribute false-positive guards for reJSHardcodedKey.
	// `.vue` SFCs are scanned as JavaScript, so `:key="item.id"`, `key="modal-btn"`,
	// `<li v-for="..." :key="idx">` etc. all match `key=` / `secret=` against a string
	// literal — but they are list-render keys / DOM attributes, never hardcoded secrets.
	// (123 FPs in owncloud/web.)
	//   1. `:key=` / `v-bind:key=` / `v-bind:secret=` — Vue bound attribute, never a JS var.
	reVueBoundKeyAttr = regexp.MustCompile(`(?i)(?::|\bv-bind:)(?:key|secret)\s*=`)
	//   2. The line carries HTML/Vue/JSX markup: an opening/closing element tag, a
	//      self-closing tag, a Vue structural directive, an event binding (@click),
	//      or another bound attribute (:class=).
	reHTMLMarkupLine = regexp.MustCompile(`</?[A-Za-z][\w.-]*[\s/>]|/>|\bv-(?:for|if|else|else-if|show|model|slot|bind|on|html|text)\b|@[\w.:-]+\s*=|:[\w.-]+\s*=`)
	//   3. The line is *only* an unbound `key=`/`secret=` HTML attribute (no spaces around
	//      `=`, the HTML convention) — i.e. a multi-line element's attribute on its own line.
	//      JS assignments conventionally read `key = "..."` with spaces and keep firing.
	reBareHTMLKeyAttr = regexp.MustCompile(`(?i)^\s*:?(?:key|secret)=["'][^"']*["']\s*/?>?\s*$`)
)

// isVueOrHTMLKeyAttr reports whether a `key=`/`secret=` string-literal match on the
// given line is an HTML/Vue/JSX element attribute rather than a JS variable assignment.
// Used to suppress reJSHardcodedKey false positives in `.vue`/JSX templates.
func isVueOrHTMLKeyAttr(line string) bool {
	return rules.GMatch(reVueBoundKeyAttr, line) ||
		rules.GMatch(reHTMLMarkupLine, line) ||
		rules.GMatch(reBareHTMLKeyAttr, line)
}

// BATOU-CRY-013: Unauthenticated encryption (CBC without HMAC)
var (
	reGoCBCEncrypt = regexp.MustCompile(`cipher\.NewCBC(Encrypter|Decrypter)\b`)
	rePyCBCMode    = regexp.MustCompile(`AES\.MODE_CBC|mode\s*=\s*['"]CBC['"]`)
	reJavaCBC      = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']AES/CBC/`)
	reJSCBCCipher  = regexp.MustCompile(`create(Cipher|Decipher)iv\s*\(\s*['"]aes-\d+-cbc['"]`)
	reAuthCheck    = regexp.MustCompile(`(?i)(hmac|mac|tag|gcm|poly1305|authenticate|verify_mac|verify_tag|AEAD|GCM|CCM)`)
)

// BATOU-CRY-014: Insecure RSA padding (PKCS1v15 for encryption)
var (
	reGoRSAPKCS1Encrypt = regexp.MustCompile(`rsa\.EncryptPKCS1v15\b`)
	reGoRSAPKCS1Decrypt = regexp.MustCompile(`rsa\.DecryptPKCS1v15\b`)
	// Match RSA/<any-mode>/PKCS1Padding in Java (avoids literal weak-mode keyword)
	reJavaRSAPKCS1      = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']RSA/[^"'/]+/PKCS1Padding["']`)
	reJavaRSANoPadding  = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']RSA["']\s*\)`)
	rePyPKCS1v15Encrypt = regexp.MustCompile(`PKCS1_v1_5\.new\s*\(`)
	reJSRSAPKCS1Padding = regexp.MustCompile(`(?i)RSA_PKCS1_PADDING`)
)

// BATOU-CRY-015: Weak password hashing (MD5/SHA for passwords)
var (
	rePasswordCtx = regexp.MustCompile(`(?i)(password|passwd|pass_hash|pwd|user_pass)`)
	// Python: hashlib.md5/sha1/sha256 with password nearby
	rePyHashPassword = regexp.MustCompile(`hashlib\.(md5|sha1|sha256|sha224)\s*\(`)
	// Go: md5.Sum or sha256.Sum256 with password nearby
	reGoHashPassword = regexp.MustCompile(`(md5\.Sum|sha1\.Sum|sha256\.Sum256|sha256\.New|sha512\.New)\s*\(`)
	// Java: MessageDigest for password context
	reJavaDigestPassword = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1|SHA-?256|SHA-?512)["']`)
	// JS/TS: createHash for password context
	reJSHashPassword = regexp.MustCompile(`crypto\.createHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]`)
	// PHP: md5($password) or sha1($password)
	rePHPHashPassword = regexp.MustCompile(`\b(md5|sha1)\s*\(\s*\$`)
	// Proper password hashing (suppress if present)
	reProperPasswordHash = regexp.MustCompile(`(?i)(bcrypt|scrypt|argon2|pbkdf2|password_hash|PBKDF2WithHmacSHA|Rfc2898DeriveBytes)`)
)

// BATOU-CRY-016: Insecure randomness in security context (broader multi-language)
var (
	// Ruby
	reRubyRandSec    = regexp.MustCompile(`\brand\s*\(`)
	reRubyRandObjSec = regexp.MustCompile(`\bRandom\.(new|rand)\b`)
	// PHP
	rePHPRandSec = regexp.MustCompile(`\b(rand|mt_rand)\s*\(`)
	// Shared security context for CRY-016
	reCRY016SecCtx = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|api[_\-]?key)`)
)

// BATOU-CRY-017: Timing-unsafe string comparison
//
// Tightening note (2026-04-26): the previous patterns matched any
// `<name with secret-keyword> == \w+` — including nil/zero/existence
// checks like `cfg.TokenManager == nil`, `if password == ""`,
// `if hash == nil`. 61 FPs in owncloud/ocis. Added reTimingNilOrZero
// to skip those — they're existence checks, not secret comparisons.
var (
	// Pattern: if (someVar == otherVar) where vars have security-related names
	reTimingCompareJS   = regexp.MustCompile(`(?:===?)\s*\w*(?i:token|secret|hash|password|digest|signature|hmac|api[_\-]?key|nonce|csrf)\w*`)
	reTimingComparePy   = regexp.MustCompile(`(?i)\w*(token|secret|hash|password|digest|signature|hmac|api_key|nonce|csrf)\w*\s*==\s*\w+`)
	reTimingCompareGo   = regexp.MustCompile(`(?i)\w*(token|secret|hash|password|digest|signature|hmac|apiKey|nonce|csrf)\w*\s*==\s*\w+`)
	reTimingCompareRuby = regexp.MustCompile(`(?i)\w*(token|secret|hash|password|digest|signature|hmac|api_key|nonce|csrf)\w*\s*==\s*\w+`)
	// Existence / nil / empty / literal checks — these aren't secret-value
	// comparisons. Match the RHS of `==` to skip:
	//   foo == nil / null / undefined / true / false / <integer> / "" / ''
	reTimingNilOrZero = regexp.MustCompile(`==\s*(?:nil|null|undefined|true|false|\d+|""|''|\(\s*\)|\[\s*\])\b?`)
	// Length comparisons (`token.length === expected.length`) leak length, not
	// content — not the timing channel CRY-017 targets, and a constant-time
	// rewrite is not the fix. Require `.length`/`.size`/`.len` immediately on one
	// side of the comparison operator so an unrelated `.length` elsewhere on the
	// line doesn't suppress a real finding.
	reTimingLengthCompare = regexp.MustCompile(`\.\s*(?:length|size|len)(?:\s*\(\s*\))?\s*[!=]==?|[!=]==?\s*\w[\w.$\[\]'"]*\.\s*(?:length|size|len)\b`)
	// Reverse pattern: variable == securityThing
	reTimingCompareRev = regexp.MustCompile(`\w+\s*===?\s*\w*(?i:token|secret|hash|password|digest|signature|hmac|api[_\-]?key|nonce|csrf)\w*`)
	// Operand extractor: the two operands either side of an (in)equality operator.
	// Used to detect reflexive comparisons (`token === token`) which can't be a
	// timing leak — both sides are the same in-memory value. (7 FPs in owncloud/web,
	// client-side store comparisons of a value against itself.)
	reTimingEqOperands = regexp.MustCompile(`([\w.$\['"\]]+)\s*[!=]==?\s*([\w.$\['"\]]+)`)
	// Safe comparison functions (suppress if present on same line)
	reTimingSafeCompare = regexp.MustCompile(`(?i)(timingSafeEqual|compare_digest|ConstantTimeCompare|secure_compare|constant_time_compare|MessageDigest\.isEqual|crypto\.subtle\.timingSafeEqual|Rack::Utils\.secure_compare)`)
)

// isReflexiveCompare reports whether the line contains an (in)equality comparison
// whose two operands are lexically identical (e.g. `token === token`, `a.id === a.id`).
// Such a comparison always evaluates the same value on both sides, so it cannot leak a
// secret through timing — suppressing it for CRY-017.
func isReflexiveCompare(line string) bool {
	// Fold-aware OR-set pre-gate. reTimingEqOperands requires the operator
	// `[!=]==?`, every match of which is `==`, `===`, `!=`, or `!==` — each
	// containing `==` or `!=` as a substring. A line with neither provably
	// cannot match, so the (backtracking) FindAllStringSubmatch is skipped.
	// (CompilePrefilter yields an always-run gate for this char-class operator,
	// so the required OR-set is asserted by hand; the operators are ASCII so no
	// lowercasing is needed.) Finding-preserving: never skips a line the regex
	// would actually match.
	if !strings.Contains(line, "==") && !strings.Contains(line, "!=") {
		return false
	}
	for _, m := range reTimingEqOperands.FindAllStringSubmatch(line, -1) {
		if m[1] != "" && m[1] == m[2] {
			return true
		}
	}
	return false
}

// BATOU-CRY-018: Hardcoded IV (Java IvParameterSpec and broader patterns)
var (
	reJavaIvParameterSpec = regexp.MustCompile(`new\s+IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\]\s*\{|"[^"]+"\s*\.getBytes)`)
	reJavaIvHexBytes      = regexp.MustCompile(`new\s+IvParameterSpec\s*\(\s*(?:javax\.xml\.bind\.DatatypeConverter|DatatypeConverter|Hex|Base64)`)
	rePyFixedIVAES        = regexp.MustCompile(`AES\.new\s*\([^)]*,\s*[^,)]*,\s*(?:b["'][^"']+["']|bytes\s*\()`)
	reGoFixedNonceSeal    = regexp.MustCompile(`\.\s*(?:Seal|Open)\s*\(\s*nil\s*,\s*(?:\[\]byte\s*\{|make\s*\(\s*\[\]byte)`)
)

// BATOU-CRY-019: Java weak random (broad detection without requiring security context)
var (
	// new Random() or new java.util.Random() — NOT SecureRandom
	reJavaNewRandom = regexp.MustCompile(`\bnew\s+(?:java\.util\.)?Random\s*\(`)
	// Math.random() or java.lang.Math.random()
	reJavaMathRandom = regexp.MustCompile(`\b(?:java\.lang\.)?Math\.random\s*\(`)
	// SecureRandom on the same line (safe — do not flag)
	reSecureRandomLine = regexp.MustCompile(`SecureRandom`)
)

func init() {
	rules.Register(&WeakHashing{})
	rules.Register(&InsecureRandom{})
	rules.Register(&WeakCipher{})
	rules.Register(&HardcodedIV{})
	rules.Register(&InsecureTLS{})
	rules.Register(&WeakKeySize{})
	rules.Register(&PlaintextProtocol{})
	rules.Register(&JSMathRandomSecurity{})
	rules.Register(&PythonRandomSecurity{})
	rules.Register(&WeakPRNG{})
	rules.Register(&PredictableSeed{})
	rules.Register(&HardcodedKey{})
	rules.Register(&UnauthenticatedEncryption{})
	rules.Register(&InsecureRSAPadding{})
	rules.Register(&WeakPasswordHash{})
	rules.Register(&InsecureRandomBroad{})
	rules.Register(&TimingUnsafeCompare{})
	rules.Register(&HardcodedIVBroad{})
	rules.Register(&JavaWeakRandomBroad{})
}

// --- BATOU-CRY-001: WeakHashing ---

type WeakHashing struct{}

func (r *WeakHashing) ID() string                      { return "BATOU-CRY-001" }
func (r *WeakHashing) Name() string                    { return "WeakHashing" }
func (r *WeakHashing) DefaultSeverity() rules.Severity { return rules.High }

func (r *WeakHashing) Description() string {
	return "Detects use of MD5 or SHA-1 for security purposes such as password hashing, digital signatures, or HMACs."
}

func (r *WeakHashing) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *WeakHashing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var algo string

		switch ctx.Language {
		case rules.LangGo:
			if loc := rules.GFindLower(reGoMD5, line, lowered[i]); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := rules.GFindLower(reGoSHA1, line, lowered[i]); loc != "" {
				matched = loc
				algo = "SHA-1"
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyMD5, line, lowered[i]); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := rules.GFindLower(rePySHA1, line, lowered[i]); loc != "" {
				matched = loc
				algo = "SHA-1"
			} else if loc := rules.GFindLower(rePyHashlibNew, line, lowered[i]); loc != "" {
				matched = loc
				if strings.Contains(loc, "md5") {
					algo = "MD5"
				} else {
					algo = "SHA-1"
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := rules.GFindLower(reJSMD5, line, lowered[i]); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := rules.GFindLower(reJSSHA1, line, lowered[i]); loc != "" {
				matched = loc
				algo = "SHA-1"
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaMD5, line, lowered[i]); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := rules.GFindLower(reJavaSHA1, line, lowered[i]); loc != "" {
				matched = loc
				algo = "SHA-1"
			} else if loc := rules.GFindLower(reJavaDigestVar, line, lowered[i]); loc != "" {
				// Indirect: getInstance(variable) — algorithm from config/properties.
				// Suppress if the variable resolves to a strong algorithm.
				if !rules.JavaDigestVarIsSafe(lines, i) {
					matched = loc
					algo = "MD5/SHA-1 (indirect)"
				}
			}
		}

		if matched == "" {
			continue
		}

		// Suppress when surrounding context (±5 lines or file path) clearly
		// identifies a non-security use of the hash: Git commit IDs, avatar
		// fingerprints, Etag/cache keys, HIBP protocol, etc. The algorithm
		// is dictated by protocol or has no security boundary.
		if hasNonSecurityContext(lines, i, ctx.FilePath) {
			continue
		}

		confidence := "medium"
		if rules.GMatchLower(reSecurityCtx, line, lowered[i]) {
			confidence = "high"
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak hash algorithm: " + algo,
			Description:   algo + " is cryptographically broken and must not be used for security purposes. Collision and preimage attacks are practical.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use SHA-256 or SHA-3 for integrity checks. Use bcrypt, scrypt, or Argon2 for password hashing.",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    confidence,
			Tags:          []string{"crypto", "hashing", algo},
		})
	}

	return findings
}

// --- BATOU-CRY-002: InsecureRandom ---

type InsecureRandom struct{}

func (r *InsecureRandom) ID() string                      { return "BATOU-CRY-002" }
func (r *InsecureRandom) Name() string                    { return "InsecureRandom" }
func (r *InsecureRandom) DefaultSeverity() rules.Severity { return rules.High }

func (r *InsecureRandom) Description() string {
	return "Detects use of non-cryptographic random number generators in security-sensitive contexts."
}

func (r *InsecureRandom) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *InsecureRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	// For Go, check if math/rand is imported
	goHasMathRand := false
	if ctx.Language == rules.LangGo {
		goHasMathRand = rules.GMatchFile(reGoMathRand, ctx)
	}

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var suggestion string

		switch ctx.Language {
		case rules.LangGo:
			if goHasMathRand {
				if loc := rules.GFindLower(reGoRandCall, line, lowered[i]); loc != "" {
					if rules.GMatchLower(reSecRandCtx, line, lowered[i]) || reSecRandCtx.MatchString(safeSurroundingLines(lines, i, 3)) {
						matched = loc
						suggestion = "Use crypto/rand for security-sensitive random values."
					}
				}
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyRandom, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reSecRandCtx, line, lowered[i]) || reSecRandCtx.MatchString(safeSurroundingLines(lines, i, 3)) {
					matched = loc
					suggestion = "Use the secrets module (secrets.token_hex, secrets.token_urlsafe) for security-sensitive random values."
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := rules.GFindLower(reJSMathRandom, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reSecRandCtx, line, lowered[i]) || reSecRandCtx.MatchString(safeSurroundingLines(lines, i, 3)) {
					matched = loc
					suggestion = "Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive random values."
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Non-cryptographic random used in security context",
			Description:   "Non-cryptographic PRNGs are predictable and must not be used for tokens, passwords, keys, or other security-sensitive values.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random"},
		})
	}

	return findings
}

// --- BATOU-CRY-003: WeakCipher ---

type WeakCipher struct{}

func (r *WeakCipher) ID() string                      { return "BATOU-CRY-003" }
func (r *WeakCipher) Name() string                    { return "WeakCipher" }
func (r *WeakCipher) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *WeakCipher) Description() string {
	return "Detects use of broken or weak encryption algorithms (DES, 3DES, RC4, Blowfish, RC2) and insecure cipher modes (ECB)."
}

func (r *WeakCipher) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *WeakCipher) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangGo:
			if loc := rules.GFindLower(reGoDES, line, lowered[i]); loc != "" {
				matched = loc
				detail = "DES/3DES"
			} else if loc := rules.GFindLower(reGoRC4, line, lowered[i]); loc != "" {
				matched = loc
				detail = "RC4"
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyDES, line, lowered[i]); loc != "" {
				matched = loc
				detail = "DES/3DES"
			} else if loc := rules.GFindLower(rePyARC4, line, lowered[i]); loc != "" {
				matched = loc
				detail = "RC4"
			} else if loc := rules.GFindLower(rePyBlowfish, line, lowered[i]); loc != "" {
				matched = loc
				detail = "Blowfish"
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaDES, line, lowered[i]); loc != "" {
				matched = loc
				detail = "DES/3DES"
			} else if loc := rules.GFindLower(reJavaRC4, line, lowered[i]); loc != "" {
				matched = loc
				detail = "RC4"
			}
		}

		// ECB mode check applies to all languages
		if matched == "" {
			if loc := rules.GFindLower(reECBMode, line, lowered[i]); loc != "" {
				// Java: suppress ECB in getProperty defaults where cipher is AES (strong).
				// FP pattern: getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding")
				// TP pattern: getProperty("cryptoAlg1", "DESede/ECB/PKCS5Padding")
				if ctx.Language == rules.LangJava {
					if m := rules.JavaGetPropertyDefault(line); m != "" {
						upper := strings.ToUpper(m)
						if strings.HasPrefix(upper, "AES") {
							continue // AES is strong; ECB mode in default is acceptable
						}
					}
				}
				matched = loc
				detail = "ECB mode"
			}
		}

		// Generic weak cipher reference (if not already caught by a language-specific pattern).
		// This fallback matches a bare `des`/`rc4` token, so it requires a crypto-API
		// context on the line and never fires inside dependency lockfiles — otherwise the
		// French article "des" in l10n bundles and `browserify-des`-style lockfile entries
		// produce false positives (10 FPs in owncloud/web).
		if matched == "" && !reWeakCipherSkipPath.MatchString(ctx.FilePath) {
			if loc := rules.GFindLower(reWeakCipher, line, lowered[i]); loc != "" && rules.GMatchLower(reWeakCipherCryptoCtx, line, lowered[i]) {
				// Avoid matching in comments that merely mention the algorithm name
				trimmed := strings.TrimSpace(line)
				if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "*") {
					matched = loc
					detail = loc
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak cipher or mode: " + detail,
			Description:   detail + " is cryptographically weak and must not be used. These algorithms have known practical attacks.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption.",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "cipher", detail},
		})
	}

	return findings
}

// --- BATOU-CRY-004: HardcodedIV ---

type HardcodedIV struct{}

func (r *HardcodedIV) ID() string                      { return "BATOU-CRY-004" }
func (r *HardcodedIV) Name() string                    { return "HardcodedIV" }
func (r *HardcodedIV) DefaultSeverity() rules.Severity { return rules.High }

func (r *HardcodedIV) Description() string {
	return "Detects hardcoded initialization vectors (IVs) and nonces, which undermine encryption security."
}

func (r *HardcodedIV) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *HardcodedIV) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	patterns := []*regexp.Regexp{reGoByteIV, reStringIV, reFixedIVBytes, reByteArrayIV}

	for i, line := range lines {
		lineNum := i + 1

		for _, pat := range patterns {
			if loc := rules.GFindLower(pat, line, lowered[i]); loc != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Hardcoded initialization vector or nonce",
					Description:   "Using a fixed IV or nonce makes encryption deterministic, enabling pattern analysis and defeating semantic security.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Generate IVs and nonces randomly for each encryption operation using a CSPRNG.",
					CWEID:         "CWE-329",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"crypto", "iv", "nonce"},
				})
				break // one finding per line
			}
		}
	}

	return findings
}

// --- BATOU-CRY-005: InsecureTLS ---

type InsecureTLS struct{}

func (r *InsecureTLS) ID() string                      { return "BATOU-CRY-005" }
func (r *InsecureTLS) Name() string                    { return "InsecureTLS" }
func (r *InsecureTLS) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *InsecureTLS) Description() string {
	return "Detects disabled TLS certificate verification and use of deprecated TLS versions (1.0, 1.1)."
}

func (r *InsecureTLS) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangAny}
}

func (r *InsecureTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var title string
		var desc string
		var suggestion string
		cweID := "CWE-295"

		switch ctx.Language {
		case rules.LangGo:
			if loc := rules.GFindLower(reGoInsecureSkip, line, lowered[i]); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "InsecureSkipVerify: true disables certificate validation, enabling man-in-the-middle attacks."
				suggestion = "Remove InsecureSkipVerify or set it to false. Use a custom VerifyPeerCertificate if you need custom validation."
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyVerifyFalse, line, lowered[i]); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "verify=False disables certificate validation for HTTPS requests."
				suggestion = "Use verify=True (the default) or provide a CA bundle path."
			} else if loc := rules.GFindLower(rePySSlNoVerify, line, lowered[i]); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "Disabling SSL certificate verification enables man-in-the-middle attacks."
				suggestion = "Use ssl.create_default_context() instead."
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := rules.GFindLower(reNodeRejectUnauth, line, lowered[i]); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "rejectUnauthorized: false disables certificate validation for TLS connections."
				suggestion = "Remove rejectUnauthorized: false to enable certificate verification."
			} else if loc := rules.GFindLower(reNodeTLSEnv, line, lowered[i]); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled via environment"
				desc = "NODE_TLS_REJECT_UNAUTHORIZED=0 globally disables TLS verification for the Node.js process."
				suggestion = "Remove this environment variable. Fix the underlying certificate issue instead."
			}
		}

		// TLS version check applies to all languages
		if matched == "" {
			if loc := rules.GFindLower(reTLS10, line, lowered[i]); loc != "" {
				matched = loc
				title = "Deprecated TLS version"
				desc = "TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE) and are deprecated by RFC 8996."
				suggestion = "Set minimum TLS version to 1.2 or preferably 1.3."
				cweID = "CWE-327"
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         cweID,
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "tls"},
		})
	}

	return findings
}

// --- BATOU-CRY-006: WeakKeySize ---

type WeakKeySize struct{}

func (r *WeakKeySize) ID() string                      { return "BATOU-CRY-006" }
func (r *WeakKeySize) Name() string                    { return "WeakKeySize" }
func (r *WeakKeySize) DefaultSeverity() rules.Severity { return rules.High }

func (r *WeakKeySize) Description() string {
	return "Detects RSA keys smaller than 2048 bits, weak elliptic curves, and insufficient symmetric key sizes."
}

func (r *WeakKeySize) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *WeakKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var title string
		var desc string

		switch ctx.Language {
		case rules.LangGo:
			if loc := rules.GFindLower(reGoRSAKeySize, line, lowered[i]); loc != "" {
				matched = loc
				title = "RSA key size too small"
				desc = "RSA keys smaller than 2048 bits can be factored with current computing resources."
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaRSAKeySize, line, lowered[i]); loc != "" {
				matched = loc
				title = "RSA key size too small"
				desc = "RSA keys smaller than 2048 bits can be factored with current computing resources."
			}
		}

		// Generic key size check for all languages
		if matched == "" {
			if loc := rules.GFindLower(reRSASmallKey, line, lowered[i]); loc != "" {
				matched = loc
				title = "Potentially weak key size"
				desc = "Key sizes of 1024 bits or less are considered insufficient for modern security requirements."
			}
		}

		// Weak EC curve check for all languages
		if matched == "" {
			if loc := rules.GFindLower(reWeakCurve, line, lowered[i]); loc != "" {
				matched = loc
				title = "Weak elliptic curve"
				desc = "P-192 and equivalent curves provide less than 128 bits of security and should not be used."
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use RSA-2048 or larger, P-256 or stronger curves, and AES-256 for symmetric encryption.",
			CWEID:         "CWE-326",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "keysize"},
		})
	}

	return findings
}

// --- BATOU-CRY-007: PlaintextProtocol ---

type PlaintextProtocol struct{}

func (r *PlaintextProtocol) ID() string                      { return "BATOU-CRY-007" }
func (r *PlaintextProtocol) Name() string                    { return "PlaintextProtocol" }
func (r *PlaintextProtocol) DefaultSeverity() rules.Severity { return rules.Medium }

func (r *PlaintextProtocol) Description() string {
	return "Detects HTTP (non-HTTPS) URLs used for sensitive operations such as API calls, authentication, or webhooks."
}

func (r *PlaintextProtocol) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PlaintextProtocol) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip test/spec/fixture files — `'http://...'` literals there are
	// DOM-attribute fixtures, mock URLs, or example values, not real
	// network calls. (Mirrors the secrets-rule treatment.)
	if reCryptoTestFile.MatchString(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1

		loc := rules.GFindLower(reHTTPURL, line, lowered[i])
		if loc == "" {
			continue
		}

		// Skip localhost/loopback addresses
		if rules.GMatchLower(reHTTPLocalhost, line, lowered[i]) {
			continue
		}

		// Skip example/test domains
		if rules.GMatchLower(reHTTPExample, line, lowered[i]) {
			continue
		}

		// Skip lines that look like test fixtures or comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		confidence := "medium"
		title := "HTTP URL used instead of HTTPS"
		if rules.GMatchLower(reHTTPSensitive, line, lowered[i]) {
			confidence = "high"
			title = "HTTP URL used for sensitive endpoint"
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   "Using plaintext HTTP exposes data in transit to eavesdropping and tampering. All sensitive communications should use HTTPS.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Replace http:// with https:// to encrypt data in transit.",
			CWEID:         "CWE-319",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    confidence,
			Tags:          []string{"crypto", "transport"},
		})
	}

	return findings
}

// --- BATOU-CRY-008: JSMathRandomSecurity ---

type JSMathRandomSecurity struct{}

func (r *JSMathRandomSecurity) ID() string                      { return "BATOU-CRY-008" }
func (r *JSMathRandomSecurity) Name() string                    { return "JSMathRandomSecurity" }
func (r *JSMathRandomSecurity) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *JSMathRandomSecurity) Description() string {
	return "Detects Math.random() usage in security-sensitive contexts such as token generation, session IDs, passwords, nonces, OTPs, and CSRF tokens."
}

func (r *JSMathRandomSecurity) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JSMathRandomSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1

		if loc := rules.GFindLower(reJSMathRandomBroad, line, lowered[i]); loc != "" {
			// Check current line and surrounding context for security-sensitive terms
			if rules.GMatchLower(reJSSecurityCtx, line, lowered[i]) || reJSSecurityCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Math.random() used in security-sensitive context",
					Description:   "Math.random() is not cryptographically secure. Its output is predictable and must not be used for tokens, session IDs, passwords, nonces, OTPs, CSRF tokens, or any security-sensitive values.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for cryptographically secure random values.",
					CWEID:         "CWE-330",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"crypto", "random", "javascript"},
				})
			}
		}
	}

	return findings
}

// --- BATOU-CRY-009: PythonRandomSecurity ---

type PythonRandomSecurity struct{}

func (r *PythonRandomSecurity) ID() string                      { return "BATOU-CRY-009" }
func (r *PythonRandomSecurity) Name() string                    { return "PythonRandomSecurity" }
func (r *PythonRandomSecurity) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *PythonRandomSecurity) Description() string {
	return "Detects Python random module usage in security-sensitive contexts. The random module uses a Mersenne Twister PRNG which is not suitable for security purposes."
}

func (r *PythonRandomSecurity) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *PythonRandomSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1

		if loc := rules.GFindLower(rePyRandomBroad, line, lowered[i]); loc != "" {
			if rules.GMatchLower(rePySecurityCtx, line, lowered[i]) || rePySecurityCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Python random module used in security-sensitive context",
					Description:   "The random module uses a Mersenne Twister PRNG which is entirely predictable. Its state can be recovered from 624 consecutive outputs. It must not be used for security purposes.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Use the secrets module (secrets.token_hex(), secrets.token_urlsafe(), secrets.choice()) for security-sensitive random values.",
					CWEID:         "CWE-330",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"crypto", "random", "python"},
				})
			}
		}
	}

	return findings
}

// --- BATOU-CRY-010: WeakPRNG ---

type WeakPRNG struct{}

func (r *WeakPRNG) ID() string                      { return "BATOU-CRY-010" }
func (r *WeakPRNG) Name() string                    { return "WeakPRNG" }
func (r *WeakPRNG) DefaultSeverity() rules.Severity { return rules.High }

func (r *WeakPRNG) Description() string {
	return "Detects use of non-cryptographic PRNGs across languages: Java java.util.Random, PHP rand()/mt_rand(), Ruby rand(), C# System.Random, and Go math/rand in security contexts."
}

func (r *WeakPRNG) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp, rules.LangGo}
}

func (r *WeakPRNG) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	// For Go, check if math/rand is imported
	goHasMathRand := false
	if ctx.Language == rules.LangGo {
		goHasMathRand = rules.GMatchFile(reGoMathRandImport, ctx)
	}

	// For Java, check if java.util.Random is imported
	javaHasUtilRandom := false
	if ctx.Language == rules.LangJava {
		javaHasUtilRandom = rules.GMatchFile(reJavaRandomImport, ctx)
	}

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var suggestion string
		var detail string

		switch ctx.Language {
		case rules.LangJava:
			if javaHasUtilRandom || rules.GMatchLower(reJavaUtilRandom, line, lowered[i]) {
				if loc := rules.GFindLower(reJavaUtilRandom, line, lowered[i]); loc != "" {
					if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
						matched = loc
						detail = "java.util.Random"
						suggestion = "Use java.security.SecureRandom for security-sensitive random values."
					}
				}
			}
		case rules.LangPHP:
			if loc := rules.GFindLower(rePHPRand, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "PHP rand()/mt_rand()"
					suggestion = "Use random_bytes() or random_int() for security-sensitive random values."
				}
			} else if loc := rules.GFindLower(rePHPArray, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "PHP array_rand()"
					suggestion = "Use random_int() for index selection or random_bytes() for security-sensitive random values."
				}
			}
		case rules.LangRuby:
			if loc := rules.GFindLower(reRubyRand, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "Ruby rand()"
					suggestion = "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.random_bytes for security-sensitive random values."
				}
			} else if loc := rules.GFindLower(reRubyRandObj, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "Ruby Random"
					suggestion = "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.random_bytes for security-sensitive random values."
				}
			}
		case rules.LangCSharp:
			if loc := rules.GFindLower(reCSharpRandom, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "System.Random"
					suggestion = "Use System.Security.Cryptography.RNGCryptoServiceProvider or RandomNumberGenerator.Create() for security-sensitive random values."
				}
			}
		case rules.LangGo:
			if goHasMathRand {
				if loc := rules.GFindLower(reGoRandCall, line, lowered[i]); loc != "" {
					if rules.GMatchLower(reWeakPRNGSecCtx, line, lowered[i]) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
						matched = loc
						detail = "math/rand"
						suggestion = "Use crypto/rand for security-sensitive random values."
					}
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak PRNG in security context: " + detail,
			Description:   detail + " is not cryptographically secure. Its output is predictable and must not be used for security-sensitive operations.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random", "prng"},
		})
	}

	return findings
}

// --- BATOU-CRY-011: PredictableSeed ---

type PredictableSeed struct{}

func (r *PredictableSeed) ID() string                      { return "BATOU-CRY-011" }
func (r *PredictableSeed) Name() string                    { return "PredictableSeed" }
func (r *PredictableSeed) DefaultSeverity() rules.Severity { return rules.High }

func (r *PredictableSeed) Description() string {
	return "Detects predictable or fixed seeds for random number generators. Time-based seeds and constant seeds make PRNG output reproducible."
}

func (r *PredictableSeed) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJava, rules.LangGo, rules.LangPHP, rules.LangRuby, rules.LangC, rules.LangCPP, rules.LangAny}
}

func (r *PredictableSeed) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var title string
		var desc string
		var suggestion string

		switch ctx.Language {
		case rules.LangPython:
			if loc := rules.GFindLower(rePySeedTime, line, lowered[i]); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding random with time makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use the secrets module instead of seeding random. If random is needed for non-security purposes, omit the seed to use OS entropy."
			} else if loc := rules.GFindLower(rePySeedFixed, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes random output completely deterministic and reproducible."
				suggestion = "Remove the fixed seed. Use the secrets module for security-sensitive values."
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaSeedTime, line, lowered[i]); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding Random with system time makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use java.security.SecureRandom which seeds itself from OS entropy."
			} else if loc := rules.GFindLower(reJavaSeedFixed, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes Random output completely deterministic and reproducible."
				suggestion = "Use java.security.SecureRandom for security-sensitive values. Remove fixed seeds."
			} else if loc := rules.GFindLower(reJavaFixedSeed, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed random seed in constructor"
				desc = "Constructing Random with a constant seed makes output completely deterministic and reproducible."
				suggestion = "Use java.security.SecureRandom for security-sensitive values."
			}
		case rules.LangGo:
			if loc := rules.GFindLower(reGoSeedTime, line, lowered[i]); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding math/rand with time.Now() makes output predictable. In Go 1.20+ math/rand auto-seeds, but still is not cryptographically secure."
				suggestion = "Use crypto/rand for security-sensitive values."
			} else if loc := rules.GFindLower(reGoSeedFixed, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes math/rand output completely deterministic and reproducible."
				suggestion = "Use crypto/rand for security-sensitive values. Remove fixed seeds."
			} else if loc := rules.GFindLower(reGoNewSource, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed seed in rand.NewSource"
				desc = "Creating a rand source with a constant seed makes output completely deterministic and reproducible."
				suggestion = "Use crypto/rand for security-sensitive values."
			}
		case rules.LangPHP:
			if loc := rules.GFindLower(rePHPSrandTime, line, lowered[i]); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding with time() makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use random_bytes() or random_int() for security-sensitive values. PHP 7+ auto-seeds, so explicit seeding is rarely needed."
			} else if loc := rules.GFindLower(rePHPSrandFixed, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes rand()/mt_rand() output completely deterministic and reproducible."
				suggestion = "Use random_bytes() or random_int() for security-sensitive values. Remove fixed seeds."
			}
		case rules.LangRuby:
			if loc := rules.GFindLower(reRubySrandFixed, line, lowered[i]); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes rand() output completely deterministic and reproducible."
				suggestion = "Use SecureRandom for security-sensitive values. Remove fixed seeds."
			}
		case rules.LangC, rules.LangCPP:
			if loc := rules.GFindLower(reCSeedTime, line, lowered[i]); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "srand(time(NULL)) makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use platform-specific CSPRNGs (e.g., getrandom(), /dev/urandom, BCryptGenRandom) for security-sensitive values."
			}
		}

		// Generic fallback: check for srand(time( in any language
		if matched == "" {
			if loc := rules.GFindLower(reCSeedTime, line, lowered[i]); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "srand(time()) makes random output predictable to anyone who can estimate when the code runs."
				suggestion = "Use a cryptographically secure random number generator for security-sensitive values."
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random", "seed"},
		})
	}

	return findings
}

// --- BATOU-CRY-012: HardcodedKey ---

type HardcodedKey struct{}

func (r *HardcodedKey) ID() string                      { return "BATOU-CRY-012" }
func (r *HardcodedKey) Name() string                    { return "HardcodedKey" }
func (r *HardcodedKey) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *HardcodedKey) Description() string {
	return "Detects hardcoded cryptographic keys (AES keys, encryption secrets, signing keys) embedded directly in source code."
}

func (r *HardcodedKey) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *HardcodedKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		var matched bool

		switch ctx.Language {
		case rules.LangGo:
			// key/secret := []byte("literal")
			if rules.GMatchLower(reGoByteStringKey, line, lowered[i]) {
				matched = true
			}
		case rules.LangPython:
			if rules.GMatchLower(rePyHardcodedKey, line, lowered[i]) {
				matched = true
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if rules.GMatchLower(reJSBufferFromKey, line, lowered[i]) && reCryptoKeyCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
				matched = true
			} else if rules.GMatchLower(reJSHardcodedKey, line, lowered[i]) && !isVueOrHTMLKeyAttr(line) {
				// `.vue` SFCs are scanned as JS — skip `:key=`/`key=` template
				// attributes (list-render keys, DOM attrs), keep firing on
				// real `key = "sk_live_..."` / `secret = "..."` assignments.
				matched = true
			}
		case rules.LangJava:
			if rules.GMatchLower(reJavaSecretKeySpec, line, lowered[i]) || rules.GMatchLower(reJavaGetBytesKey, line, lowered[i]) {
				if rules.GMatchLower(reCryptoKeyCtx, line, lowered[i]) || reCryptoKeyCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = true
				}
			}
		}

		// Generic check for all languages: explicitly named crypto key variables
		if !matched {
			if rules.GMatchLower(reGenericHardcodedKey, line, lowered[i]) {
				matched = true
			}
		}

		if !matched {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Hardcoded cryptographic key",
			Description:   "Cryptographic keys embedded in source code can be extracted by anyone with access to the code or binary. Keys should be loaded from secure key management systems, environment variables, or encrypted configuration.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Load keys from environment variables, a secrets manager (Vault, AWS KMS, GCP KMS), or encrypted config files. Never commit keys to source control.",
			CWEID:         "CWE-321",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "hardcoded-key"},
		})
	}

	return findings
}

// --- BATOU-CRY-013: UnauthenticatedEncryption ---

type UnauthenticatedEncryption struct{}

func (r *UnauthenticatedEncryption) ID() string                      { return "BATOU-CRY-013" }
func (r *UnauthenticatedEncryption) Name() string                    { return "UnauthenticatedEncryption" }
func (r *UnauthenticatedEncryption) DefaultSeverity() rules.Severity { return rules.High }

func (r *UnauthenticatedEncryption) Description() string {
	return "Detects use of CBC mode encryption without authentication (HMAC/MAC), which is vulnerable to padding oracle attacks."
}

func (r *UnauthenticatedEncryption) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *UnauthenticatedEncryption) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	// Check if any authentication is present in the entire file
	hasAuth := rules.GMatchFile(reAuthCheck, ctx)

	for i, line := range lines {
		lineNum := i + 1
		var matched string

		switch ctx.Language {
		case rules.LangGo:
			if loc := rules.GFindLower(reGoCBCEncrypt, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyCBCMode, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaCBC, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := rules.GFindLower(reJSCBCCipher, line, lowered[i]); loc != "" {
				matched = loc
			}
		}

		if matched == "" {
			continue
		}

		// Suppress if authentication is present anywhere in the file
		if hasAuth {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "CBC mode without authentication (padding oracle risk)",
			Description:   "CBC mode without a MAC/HMAC is vulnerable to padding oracle attacks (e.g., POODLE, Lucky13). An attacker can decrypt ciphertext by observing padding error responses.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use AES-GCM or ChaCha20-Poly1305 for authenticated encryption. If CBC is required, always apply HMAC-SHA256 to the ciphertext (encrypt-then-MAC).",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "cbc", "padding-oracle"},
		})
	}

	return findings
}

// --- BATOU-CRY-014: InsecureRSAPadding ---

type InsecureRSAPadding struct{}

func (r *InsecureRSAPadding) ID() string                      { return "BATOU-CRY-014" }
func (r *InsecureRSAPadding) Name() string                    { return "InsecureRSAPadding" }
func (r *InsecureRSAPadding) DefaultSeverity() rules.Severity { return rules.High }

func (r *InsecureRSAPadding) Description() string {
	return "Detects use of PKCS#1 v1.5 padding for RSA encryption, which is vulnerable to Bleichenbacher's attack and padding oracle attacks."
}

func (r *InsecureRSAPadding) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *InsecureRSAPadding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangGo:
			if loc := rules.GFindLower(reGoRSAPKCS1Encrypt, line, lowered[i]); loc != "" {
				matched = loc
				detail = "rsa.EncryptPKCS1v15"
			} else if loc := rules.GFindLower(reGoRSAPKCS1Decrypt, line, lowered[i]); loc != "" {
				matched = loc
				detail = "rsa.DecryptPKCS1v15"
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaRSAPKCS1, line, lowered[i]); loc != "" {
				matched = loc
				detail = "RSA/PKCS1Padding"
			} else if loc := rules.GFindLower(reJavaRSANoPadding, line, lowered[i]); loc != "" {
				matched = loc
				detail = "RSA with no explicit mode (defaults to insecure padding)"
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyPKCS1v15Encrypt, line, lowered[i]); loc != "" {
				matched = loc
				detail = "PKCS1_v1_5"
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := rules.GFindLower(reJSRSAPKCS1Padding, line, lowered[i]); loc != "" {
				matched = loc
				detail = "RSA_PKCS1_PADDING"
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Insecure RSA padding: " + detail,
			Description:   "PKCS#1 v1.5 padding for RSA encryption is vulnerable to Bleichenbacher's chosen-ciphertext attack. An attacker can decrypt messages or forge signatures by making adaptive queries.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use RSA-OAEP (Optimal Asymmetric Encryption Padding) for encryption. For signatures, use PSS padding instead of PKCS1v15.",
			CWEID:         "CWE-780",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "rsa", "padding"},
		})
	}

	return findings
}

// --- BATOU-CRY-015: WeakPasswordHash ---

type WeakPasswordHash struct{}

func (r *WeakPasswordHash) ID() string                      { return "BATOU-CRY-015" }
func (r *WeakPasswordHash) Name() string                    { return "WeakPasswordHash" }
func (r *WeakPasswordHash) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *WeakPasswordHash) Description() string {
	return "Detects use of fast hash functions (MD5, SHA-1, SHA-256) for password storage instead of purpose-built password hashing algorithms (bcrypt, scrypt, Argon2)."
}

func (r *WeakPasswordHash) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP}
}

func (r *WeakPasswordHash) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// If proper password hashing is used in the file, suppress
	if rules.GMatchFile(reProperPasswordHash, ctx) {
		return nil
	}

	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string

		// Only flag if password context exists on the line or nearby
		hasPasswordCtx := rules.GMatchLower(rePasswordCtx, line, lowered[i]) || rePasswordCtx.MatchString(safeSurroundingLines(lines, i, 3))
		if !hasPasswordCtx {
			continue
		}

		switch ctx.Language {
		case rules.LangPython:
			if loc := rules.GFindLower(rePyHashPassword, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangGo:
			if loc := rules.GFindLower(reGoHashPassword, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaDigestPassword, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := rules.GFindLower(reJSHashPassword, line, lowered[i]); loc != "" {
				matched = loc
			}
		case rules.LangPHP:
			if loc := rules.GFindLower(rePHPHashPassword, line, lowered[i]); loc != "" {
				matched = loc
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Fast hash used for password storage",
			Description:   "Fast hash functions (MD5, SHA-1, SHA-256) can be brute-forced at billions of attempts per second using GPUs. Password storage requires slow, salted, memory-hard algorithms.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use bcrypt, scrypt, or Argon2id for password hashing. These algorithms are intentionally slow and resistant to GPU/ASIC attacks.",
			CWEID:         "CWE-916",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "password", "hashing"},
		})
	}

	return findings
}

// --- BATOU-CRY-016: InsecureRandomBroad ---

type InsecureRandomBroad struct{}

func (r *InsecureRandomBroad) ID() string                      { return "BATOU-CRY-016" }
func (r *InsecureRandomBroad) Name() string                    { return "InsecureRandomBroad" }
func (r *InsecureRandomBroad) DefaultSeverity() rules.Severity { return rules.High }

func (r *InsecureRandomBroad) Description() string {
	return "Detects insecure random number generators used in security contexts across Ruby and PHP (complementing CRY-008/009/010 for other languages)."
}

func (r *InsecureRandomBroad) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby, rules.LangPHP}
}

func (r *InsecureRandomBroad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var suggestion string
		var detail string

		switch ctx.Language {
		case rules.LangRuby:
			if loc := rules.GFindLower(reRubyRandSec, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reCRY016SecCtx, line, lowered[i]) || reCRY016SecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "Ruby rand()"
					suggestion = "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.random_bytes for security-sensitive random values."
				}
			} else if loc := rules.GFindLower(reRubyRandObjSec, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reCRY016SecCtx, line, lowered[i]) || reCRY016SecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "Ruby Random"
					suggestion = "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.random_bytes for security-sensitive random values."
				}
			}
		case rules.LangPHP:
			if loc := rules.GFindLower(rePHPRandSec, line, lowered[i]); loc != "" {
				if rules.GMatchLower(reCRY016SecCtx, line, lowered[i]) || reCRY016SecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "PHP rand()/mt_rand()"
					suggestion = "Use random_bytes() or random_int() for security-sensitive random values."
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Insecure random in security context: " + detail,
			Description:   detail + " is not cryptographically secure. Its output is predictable and must not be used for tokens, session IDs, passwords, nonces, OTPs, CSRF tokens, or any security-sensitive values.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random"},
		})
	}

	return findings
}

// --- BATOU-CRY-017: TimingUnsafeCompare ---

type TimingUnsafeCompare struct{}

func (r *TimingUnsafeCompare) ID() string                      { return "BATOU-CRY-017" }
func (r *TimingUnsafeCompare) Name() string                    { return "TimingUnsafeCompare" }
func (r *TimingUnsafeCompare) DefaultSeverity() rules.Severity { return rules.Medium }

func (r *TimingUnsafeCompare) Description() string {
	return "Detects use of == or === to compare secrets, tokens, hashes, or signatures instead of constant-time comparison functions."
}

func (r *TimingUnsafeCompare) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangRuby}
}

func (r *TimingUnsafeCompare) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Skip lines that already use safe comparison
		if rules.GMatchLower(reTimingSafeCompare, line, lowered[i]) {
			continue
		}

		// Skip nil / zero / empty / literal existence checks — these
		// are not secret-value comparisons even if the variable name
		// contains a security keyword.
		if rules.GMatchLower(reTimingNilOrZero, line, lowered[i]) {
			continue
		}

		// Skip length/size comparisons — they leak length, not content, and
		// a constant-time rewrite is not the fix.
		if rules.GMatchLower(reTimingLengthCompare, line, lowered[i]) {
			continue
		}

		// Skip reflexive comparisons (`token === token`) — both sides are the
		// same in-memory value, so there is no timing leak. (Seen in
		// client-side stores in owncloud/web.)
		if isReflexiveCompare(line) {
			continue
		}

		var matched bool
		var suggestion string

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if rules.GMatchLower(reTimingCompareJS, line, lowered[i]) || rules.GMatchLower(reTimingCompareRev, line, lowered[i]) {
				matched = true
				suggestion = "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) for constant-time comparison."
			}
		case rules.LangPython:
			if rules.GMatchLower(reTimingComparePy, line, lowered[i]) {
				matched = true
				suggestion = "Use hmac.compare_digest(a, b) for constant-time comparison."
			}
		case rules.LangGo:
			if rules.GMatchLower(reTimingCompareGo, line, lowered[i]) {
				matched = true
				suggestion = "Use subtle.ConstantTimeCompare([]byte(a), []byte(b)) from crypto/subtle for constant-time comparison."
			}
		case rules.LangRuby:
			if rules.GMatchLower(reTimingCompareRuby, line, lowered[i]) {
				matched = true
				suggestion = "Use Rack::Utils.secure_compare(a, b) or ActiveSupport::SecurityUtils.secure_compare(a, b) for constant-time comparison."
			}
		}

		if !matched {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Timing-unsafe comparison of secret value",
			Description:   "Using == or === to compare secrets, tokens, hashes, or signatures leaks information through timing side-channels. An attacker can determine how many leading bytes match by measuring response time.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   trimmed,
			Suggestion:    suggestion,
			CWEID:         "CWE-208",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"crypto", "timing", "comparison"},
		})
	}

	return findings
}

// --- BATOU-CRY-018: HardcodedIVBroad ---

type HardcodedIVBroad struct{}

func (r *HardcodedIVBroad) ID() string                      { return "BATOU-CRY-018" }
func (r *HardcodedIVBroad) Name() string                    { return "HardcodedIVBroad" }
func (r *HardcodedIVBroad) DefaultSeverity() rules.Severity { return rules.High }

func (r *HardcodedIVBroad) Description() string {
	return "Detects hardcoded initialization vectors via Java IvParameterSpec, Python AES with fixed IV bytes, and Go fixed nonce patterns."
}

func (r *HardcodedIVBroad) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangPython, rules.LangGo}
}

func (r *HardcodedIVBroad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangJava:
			if loc := rules.GFindLower(reJavaIvParameterSpec, line, lowered[i]); loc != "" {
				matched = loc
				detail = "IvParameterSpec with hardcoded bytes"
			} else if loc := rules.GFindLower(reJavaIvHexBytes, line, lowered[i]); loc != "" {
				matched = loc
				detail = "IvParameterSpec with hardcoded hex/base64"
			}
		case rules.LangPython:
			if loc := rules.GFindLower(rePyFixedIVAES, line, lowered[i]); loc != "" {
				matched = loc
				detail = "AES with hardcoded IV bytes"
			}
		case rules.LangGo:
			if loc := rules.GFindLower(reGoFixedNonceSeal, line, lowered[i]); loc != "" {
				matched = loc
				detail = "AEAD Seal/Open with fixed nonce"
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Hardcoded IV/nonce: " + detail,
			Description:   "Using a fixed IV or nonce makes encryption deterministic, enabling pattern analysis and defeating semantic security. For AES-GCM, nonce reuse is catastrophic (key recovery).",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Generate IVs and nonces randomly for each encryption operation using a CSPRNG. For AES-GCM, use 12-byte random nonces.",
			CWEID:         "CWE-329",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "iv", "nonce"},
		})
	}

	return findings
}

// --- BATOU-CRY-019: JavaWeakRandomBroad ---

type JavaWeakRandomBroad struct{}

func (r *JavaWeakRandomBroad) ID() string                      { return "BATOU-CRY-019" }
func (r *JavaWeakRandomBroad) Name() string                    { return "JavaWeakRandomBroad" }
func (r *JavaWeakRandomBroad) DefaultSeverity() rules.Severity { return rules.High }

func (r *JavaWeakRandomBroad) Description() string {
	return "Detects java.util.Random and Math.random() usage in Java code. These are not cryptographically secure."
}

func (r *JavaWeakRandomBroad) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaWeakRandomBroad) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Skip lines that use SecureRandom
		if rules.GMatchLower(reSecureRandomLine, line, lowered[i]) {
			continue
		}

		// Skip import statements
		if strings.HasPrefix(trimmed, "import ") {
			continue
		}

		var matched string
		var detail string

		if loc := rules.GFindLower(reJavaNewRandom, line, lowered[i]); loc != "" {
			matched = loc
			detail = "java.util.Random is not cryptographically secure"
		} else if loc := rules.GFindLower(reJavaMathRandom, line, lowered[i]); loc != "" {
			matched = loc
			detail = "Math.random() is not cryptographically secure"
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak random: " + detail,
			Description:   "java.util.Random and Math.random() use predictable pseudo-random number generators. Their output can be reverse-engineered from observed values.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   strings.TrimSpace(matched),
			Suggestion:    "Use java.security.SecureRandom for all random number generation in security-sensitive contexts.",
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"crypto", "random", "java"},
		})
	}

	return findings
}

// --- Helpers ---

// hasNonSecurityContext reports true when CRY-001 should be suppressed
// because the use is clearly an identifier / cache key / protocol primitive
// rather than a security boundary. Checks ±5 lines around the matched line
// and the file path.
func hasNonSecurityContext(lines []string, idx int, filePath string) bool {
	if reNonSecurityCtx.MatchString(filePath) {
		return true
	}
	window := safeSurroundingLines(lines, idx, 5)
	return reNonSecurityCtx.MatchString(window)
}

// safeSurroundingLines returns a window of lines around the given index for context analysis.
func safeSurroundingLines(lines []string, idx, window int) string {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}
