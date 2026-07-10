package cast

import "testing"

// NOTE: the OpenSSL SSL_VERIFY_NONE shape (a once-planned BATOU-CAST-010) was
// evaluated against curl/openssl.c and redis/tls.c and deliberately NOT shipped
// — both legitimately set SSL_VERIFY_NONE with a compensating control, so a
// single-file check false-positives on them. See the rationale block in
// cast_tls.go. The FP-free sibling (always-accept callback) is CAST-009.

// --- BATOU-CAST-011: libcurl CURLOPT_SSL_VERIFY* = 0 (CWE-295) -------------

func TestCurlVerifyPeerOff_TP(t *testing.T) {
	code := `
void fetch(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
}`
	if !hasRule(scanC(code), "BATOU-CAST-011") {
		t.Error("expected BATOU-CAST-011 for CURLOPT_SSL_VERIFYPEER, 0L")
	}
}

func TestCurlVerifyHostOff_TP(t *testing.T) {
	code := `
void fetch(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0);
}`
	if !hasRule(scanC(code), "BATOU-CAST-011") {
		t.Error("expected BATOU-CAST-011 for CURLOPT_SSL_VERIFYHOST, 0")
	}
}

func TestCurlVerifyPeerOn_Safe(t *testing.T) {
	code := `
void fetch(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
}`
	if hasRule(scanC(code), "BATOU-CAST-011") {
		t.Error("BATOU-CAST-011 false positive on enabled verification")
	}
}

func TestCurlVerifyPeerVar_Safe(t *testing.T) {
	// A runtime-computed value must not fire — only literal 0/false.
	code := `
void fetch(CURL *h, long want) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, want);
}`
	if hasRule(scanC(code), "BATOU-CAST-011") {
		t.Error("BATOU-CAST-011 false positive on variable verify value")
	}
}

func TestCurlOtherOpt_Safe(t *testing.T) {
	// A different option set to 0 must not fire.
	code := `
void fetch(CURL *h) {
    curl_easy_setopt(h, CURLOPT_VERBOSE, 0);
}`
	if hasRule(scanC(code), "BATOU-CAST-011") {
		t.Error("BATOU-CAST-011 false positive on unrelated CURLOPT_VERBOSE")
	}
}

// --- BATOU-CAST-012: GnuTLS verify-flags disable (CWE-295) -----------------

func TestGnuTLSVerifyDisable_TP(t *testing.T) {
	code := `
void setup(gnutls_certificate_credentials_t cred) {
    gnutls_certificate_set_verify_flags(cred, GNUTLS_VERIFY_DISABLE_CA_SIGN);
}`
	if !hasRule(scanC(code), "BATOU-CAST-012") {
		t.Error("expected BATOU-CAST-012 for GNUTLS_VERIFY_DISABLE_CA_SIGN")
	}
}

func TestGnuTLSVerifyDefault_Safe(t *testing.T) {
	code := `
void setup(gnutls_certificate_credentials_t cred) {
    gnutls_certificate_set_verify_flags(cred, 0);
}`
	if hasRule(scanC(code), "BATOU-CAST-012") {
		t.Error("BATOU-CAST-012 false positive on default (0) verify flags")
	}
}

// --- BATOU-CAST-013: strtok (CWE-477) --------------------------------------

func TestStrtok_TP(t *testing.T) {
	code := `
void parse(char *line) {
    char *tok = strtok(line, ",");
    while (tok) { tok = strtok(NULL, ","); }
}`
	if !hasRule(scanC(code), "BATOU-CAST-013") {
		t.Error("expected BATOU-CAST-013 for strtok()")
	}
}

func TestStrtokR_Safe(t *testing.T) {
	code := `
void parse(char *line) {
    char *sp;
    char *tok = strtok_r(line, ",", &sp);
}`
	if hasRule(scanC(code), "BATOU-CAST-013") {
		t.Error("BATOU-CAST-013 false positive on strtok_r()")
	}
}

func TestStrsep_Safe(t *testing.T) {
	code := `
void parse(char *line) {
    char *tok = strsep(&line, ",");
}`
	if hasRule(scanC(code), "BATOU-CAST-013") {
		t.Error("BATOU-CAST-013 false positive on strsep()")
	}
}

// --- BATOU-CAST-014: insecure temp file (CWE-377) --------------------------

func TestMktemp_TP(t *testing.T) {
	code := `
void work() {
    char tmpl[] = "/tmp/fooXXXXXX";
    char *p = mktemp(tmpl);
}`
	if !hasRule(scanC(code), "BATOU-CAST-014") {
		t.Error("expected BATOU-CAST-014 for mktemp()")
	}
}

func TestTmpnam_TP(t *testing.T) {
	code := `
void work() {
    char *name = tmpnam(NULL);
}`
	if !hasRule(scanC(code), "BATOU-CAST-014") {
		t.Error("expected BATOU-CAST-014 for tmpnam()")
	}
}

func TestMkstemp_Safe(t *testing.T) {
	code := `
void work() {
    char tmpl[] = "/tmp/fooXXXXXX";
    int fd = mkstemp(tmpl);
}`
	if hasRule(scanC(code), "BATOU-CAST-014") {
		t.Error("BATOU-CAST-014 false positive on mkstemp()")
	}
}

// --- BATOU-CAST-015: unbounded scanf %s (CWE-120) --------------------------

func TestScanfUnbounded_TP(t *testing.T) {
	code := `
void read_name() {
    char buf[64];
    scanf("%s", buf);
}`
	if !hasRule(scanC(code), "BATOU-CAST-015") {
		t.Error("expected BATOU-CAST-015 for scanf with unbounded string conversion")
	}
}

func TestSscanfUnbounded_TP(t *testing.T) {
	code := `
void parse(const char *src) {
    char buf[32];
    sscanf(src, "key=%s", buf);
}`
	if !hasRule(scanC(code), "BATOU-CAST-015") {
		t.Error("expected BATOU-CAST-015 for sscanf with unbounded string conversion")
	}
}

func TestScanfBracketUnbounded_TP(t *testing.T) {
	code := `
void read_line() {
    char buf[64];
    scanf("%[^\n]", buf);
}`
	if !hasRule(scanC(code), "BATOU-CAST-015") {
		t.Error("expected BATOU-CAST-015 for scanf with unbounded bracket conversion")
	}
}

func TestScanfWidthLimited_Safe(t *testing.T) {
	code := `
void read_name() {
    char buf[64];
    scanf("%63s", buf);
}`
	if hasRule(scanC(code), "BATOU-CAST-015") {
		t.Error("BATOU-CAST-015 false positive on width-limited conversion")
	}
}

func TestScanfNumeric_Safe(t *testing.T) {
	// %d and friends do not write a string — no overflow.
	code := `
void read_num() {
    int n;
    scanf("%d", &n);
}`
	if hasRule(scanC(code), "BATOU-CAST-015") {
		t.Error("BATOU-CAST-015 false positive on numeric conversion")
	}
}

func TestScanfSuppressed_Safe(t *testing.T) {
	// %*s discards input (no destination) — not an overflow.
	code := `
void skip() {
    scanf("%*s");
}`
	if hasRule(scanC(code), "BATOU-CAST-015") {
		t.Error("BATOU-CAST-015 false positive on assignment-suppressed conversion")
	}
}

// --- BATOU-CAST-016: secret-scrub memset dead store (CWE-14) ---------------

func TestSecretScrubDeadStore_TP(t *testing.T) {
	code := `
void use_key() {
    char key[32];
    derive(key);
    encrypt(key);
    memset(key, 0, sizeof(key));
}`
	if !hasRule(scanC(code), "BATOU-CAST-016") {
		t.Error("expected BATOU-CAST-016 for secret-scrub memset never read again")
	}
}

func TestSecretScrubExplicitBzero_Safe(t *testing.T) {
	// explicit_bzero is the recommended replacement and is not a memset.
	code := `
void use_key() {
    char key[32];
    derive(key);
    explicit_bzero(key, sizeof(key));
}`
	if hasRule(scanC(code), "BATOU-CAST-016") {
		t.Error("BATOU-CAST-016 false positive on explicit_bzero")
	}
}

func TestMemsetInit_Safe(t *testing.T) {
	// Initialization memset on a non-secret buffer that IS read afterward.
	code := `
void build() {
    char buf[128];
    memset(buf, 0, sizeof(buf));
    fill(buf);
    send(buf);
}`
	if hasRule(scanC(code), "BATOU-CAST-016") {
		t.Error("BATOU-CAST-016 false positive on initialization memset of non-secret buffer")
	}
}

func TestSecretScrubThenRead_Safe(t *testing.T) {
	// A "key" that is read after the memset is not a dead store.
	code := `
void f() {
    char key[32];
    memset(key, 0, sizeof(key));
    derive(key);
    encrypt(key);
}`
	if hasRule(scanC(code), "BATOU-CAST-016") {
		t.Error("BATOU-CAST-016 false positive when secret is read after memset")
	}
}

// --- BATOU-CAST-017: privilege drop omits setgroups (CWE-252) --------------

func TestPrivDropNoSetgroups_TP(t *testing.T) {
	code := `
void drop(uid_t uid, gid_t gid) {
    setgid(gid);
    setuid(uid);
}`
	if !hasRule(scanC(code), "BATOU-CAST-017") {
		t.Error("expected BATOU-CAST-017 for setgid+setuid without setgroups")
	}
}

func TestPrivDropWithSetgroups_Safe(t *testing.T) {
	code := `
void drop(uid_t uid, gid_t gid) {
    setgroups(0, NULL);
    setgid(gid);
    setuid(uid);
}`
	if hasRule(scanC(code), "BATOU-CAST-017") {
		t.Error("BATOU-CAST-017 false positive when setgroups present")
	}
}

func TestPrivDropWithInitgroups_Safe(t *testing.T) {
	code := `
void drop(const char *user, uid_t uid, gid_t gid) {
    initgroups(user, gid);
    setgid(gid);
    setuid(uid);
}`
	if hasRule(scanC(code), "BATOU-CAST-017") {
		t.Error("BATOU-CAST-017 false positive when initgroups present")
	}
}

func TestSetuidOnly_Safe(t *testing.T) {
	// No setgid — not a full identity drop; do not flag.
	code := `
void drop(uid_t uid) {
    setuid(uid);
}`
	if hasRule(scanC(code), "BATOU-CAST-017") {
		t.Error("BATOU-CAST-017 false positive on setuid-only function")
	}
}

// --- BATOU-CAST-018: /dev/random loop fd exhaustion (CWE-400) --------------

func TestDevRandomLoopNoClose_TP(t *testing.T) {
	code := `
void seed_all(int n) {
    for (int i = 0; i < n; i++) {
        int fd = open("/dev/random", 0);
        read(fd, &buf[i], 1);
    }
}`
	if !hasRule(scanC(code), "BATOU-CAST-018") {
		t.Error("expected BATOU-CAST-018 for /dev/random open in loop without close")
	}
}

func TestDevRandomLoopWithClose_Safe(t *testing.T) {
	code := `
void seed_all(int n) {
    for (int i = 0; i < n; i++) {
        int fd = open("/dev/random", 0);
        read(fd, &buf[i], 1);
        close(fd);
    }
}`
	if hasRule(scanC(code), "BATOU-CAST-018") {
		t.Error("BATOU-CAST-018 false positive when fd is closed in the loop")
	}
}

func TestDevRandomOpenOnce_Safe(t *testing.T) {
	// Opened once outside the loop — no exhaustion.
	code := `
void seed_all(int n) {
    int fd = open("/dev/random", 0);
    for (int i = 0; i < n; i++) {
        read(fd, &buf[i], 1);
    }
    close(fd);
}`
	if hasRule(scanC(code), "BATOU-CAST-018") {
		t.Error("BATOU-CAST-018 false positive on open-once-outside-loop")
	}
}
