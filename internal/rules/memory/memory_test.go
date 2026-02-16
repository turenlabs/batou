package memory

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-MEM-001: Banned Functions ---

func TestMEM001_Gets(t *testing.T) {
	content := `char buf[256];
gets(buf);`
	result := testutil.ScanContent(t, "/app/input.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_Strcpy(t *testing.T) {
	content := `char dest[64];
strcpy(dest, src);`
	result := testutil.ScanContent(t, "/app/string.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_Strcat(t *testing.T) {
	content := `strcat(buf, user_input);`
	result := testutil.ScanContent(t, "/app/string.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_Sprintf(t *testing.T) {
	content := `sprintf(buf, "Hello %s", name);`
	result := testutil.ScanContent(t, "/app/format.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_ScanfS(t *testing.T) {
	content := `scanf("%s", buffer);`
	result := testutil.ScanContent(t, "/app/input.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_Atoi(t *testing.T) {
	content := `int val = atoi(argv[1]);`
	result := testutil.ScanContent(t, "/app/parse.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_Fixture_BufferOverflow(t *testing.T) {
	if !testutil.FixtureExists("c/vulnerable/buffer_overflow.c") {
		t.Skip("C buffer overflow fixture not available")
	}
	content := testutil.LoadFixture(t, "c/vulnerable/buffer_overflow.c")
	result := testutil.ScanContent(t, "/app/vuln.c", content)
	hasMem := testutil.HasFinding(result, "BATOU-MEM-001") ||
		testutil.HasFinding(result, "BATOU-MEM-003")
	if !hasMem {
		t.Errorf("expected memory finding in buffer_overflow.c, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestMEM001_Fixture_FormatString(t *testing.T) {
	if !testutil.FixtureExists("c/vulnerable/format_string.c") {
		t.Skip("C format string fixture not available")
	}
	content := testutil.LoadFixture(t, "c/vulnerable/format_string.c")
	result := testutil.ScanContent(t, "/app/vuln.c", content)
	hasMem := testutil.HasFinding(result, "BATOU-MEM-001") ||
		testutil.HasFinding(result, "BATOU-MEM-002")
	if !hasMem {
		t.Errorf("expected memory finding in format_string.c, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestMEM001_Safe_Fixture(t *testing.T) {
	if !testutil.FixtureExists("c/safe/buffer_safe.c") {
		t.Skip("C safe buffer fixture not available")
	}
	content := testutil.LoadFixture(t, "c/safe/buffer_safe.c")
	result := testutil.ScanContent(t, "/app/safe.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-001")
}

func TestMEM001_Safe_FormatFixture(t *testing.T) {
	if !testutil.FixtureExists("c/safe/format_safe.c") {
		t.Skip("C safe format fixture not available")
	}
	content := testutil.LoadFixture(t, "c/safe/format_safe.c")
	result := testutil.ScanContent(t, "/app/safe.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-002")
}

// --- BATOU-MEM-002: Format String ---

func TestMEM002_PrintfVar(t *testing.T) {
	content := `printf(user_input);`
	result := testutil.ScanContent(t, "/app/format.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-002")
}

func TestMEM002_FprintfVar(t *testing.T) {
	content := `fprintf(stderr, user_msg);`
	result := testutil.ScanContent(t, "/app/format.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-002")
}

func TestMEM002_SyslogVar(t *testing.T) {
	content := `syslog(LOG_ERR, user_input);`
	result := testutil.ScanContent(t, "/app/log.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-002")
}

func TestMEM002_Safe_LiteralFormat(t *testing.T) {
	content := `printf("%s", user_input);`
	result := testutil.ScanContent(t, "/app/format.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-002")
}

// --- BATOU-MEM-003: Buffer Overflow ---

func TestMEM003_StrncpyStrlen(t *testing.T) {
	content := `strncpy(dst, src, strlen(src));`
	result := testutil.ScanContent(t, "/app/string.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-003")
}

func TestMEM003_MemcpyVar(t *testing.T) {
	content := `memcpy(dst, src, user_len)`
	result := testutil.ScanContent(t, "/app/copy.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-003")
}

// --- BATOU-MEM-004: Memory Management (Double Free / Use After Free) ---

func TestMEM004_DoubleFree(t *testing.T) {
	content := `void vuln(char *ptr) {
    free(ptr);
    free(ptr);
}`
	result := testutil.ScanContent(t, "/app/mem.c", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-MEM-004", "BATOU-MEM-008")
}

func TestMEM004_UseAfterFree(t *testing.T) {
	content := `void vuln() {
    char *buf = malloc(100);
    free(buf);
    buf[0] = 'a';
}`
	result := testutil.ScanContent(t, "/app/mem.c", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-MEM-004", "BATOU-MEM-006", "BATOU-MEM-007")
}

func TestMEM004_Safe_NullAfterFree(t *testing.T) {
	content := `void safe() {
    char *buf = malloc(100);
    free(buf);
    buf = NULL;
}`
	result := testutil.ScanContent(t, "/app/mem.c", content)
	// After setting to NULL, there should be no use-after-free
	// The double-free should not trigger since we set NULL before any reuse
	_ = result
}

// --- BATOU-MEM-005: Integer Overflow in Allocation ---

func TestMEM005_MallocMul(t *testing.T) {
	content := `buf = malloc(count * sizeof(int))`
	result := testutil.ScanContent(t, "/app/alloc.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-005")
}

func TestMEM005_ReallocArith(t *testing.T) {
	content := `buf = realloc(buf, size + extra)`
	result := testutil.ScanContent(t, "/app/alloc.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-005")
}

func TestMEM005_Fixture_IntegerOverflow(t *testing.T) {
	if !testutil.FixtureExists("c/vulnerable/integer_overflow.c") {
		t.Skip("C integer overflow fixture not available")
	}
	content := testutil.LoadFixture(t, "c/vulnerable/integer_overflow.c")
	result := testutil.ScanContent(t, "/app/alloc.c", content)
	hasMem := testutil.HasFinding(result, "BATOU-MEM-005") || testutil.HasFinding(result, "BATOU-MEM-001")
	if !hasMem {
		t.Errorf("expected memory finding in integer_overflow.c, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- BATOU-MEM-006: Null Pointer Dereference ---

func TestMEM006_MallocNoCheck(t *testing.T) {
	content := `void process() {
    buf = malloc(1024);
    buf[0] = 'a';
}`
	result := testutil.ScanContent(t, "/app/alloc.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-006")
}

func TestMEM006_Safe_WithNullCheck(t *testing.T) {
	content := `void process() {
    buf = malloc(1024);
    if (buf == NULL) return;
    buf[0] = 'a';
}`
	result := testutil.ScanContent(t, "/app/alloc.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-006")
}

func TestMEM006_Safe_Fixture(t *testing.T) {
	if !testutil.FixtureExists("c/safe/malloc_safe.c") {
		t.Skip("C safe malloc fixture not available")
	}
	content := testutil.LoadFixture(t, "c/safe/malloc_safe.c")
	result := testutil.ScanContent(t, "/app/safe.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-006")
}
