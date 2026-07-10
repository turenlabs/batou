package race

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// truncate(): the long-string branch (len(s) > maxLen) is only exercised when
// a matched/trimmed line exceeds 120 chars. RACE-004 truncates the full
// trimmed line, so a very long outer null-check line produces a "..."-suffixed
// MatchedText.
// ---------------------------------------------------------------------------

func TestRACE004_LongLine_MatchedTextTruncated(t *testing.T) {
	// The outer null-check line is padded past 120 chars with a comment-free
	// trailing token so reDoubleCheckLock still matches (`if ( x == null ) {`
	// at end-of-line). We keep it as a single logical line.
	longName := "instanceFieldWithAnExtremelyLongDescriptiveIdentifierNameThatExceedsTheTruncationLimitForMatchedTextEasily"
	content := "public class Singleton {\n" +
		"    private static Singleton " + longName + ";\n" +
		"    public static Singleton getInstance() {\n" +
		"        if (" + longName + " == null) {\n" +
		"            synchronized (Singleton.class) {\n" +
		"                if (" + longName + " == null) {\n" +
		"                    " + longName + " = new Singleton();\n" +
		"                }\n" +
		"            }\n" +
		"        }\n" +
		"        return " + longName + ";\n" +
		"    }\n" +
		"}\n"
	result := testutil.ScanContent(t, "/app/Singleton.java", content)
	fs := testutil.FindingsByRule(result, "BATOU-RACE-004")
	if len(fs) == 0 {
		t.Fatal("expected a BATOU-RACE-004 finding for long-line DCL")
	}
	if !strings.HasSuffix(fs[0].MatchedText, "...") {
		t.Errorf("MatchedText = %q, want a truncated value ending in %q", fs[0].MatchedText, "...")
	}
	if len(fs[0].MatchedText) != 123 { // 120 chars + "..."
		t.Errorf("MatchedText len = %d, want 123 (120 + ellipsis)", len(fs[0].MatchedText))
	}
}

// truncate() directly: unit-test both branches without the scanner.
func TestTruncate_BothBranches(t *testing.T) {
	if got := truncate("short", 120); got != "short" {
		t.Errorf("truncate short = %q, want unchanged", got)
	}
	long := strings.Repeat("a", 200)
	got := truncate(long, 10)
	if got != strings.Repeat("a", 10)+"..." {
		t.Errorf("truncate long = %q, want first 10 + ellipsis", got)
	}
}

// ---------------------------------------------------------------------------
// BATOU-RACE-002: Go check-then-act with NO goroutine evidence -> the Go
// concurrency gate's `continue` (race.go:242-243) suppresses the finding.
// ---------------------------------------------------------------------------

func TestRACE002_Go_NoGoroutine_Safe(t *testing.T) {
	content := `package main

func get(m map[string]int, key string) int {
	if m[key] == 0 {
		m[key] = 1
	}
	return m[key]
}
`
	result := testutil.ScanContent(t, "/app/get.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-002")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-003: atomic operation nearby -> reAtomicOp `continue`
// (race.go:319-320). UPDATE ... SET balance = balance - amount is the atomic
// DB form the rule treats as safe.
// ---------------------------------------------------------------------------

func TestRACE003_AtomicDBUpdate_Safe(t *testing.T) {
	// Python server-side: the read+update is guarded by an atomic SQL UPDATE
	// in the immediate vicinity, so reAtomicOp suppresses the finding.
	content := `def withdraw(user, amount):
    balance = get_balance(user)
    db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, user)
    return balance
`
	result := testutil.ScanContent(t, "/app/wallet.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-003")
}

func TestRACE003_LockNearby_Safe(t *testing.T) {
	// A lock acquired within 10 lines back suppresses RACE-003 (reLockNearby).
	content := `import threading
lock = threading.Lock()

def withdraw(amount):
    lock.acquire()
    balance = get_balance()
    balance = balance - amount
    save(balance)
`
	result := testutil.ScanContent(t, "/app/wallet.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-003")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-004: comment line inside the scan loop hits the isComment
// `continue` (race.go:369-370); and the inner-loop end clamp (race.go:377-379)
// is hit when the DCL outer check is within 10 lines of EOF.
// ---------------------------------------------------------------------------

func TestRACE004_CommentLine_StillFires(t *testing.T) {
	// Leading comment lines are skipped via isComment; the real DCL still
	// fires. Also: the second null-check is the LAST line before the closing
	// brace, exercising the inner-loop EOF clamp.
	// NOTE: comments here must avoid the words "volatile"/"lock"/"sync" so the
	// safe-gates (reVolatile/reLazySafe) are not tripped by comment text — the
	// nearby-pattern window does not strip comments.
	content := `// Singleton with the classic broken init-on-first-use pattern
public class Singleton {
    // the instance field is plain, not guarded for visibility
    private static Singleton instance;
    public static Singleton getInstance() {
        if (instance == null) {
            synchronized (Singleton.class) {
                if (instance == null) {
                    instance = new Singleton();
                }
            }
        }
        return instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Singleton.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-004")
}

func TestRACE004_OuterCheckNearEOF_Clamp(t *testing.T) {
	// The outer `if (x == null) {` is close enough to EOF that innerEnd
	// (i+10) overruns len(lines) and the clamp branch (race.go:377-379) runs.
	// The sync block + inner null-check appear immediately after.
	content := `public class S {
    private static S instance;
    public static S g() {
        if (instance == null) {
            synchronized (S.class) {
                if (instance == null) { instance = new S(); }
}}return instance;}}
`
	result := testutil.ScanContent(t, "/app/S.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-004")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-006: comment lines in both the Go and Java loops hit the
// isComment `continue` branches (race.go:499-500 Go, 528-529 Java).
// ---------------------------------------------------------------------------

func TestRACE006_Go_CommentLine_StillFires(t *testing.T) {
	content := `package main

// counter is shared mutable state touched by the goroutine below
var counter int

func run() {
	// launch worker without any synchronization
	go func() {
		counter = counter + 1
	}()
}
`
	result := testutil.ScanContent(t, "/app/run.go", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-006")
}

func TestRACE006_Java_CommentLine_StillFires(t *testing.T) {
	content := `public class Worker {
    // total is mutated by the thread with no guards at all
    private int total;
    void launch() {
        // unguarded shared write -> data race
        new Thread(() -> total++).start();
    }
}
`
	result := testutil.ScanContent(t, "/app/Worker.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-006")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-007: comment line in the scan loop hits isComment `continue`
// (race.go:591-592). NonAtomicRMW is registered-out, so call Scan directly.
// ---------------------------------------------------------------------------

func TestRACE007_CommentLine_StillFires(t *testing.T) {
	content := `package main

var counter int

func run() {
	// spawn concurrency, then a plain compound assignment below
	go func() {}()
	// this increment can lose updates under concurrency
	counter += 1
}
`
	ctx := &rules.ScanContext{
		FilePath: "/app/rmw.go",
		Content:  content,
		Language: rules.LangGo,
	}
	findings := (&NonAtomicRMW{}).Scan(ctx)
	if len(findings) == 0 {
		t.Fatal("expected BATOU-RACE-007 finding despite comment lines")
	}
}

// ---------------------------------------------------------------------------
// BATOU-RACE-008: exercise the remaining LazyInitRace branches.
// ---------------------------------------------------------------------------

func TestRACE008_Java_CommentLine_StillFires(t *testing.T) {
	// Comment lines hit the Java-branch isComment continue (race.go:647-648).
	content := `public class Config {
    // lazily-initialized singleton, no synchronization
    private static Config instance;
    public static Config get() {
        // classic unsafe lazy init
        if (instance == null) {
            instance = new Config();
        }
        return instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Config.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-008")
}

func TestRACE008_Java_VolatileSafeGate(t *testing.T) {
	// reLazySafe ("volatile") within 5 lines back of the instance declaration
	// triggers the Java safe-gate continue (race.go:653-654).
	content := `public class Config {
    private static volatile boolean ready;
    private static Config instance;
    public static Config get() {
        if (instance == null) {
            instance = new Config();
        }
        return instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Config.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-008")
}

func TestRACE008_CSharp_CommentLine_StillFires(t *testing.T) {
	// Comment lines hit the C#-branch isComment continue (race.go:681-682).
	content := `public class Config {
    // unsafe lazy init in C#
    private static Config _instance;
    public static Config Get() {
        // no Lazy<T>, no lock
        if (_instance == null) {
            _instance = new Config();
        }
        return _instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Config.cs", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-008")
}

func TestRACE008_CSharp_SyncBlockSafeGate(t *testing.T) {
	// A lock(...) block within 20 lines after the _instance declaration hits
	// the C# reSyncBlock safe-gate continue (race.go:689-690). reLazySafe must
	// NOT precede it (that would take the earlier gate), so we use a plain
	// lock() guard around the creation.
	content := `public class Config {
    private static readonly object _gate = new object();
    private static Config _instance;
    public static Config Get() {
        if (_instance == null) {
            lock (_gate) {
                _instance = new Config();
            }
        }
        return _instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Config.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-008")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-008: unsupported language hits neither switch arm -> 0 findings.
// ---------------------------------------------------------------------------

func TestRACE008_UnsupportedLanguage_NoFindings(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/x.go",
		Content:  "var instance *T\nif instance == nil { instance = newT() }\n",
		Language: rules.LangGo,
	}
	if f := (&LazyInitRace{}).Scan(ctx); len(f) != 0 {
		t.Fatalf("expected 0 RACE-008 findings for Go, got %d", len(f))
	}
}
