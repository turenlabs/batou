package race

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// Rule metadata sanity (ID/Name/Severity/Languages must stay in sync)
// ---------------------------------------------------------------------------

func TestRACE_RuleMetadata(t *testing.T) {
	cases := []struct {
		rule    rules.Rule
		id      string
		name    string
		minSev  rules.Severity
		wantLng rules.Language
	}{
		{&TOCTOU{}, "BATOU-RACE-001", "TOCTOU", rules.Medium, rules.LangGo},
		{&CheckThenAct{}, "BATOU-RACE-002", "CheckThenAct", rules.Medium, rules.LangGo},
		{&BalanceRace{}, "BATOU-RACE-003", "BalanceRace", rules.High, rules.LangGo},
		{&DoubleCheckedLocking{}, "BATOU-RACE-004", "DoubleCheckedLocking", rules.Medium, rules.LangJava},
		{&SignalHandlerRace{}, "BATOU-RACE-005", "SignalHandlerRace", rules.Medium, rules.LangC},
		{&SharedMutableState{}, "BATOU-RACE-006", "SharedMutableState", rules.Medium, rules.LangGo},
		{&NonAtomicRMW{}, "BATOU-RACE-007", "NonAtomicRMW", rules.Medium, rules.LangGo},
		{&LazyInitRace{}, "BATOU-RACE-008", "LazyInitRace", rules.Medium, rules.LangJava},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if got := c.rule.ID(); got != c.id {
				t.Errorf("ID() = %q, want %q", got, c.id)
			}
			if got := c.rule.Name(); got != c.name {
				t.Errorf("Name() = %q, want %q", got, c.name)
			}
			if got := c.rule.DefaultSeverity(); got != c.minSev {
				t.Errorf("DefaultSeverity() = %v, want %v", got, c.minSev)
			}
			if c.rule.Description() == "" {
				t.Error("Description() is empty")
			}
			found := false
			for _, l := range c.rule.Languages() {
				if l == c.wantLng {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Languages() = %v, missing %v", c.rule.Languages(), c.wantLng)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-RACE-001: TOCTOU file operation
// ---------------------------------------------------------------------------

func TestRACE001_Python_AccessThenOpen_Fires(t *testing.T) {
	content := `import os

def read_config(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-001")
}

func TestRACE001_Python_AccessNoOpen_Safe(t *testing.T) {
	// os.access with no subsequent open within 10 lines: no TOCTOU.
	content := `import os

def can_read(path):
    return os.access(path, os.R_OK)
`
	result := testutil.ScanContent(t, "/app/perm.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-001")
}

func TestRACE001_C_AccessThenFopen_Fires(t *testing.T) {
	content := `#include <unistd.h>
#include <stdio.h>

int load(const char *path) {
    if (access(path, R_OK) == 0) {
        FILE *fp = fopen(path, "r");
        return fp != NULL;
    }
    return -1;
}
`
	result := testutil.ScanContent(t, "/app/load.c", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-001")
}

func TestRACE001_Go_StatThenOpen_Fires(t *testing.T) {
	// os.Stat(...) ... os.IsNotExist on one line (reTOCTOUGoExists), followed
	// by os.Open within 10 lines (reFileOpenAfter). os.ReadFile is NOT in the
	// open-after pattern, so the check uses os.Open explicitly.
	content := `package main

import "os"

func read(path string) (*os.File, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	return os.Open(path)
}
`
	result := testutil.ScanContent(t, "/app/read.go", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-001")
}

func TestRACE001_Comment_Ignored(t *testing.T) {
	// The check pattern only appears in a comment line; should not fire.
	content := `import os

def noop(path):
    # os.path.exists(path) then open(path) would be TOCTOU
    return path
`
	result := testutil.ScanContent(t, "/app/noop.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-001")
}

func TestRACE001_UnsupportedLanguage_NoFindings(t *testing.T) {
	// TOCTOU.Languages() excludes Ruby; scanning a .rb yields no RACE-001.
	content := `require 'fileutils'
if File.exist?(path)
  File.open(path) { |f| f.read }
end
`
	result := testutil.ScanContent(t, "/app/file.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-001")
}

// Directly exercise the default branch of Scan() for an unsupported language.
func TestRACE001_ScanDefaultBranch(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/x.rb",
		Content:  "if File.exist?(p)\n  File.open(p)\nend\n",
		Language: rules.LangRuby,
	}
	if f := (&TOCTOU{}).Scan(ctx); len(f) != 0 {
		t.Fatalf("expected 0 findings for unsupported language, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// BATOU-RACE-002: Check-then-act allowlist suppression
// ---------------------------------------------------------------------------

func TestRACE002_Python_AllowlistTuple_Safe(t *testing.T) {
	// `if scheme not in (...)` is input validation, not check-then-act.
	content := `import threading

def validate(scheme):
    if scheme not in ('http', 'https', 'ftp'):
        raise ValueError("bad scheme")
    return scheme
`
	result := testutil.ScanContent(t, "/app/validate.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-002")
}

func TestRACE002_Java_ThreadStart_Fires(t *testing.T) {
	content := `public class Cache {
    private java.util.Map<String,Integer> map = new java.util.HashMap<>();
    void run(String key) {
        new Thread(() -> doWork()).start();
        if (map.containsKey(key)) {
            map.get(key);
        }
    }
}
`
	result := testutil.ScanContent(t, "/app/Cache.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-002")
}

func TestRACE002_Java_NoThread_Safe(t *testing.T) {
	// Java check-then-act with no thread-start evidence: rule requires it.
	content := `public class Cache {
    private java.util.Map<String,Integer> map = new java.util.HashMap<>();
    int get(String key) {
        if (map.containsKey(key)) {
            return map.get(key);
        }
        return 0;
    }
}
`
	result := testutil.ScanContent(t, "/app/Cache.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-002")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-004: Double-checked locking
// ---------------------------------------------------------------------------

func TestRACE004_Java_DCL_NoVolatile_Fires(t *testing.T) {
	content := `public class Singleton {
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

func TestRACE004_Java_DCL_Volatile_Safe(t *testing.T) {
	content := `public class Singleton {
    private static volatile Singleton instance;
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
	testutil.MustNotFindRule(t, result, "BATOU-RACE-004")
}

func TestRACE004_Java_NullCheckNoSync_Safe(t *testing.T) {
	// Outer null check but no synchronized block follows: not DCL.
	content := `public class Lazy {
    private static Lazy instance;
    public static Lazy get() {
        if (instance == null) {
            instance = new Lazy();
        }
        return instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Lazy.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-004")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-005: Signal handler with non-reentrant function
// ---------------------------------------------------------------------------

func TestRACE005_C_SignalHandlerPrintf_Fires(t *testing.T) {
	content := `#include <signal.h>
#include <stdio.h>

void handler(int sig) {
    printf("caught %d\n", sig);
}

int main(void) {
    signal(SIGINT, handler);
    printf("ready\n");
    return 0;
}
`
	result := testutil.ScanContent(t, "/app/sig.c", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-005")
}

func TestRACE005_C_NoSignal_Safe(t *testing.T) {
	// printf with no signal registration in the file: rule needs the handler.
	content := `#include <stdio.h>

int main(void) {
    printf("hello\n");
    return 0;
}
`
	result := testutil.ScanContent(t, "/app/main.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-005")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-006: Shared mutable state without synchronization
// ---------------------------------------------------------------------------

func TestRACE006_Go_GoroutineNoSync_Fires(t *testing.T) {
	content := `package main

var counter int

func run() {
	go func() {
		counter = counter + 1
	}()
}
`
	result := testutil.ScanContent(t, "/app/run.go", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-006")
}

func TestRACE006_Go_GoroutineWithMutex_Safe(t *testing.T) {
	content := `package main

import "sync"

var mu sync.Mutex
var counter int

func run() {
	go func() {
		mu.Lock()
		counter = counter + 1
		mu.Unlock()
	}()
}
`
	result := testutil.ScanContent(t, "/app/run.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-006")
}

func TestRACE006_Java_ThreadNoSync_Fires(t *testing.T) {
	content := `public class Worker {
    private int total;
    void launch() {
        new Thread(() -> total++).start();
    }
}
`
	result := testutil.ScanContent(t, "/app/Worker.java", content)
	testutil.MustFindRule(t, result, "BATOU-RACE-006")
}

func TestRACE006_Java_ThreadWithLock_Safe(t *testing.T) {
	content := `import java.util.concurrent.locks.ReentrantLock;
public class Worker {
    private final ReentrantLock lock = new ReentrantLock();
    private int total;
    void launch() {
        new Thread(() -> {
            lock.lock();
            total++;
            lock.unlock();
        }).start();
    }
}
`
	result := testutil.ScanContent(t, "/app/Worker.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-006")
}

// ---------------------------------------------------------------------------
// BATOU-RACE-007: Non-atomic read-modify-write (registered out — call Scan directly)
// ---------------------------------------------------------------------------

func TestRACE007_Go_ConcurrentRMW_Fires(t *testing.T) {
	content := `package main

var counter int

func run() {
	go func() {}()
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
		t.Fatal("expected BATOU-RACE-007 finding for concurrent +=")
	}
	if findings[0].RuleID != "BATOU-RACE-007" {
		t.Fatalf("RuleID = %q, want BATOU-RACE-007", findings[0].RuleID)
	}
}

func TestRACE007_Go_NoConcurrency_Safe(t *testing.T) {
	// No goroutine/thread/sync construct anywhere: rule bails early.
	content := `package main

func run() {
	counter := 0
	counter += 1
	_ = counter
}
`
	ctx := &rules.ScanContext{
		FilePath: "/app/rmw.go",
		Content:  content,
		Language: rules.LangGo,
	}
	if f := (&NonAtomicRMW{}).Scan(ctx); len(f) != 0 {
		t.Fatalf("expected 0 findings without concurrency, got %d", len(f))
	}
}

func TestRACE007_Go_RMWWithAtomic_Safe(t *testing.T) {
	// Concurrency present but atomic op guards the RMW within 5 lines back.
	content := `package main

import "sync/atomic"

var counter int64

func run() {
	go func() {}()
	atomic.AddInt64(&counter, 1)
	counter += 1
}
`
	ctx := &rules.ScanContext{
		FilePath: "/app/rmw.go",
		Content:  content,
		Language: rules.LangGo,
	}
	if f := (&NonAtomicRMW{}).Scan(ctx); len(f) != 0 {
		t.Fatalf("expected 0 findings with nearby atomic, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// BATOU-RACE-008: Race in lazy initialization singleton
// ---------------------------------------------------------------------------

func TestRACE008_Java_LazyInitNoSync_Fires(t *testing.T) {
	content := `public class Config {
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
	testutil.MustFindRule(t, result, "BATOU-RACE-008")
}

func TestRACE008_Java_LazyInitSynchronized_Safe(t *testing.T) {
	content := `public class Config {
    private static Config instance;
    public static synchronized Config get() {
        synchronized (Config.class) {
            if (instance == null) {
                instance = new Config();
            }
        }
        return instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Config.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-008")
}

func TestRACE008_CSharp_LazyInitNoSync_Fires(t *testing.T) {
	content := `public class Config {
    private static Config _instance;
    public static Config Get() {
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

func TestRACE008_CSharp_LazyType_Safe(t *testing.T) {
	// Lazy<T> field is the recommended thread-safe pattern. reLazySafe is
	// checked 5 lines *back* from the _instance declaration, so the Lazy<>
	// field must precede it for the safe gate to suppress the finding.
	content := `public class Config {
    private static Lazy<Config> lazy = new Lazy<Config>(() => new Config());
    private static Config _instance;
    public static Config Get() {
        if (_instance == null) {
            _instance = lazy.Value;
        }
        return _instance;
    }
}
`
	result := testutil.ScanContent(t, "/app/Config.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RACE-008")
}

// ---------------------------------------------------------------------------
// Finding-shape assertions: verify a representative finding's metadata.
// ---------------------------------------------------------------------------

func TestRACE_FindingShape(t *testing.T) {
	content := `import os

def read_config(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	fs := testutil.FindingsByRule(result, "BATOU-RACE-001")
	if len(fs) == 0 {
		t.Fatal("expected a BATOU-RACE-001 finding")
	}
	f := fs[0]
	if f.CWEID != "CWE-367" {
		t.Errorf("CWEID = %q, want CWE-367", f.CWEID)
	}
	if f.LineNumber <= 0 {
		t.Errorf("LineNumber = %d, want > 0", f.LineNumber)
	}
	if f.MatchedText == "" {
		t.Error("MatchedText is empty")
	}
	if f.Suggestion == "" {
		t.Error("Suggestion is empty")
	}
}
