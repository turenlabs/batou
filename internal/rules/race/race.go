package race

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-RACE-001: TOCTOU file operation
var (
	reTOCTOUAccessOpen  = regexp.MustCompile(`(?i)\b(?:os\.access|os\.path\.exists|os\.path\.isfile|os\.path\.isdir|Path\.exists|Path\.is_file)\s*\(`)
	reTOCTOUStatOpen    = regexp.MustCompile(`(?i)\b(?:os\.Stat|os\.Lstat|syscall\.Stat|stat|lstat|access)\s*\(`)
	reTOCTOUFileExistsC = regexp.MustCompile(`(?i)\b(?:access|stat|lstat|fstat)\s*\(\s*[^,)]+,\s*(?:F_OK|R_OK|W_OK|X_OK)\s*\)`)
	reTOCTOUGoExists    = regexp.MustCompile(`(?i)\b(?:os\.Stat|os\.Lstat)\s*\([^)]+\).*(?:os\.IsNotExist|errors\.Is)`)
	reFileOpenAfter     = regexp.MustCompile(`(?i)\b(?:open|fopen|os\.Open|os\.Create|os\.OpenFile|ioutil\.ReadFile|ioutil\.WriteFile|File\.new|File\.open)\s*\(`)
)

// BATOU-RACE-002: Check-then-act without locking
var (
	reCheckThenActMap   = regexp.MustCompile(`(?i)(?:if\s+.*\b(?:in|contains|containsKey|has|hasKey|get|include\?)\s*\(|if\s+\w+\s*\[\s*\w+\s*\]\s*(?:!=|==))`)
	reCheckThenActNull  = regexp.MustCompile(`(?i)(?:if\s*\(\s*\w+\s*(?:!=|==)\s*(?:null|nil|None|undefined)\s*\)\s*\{?\s*$)`)
	reLockNearby        = regexp.MustCompile(`(?i)(?:\.Lock\(\)|\.lock\(\)|synchronized|mutex|Monitor\.Enter|lock\s*\(|threading\.Lock|RLock|Semaphore|\.acquire\(\)|ReentrantLock)`)
)

// BATOU-RACE-003: Race condition in balance/counter update
var (
	reBalanceUpdate     = regexp.MustCompile(`(?i)(?:balance|amount|quantity|stock|inventory|credits?|points?|counter|count)\s*(?:=\s*(?:balance|amount|quantity|stock|inventory|credits?|points?|counter|count)\s*[-+]|\+=|-=)`)
	reBalanceRead       = regexp.MustCompile(`(?i)(?:balance|amount|quantity|stock|inventory|credits?|points?)\s*=\s*(?:get|fetch|find|select|read|load|query)`)
	reAtomicOp          = regexp.MustCompile(`(?i)(?:atomic|AtomicInteger|AtomicLong|\.getAndAdd|\.incrementAndGet|\.compareAndSet|F\s*\(\s*["'](?:balance|amount|quantity)\s*["']\s*\)\s*-\s*|\.update\s*\(|UPDATE\s+\w+\s+SET\s+\w+\s*=\s*\w+\s*[-+])`)
)

// BATOU-RACE-004: Double-checked locking anti-pattern
var (
	reDoubleCheckLock = regexp.MustCompile(`(?i)if\s*\(\s*\w+\s*==\s*null\s*\)\s*\{?\s*$`)
	reSyncBlock       = regexp.MustCompile(`(?i)(?:synchronized\s*\(|lock\s*\(|Monitor\.Enter|\.Lock\(\))`)
	reDoubleCheckInner = regexp.MustCompile(`(?i)if\s*\(\s*\w+\s*==\s*null\s*\)`)
	reVolatile        = regexp.MustCompile(`(?i)(?:volatile|Volatile\.Read|Interlocked|AtomicReference|@GuardedBy)`)
)

// BATOU-RACE-005: Signal handler with non-reentrant function
var (
	reSignalHandler    = regexp.MustCompile(`(?i)\b(?:signal|sigaction)\s*\(\s*(?:SIG\w+|SIGINT|SIGTERM|SIGKILL|SIGUSR\d)\s*,`)
	reNonReentrantFunc = regexp.MustCompile(`(?i)\b(?:printf|fprintf|sprintf|snprintf|malloc|calloc|realloc|free|exit|abort|syslog|strtok|ctime|localtime|asctime|gmtime|gethostbyname|getservbyname|getpwnam|getgrnam|strerror)\s*\(`)
)

// BATOU-RACE-006: Shared mutable state without synchronization
var (
	reGoGoroutineWrite     = regexp.MustCompile(`(?i)\bgo\s+(?:func\s*\(|[a-zA-Z_]\w*\s*\()`)
	reGoSharedWrite        = regexp.MustCompile(`(?i)(?:\w+\s*=\s*|(?:append|delete)\s*\()`)
	reGoSyncMechanism      = regexp.MustCompile(`(?i)(?:sync\.Mutex|sync\.RWMutex|sync\.WaitGroup|sync\.Once|sync\.Map|chan\s+|<-\s*\w+|\w+\s*<-|atomic\.)`)
	reJavaSyncAccess       = regexp.MustCompile(`(?i)(?:private|public|protected)?\s*(?:static\s+)?(?:(?!volatile)\w+\s+)+\w+\s*;`)
	reJavaThreadStart      = regexp.MustCompile(`(?i)(?:\.start\(\)|ExecutorService|ThreadPoolExecutor|new\s+Thread|CompletableFuture\.(?:runAsync|supplyAsync))`)
)

// BATOU-RACE-007: Non-atomic read-modify-write
var (
	reReadModifyWrite   = regexp.MustCompile(`(?i)(\w+)\s*(?:\+=|-=|\*=|/=|%=|\+\+|--)`)
	reReadModifyWriteExplicit = regexp.MustCompile(`(?i)(\w+)\s*=\s*\1\s*[-+*/]`)
	reAtomicOrLock      = regexp.MustCompile(`(?i)(?:atomic|Atomic|\.Lock\(\)|synchronized|lock\s*\(|Interlocked|sync\.Mutex|chan\b)`)
)

// BATOU-RACE-008: Race in lazy initialization singleton
var (
	reLazyInitJava   = regexp.MustCompile(`(?i)(?:private\s+static\s+\w+\s+instance\s*;|static\s+\w+\s+INSTANCE\s*;)`)
	reLazyInitCheck  = regexp.MustCompile(`(?i)if\s*\(\s*(?:instance|INSTANCE)\s*==\s*null\s*\)`)
	reLazyInitCS     = regexp.MustCompile(`(?i)(?:private\s+static\s+\w+\s+_instance\s*;|static\s+\w+\s+s_instance\s*;)`)
	reLazyInitCSCheck = regexp.MustCompile(`(?i)if\s*\(\s*(?:_instance|s_instance)\s*==\s*null\s*\)`)
	reLazySafe       = regexp.MustCompile(`(?i)(?:volatile|Lazy<|LazyHolder|@Singleton|enum\s+\w+\s*\{|Interlocked\.CompareExchange|sync\.Once|Holder)`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func hasNearbyPattern(lines []string, idx, before, after int, re *regexp.Regexp) bool {
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := idx + after + 1
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-RACE-001: TOCTOU file operation
// ---------------------------------------------------------------------------

type TOCTOU struct{}

func (r *TOCTOU) ID() string                     { return "BATOU-RACE-001" }
func (r *TOCTOU) Name() string                   { return "TOCTOU" }
func (r *TOCTOU) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TOCTOU) Description() string {
	return "Detects Time-of-Check-Time-of-Use (TOCTOU) race conditions where a file is checked for existence or permissions, then opened/modified in a separate operation."
}
func (r *TOCTOU) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP, rules.LangGo, rules.LangPython}
}

func (r *TOCTOU) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var checkPatterns []*regexp.Regexp
	switch ctx.Language {
	case rules.LangC, rules.LangCPP:
		checkPatterns = []*regexp.Regexp{reTOCTOUFileExistsC}
	case rules.LangGo:
		checkPatterns = []*regexp.Regexp{reTOCTOUGoExists, reTOCTOUStatOpen}
	case rules.LangPython:
		checkPatterns = []*regexp.Regexp{reTOCTOUAccessOpen}
	default:
		return findings
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range checkPatterns {
			if m := re.FindString(line); m != "" {
				// Check if a file open follows within 10 lines
				if hasNearbyPattern(lines, i, 0, 10, reFileOpenAfter) {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "TOCTOU: file check followed by file operation",
						Description:   "A file existence/permission check is followed by a file open/read/write. Between the check and the use, another process could modify or replace the file (symlink attack, race condition).",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   truncate(m, 120),
						Suggestion:    "Use atomic file operations: open the file directly and handle errors (EAFP). In C, use O_CREAT|O_EXCL flags. In Go, use os.OpenFile with appropriate flags. In Python, use try/except around open().",
						CWEID:         "CWE-367",
						OWASPCategory: "A04:2021-Insecure Design",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"race-condition", "toctou", "file-operation"},
					})
					break
				}
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-002: Check-then-act without locking
// ---------------------------------------------------------------------------

type CheckThenAct struct{}

func (r *CheckThenAct) ID() string                     { return "BATOU-RACE-002" }
func (r *CheckThenAct) Name() string                   { return "CheckThenAct" }
func (r *CheckThenAct) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CheckThenAct) Description() string {
	return "Detects check-then-act patterns on shared data structures without proper synchronization, which can lead to race conditions."
}
func (r *CheckThenAct) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJava, rules.LangPython, rules.LangCSharp, rules.LangJavaScript, rules.LangTypeScript, rules.LangRuby}
}

func (r *CheckThenAct) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reCheckThenActMap, reCheckThenActNull} {
			if m := re.FindString(line); m != "" {
				// Check for locking/synchronization nearby
				if hasNearbyPattern(lines, i, 10, 0, reLockNearby) {
					continue
				}
				// Only flag if there is concurrent access evidence
				if ctx.Language == rules.LangGo {
					if !hasNearbyPattern(lines, i, 30, 30, reGoGoroutineWrite) {
						continue
					}
				}
				if ctx.Language == rules.LangJava || ctx.Language == rules.LangCSharp {
					if !hasNearbyPattern(lines, i, 50, 50, reJavaThreadStart) {
						continue
					}
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Check-then-act without synchronization",
					Description:   "A check-then-act pattern on shared data is performed without proper locking. Between the check and the action, another thread/goroutine can modify the shared state, causing inconsistent behavior.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Protect the check-then-act sequence with a mutex/lock, use atomic operations, or use concurrent-safe data structures (sync.Map in Go, ConcurrentHashMap in Java).",
					CWEID:         "CWE-362",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"race-condition", "check-then-act", "concurrency"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-003: Race condition in balance/counter update
// ---------------------------------------------------------------------------

type BalanceRace struct{}

func (r *BalanceRace) ID() string                     { return "BATOU-RACE-003" }
func (r *BalanceRace) Name() string                   { return "BalanceRace" }
func (r *BalanceRace) DefaultSeverity() rules.Severity { return rules.High }
func (r *BalanceRace) Description() string {
	return "Detects non-atomic read-then-update patterns on financial balances, counters, or inventory, which can lead to race conditions and double-spending."
}
func (r *BalanceRace) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *BalanceRace) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reBalanceUpdate, reBalanceRead} {
			if m := re.FindString(line); m != "" {
				// Skip if atomic/transactional operation is used
				if hasNearbyPattern(lines, i, 10, 10, reAtomicOp) {
					continue
				}
				if hasNearbyPattern(lines, i, 10, 0, reLockNearby) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Race condition in balance/counter update",
					Description:   "A balance, counter, or inventory value is read and then updated in separate operations without proper synchronization. Concurrent requests can cause double-spending, overdraft, or inventory underselling.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use atomic database operations (UPDATE ... SET balance = balance - amount WHERE balance >= amount), optimistic locking with version columns, or database transactions with SELECT ... FOR UPDATE.",
					CWEID:         "CWE-362",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"race-condition", "balance", "double-spend", "toctou"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-004: Double-checked locking anti-pattern
// ---------------------------------------------------------------------------

type DoubleCheckedLocking struct{}

func (r *DoubleCheckedLocking) ID() string                     { return "BATOU-RACE-004" }
func (r *DoubleCheckedLocking) Name() string                   { return "DoubleCheckedLocking" }
func (r *DoubleCheckedLocking) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DoubleCheckedLocking) Description() string {
	return "Detects the double-checked locking pattern without volatile/atomic guarantees, which is broken in Java (pre-1.5 memory model) and C++ without memory fences."
}
func (r *DoubleCheckedLocking) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangCPP, rules.LangCSharp}
}

func (r *DoubleCheckedLocking) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reDoubleCheckLock.MatchString(line) {
			// Look for synchronized/lock within next 5 lines, then another null check
			if hasNearbyPattern(lines, i, 0, 5, reSyncBlock) {
				innerStart := i + 1
				innerEnd := i + 10
				if innerEnd > len(lines) {
					innerEnd = len(lines)
				}
				for j := innerStart; j < innerEnd; j++ {
					if reDoubleCheckInner.MatchString(lines[j]) {
						// Found double-checked locking, check if volatile is used
						if hasNearbyPattern(lines, i, 20, 0, reVolatile) || hasNearbyPattern(lines, i, 20, 0, reLazySafe) {
							continue
						}
						findings = append(findings, rules.Finding{
							RuleID:        r.ID(),
							Severity:      r.DefaultSeverity(),
							SeverityLabel: r.DefaultSeverity().String(),
							Title:         "Double-checked locking without volatile/atomic",
							Description:   "Double-checked locking pattern detected without volatile keyword or memory barriers. Without volatile, the JVM/compiler may reorder instructions, causing a thread to see a partially constructed object.",
							FilePath:      ctx.FilePath,
							LineNumber:    i + 1,
							MatchedText:   truncate(trimmed, 120),
							Suggestion:    "In Java, declare the instance field as 'volatile'. In C++, use std::atomic with memory_order_acquire/release. Better yet, use the Initialization-on-demand holder idiom (Java), std::call_once (C++), or Lazy<T> (C#).",
							CWEID:         "CWE-609",
							OWASPCategory: "A04:2021-Insecure Design",
							Language:      ctx.Language,
							Confidence:    "medium",
							Tags:          []string{"race-condition", "double-checked-locking", "singleton"},
						})
						break
					}
				}
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-005: Signal handler with non-reentrant function
// ---------------------------------------------------------------------------

type SignalHandlerRace struct{}

func (r *SignalHandlerRace) ID() string                     { return "BATOU-RACE-005" }
func (r *SignalHandlerRace) Name() string                   { return "SignalHandlerRace" }
func (r *SignalHandlerRace) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SignalHandlerRace) Description() string {
	return "Detects signal handlers that call non-reentrant functions (printf, malloc, free, etc.), which can cause undefined behavior if the signal interrupts the same function."
}
func (r *SignalHandlerRace) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *SignalHandlerRace) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Find signal handler registrations and check the handler functions
	inSignalHandler := false
	handlerDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Detect signal handler registration with inline function
		if reSignalHandler.MatchString(line) {
			inSignalHandler = true
			handlerDepth = 0
		}

		if inSignalHandler {
			handlerDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if m := reNonReentrantFunc.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Signal handler calls non-reentrant function",
					Description:   "A non-reentrant function is called inside or near a signal handler. If the signal interrupts the same function in the main program, it causes undefined behavior (deadlocks, memory corruption, crashes).",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Only use async-signal-safe functions in signal handlers (write(), _exit(), signal()). Set a volatile sig_atomic_t flag in the handler and check it in the main loop. See signal-safety(7) for the full list.",
					CWEID:         "CWE-479",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"race-condition", "signal-handler", "reentrant"},
				})
			}
			if handlerDepth <= 0 && strings.Contains(line, "}") {
				inSignalHandler = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-006: Shared mutable state without synchronization
// ---------------------------------------------------------------------------

type SharedMutableState struct{}

func (r *SharedMutableState) ID() string                     { return "BATOU-RACE-006" }
func (r *SharedMutableState) Name() string                   { return "SharedMutableState" }
func (r *SharedMutableState) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SharedMutableState) Description() string {
	return "Detects goroutine or thread launches that access shared mutable state without visible synchronization mechanisms."
}
func (r *SharedMutableState) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJava}
}

func (r *SharedMutableState) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	switch ctx.Language {
	case rules.LangGo:
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if m := reGoGoroutineWrite.FindString(line); m != "" {
				// Check if any sync mechanism exists in the surrounding context
				if hasNearbyPattern(lines, i, 20, 20, reGoSyncMechanism) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Goroutine accessing shared state without synchronization",
					Description:   "A goroutine is launched without visible synchronization (mutex, channel, sync.Map). If the goroutine reads or writes shared variables, this is a data race.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use sync.Mutex/sync.RWMutex for shared state, channels for communication, sync.Map for concurrent maps, or atomic operations for counters. Run with 'go test -race' to detect races.",
					CWEID:         "CWE-362",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"race-condition", "goroutine", "data-race"},
				})
			}
		}
	case rules.LangJava:
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if m := reJavaThreadStart.FindString(line); m != "" {
				if hasNearbyPattern(lines, i, 20, 20, reLockNearby) || hasNearbyPattern(lines, i, 20, 20, reVolatile) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Thread accessing shared state without synchronization",
					Description:   "A thread is launched without visible synchronization (synchronized, volatile, locks). If the thread reads or writes shared fields, this is a data race with undefined behavior under the Java Memory Model.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use synchronized blocks, volatile fields, java.util.concurrent locks, or concurrent collections. Prefer higher-level abstractions like CompletableFuture or ExecutorService with proper synchronization.",
					CWEID:         "CWE-362",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"race-condition", "thread", "data-race", "java"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-007: Non-atomic read-modify-write
// ---------------------------------------------------------------------------

type NonAtomicRMW struct{}

func (r *NonAtomicRMW) ID() string                     { return "BATOU-RACE-007" }
func (r *NonAtomicRMW) Name() string                   { return "NonAtomicRMW" }
func (r *NonAtomicRMW) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NonAtomicRMW) Description() string {
	return "Detects non-atomic read-modify-write operations (+=, -=, ++, --) on shared variables in concurrent contexts, which can lose updates."
}
func (r *NonAtomicRMW) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJava, rules.LangPython, rules.LangCSharp, rules.LangC, rules.LangCPP}
}

func (r *NonAtomicRMW) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Only flag if concurrency constructs are present in the file
	hasConcurrency := false
	for _, line := range lines {
		if reGoGoroutineWrite.MatchString(line) || reJavaThreadStart.MatchString(line) || reSyncBlock.MatchString(line) {
			hasConcurrency = true
			break
		}
	}
	if !hasConcurrency {
		return findings
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reReadModifyWrite, reReadModifyWriteExplicit} {
			if m := re.FindString(line); m != "" {
				// Check for atomic operations or locks nearby
				if hasNearbyPattern(lines, i, 5, 0, reAtomicOrLock) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Non-atomic read-modify-write in concurrent context",
					Description:   "A compound assignment (+=, -=, ++, --) or explicit read-modify-write is used in a file with concurrency constructs. These operations are not atomic and can lose updates under concurrent access.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use atomic operations (atomic.AddInt64 in Go, AtomicInteger in Java, Interlocked.Add in C#), or protect the read-modify-write with a mutex/lock.",
					CWEID:         "CWE-362",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"race-condition", "non-atomic", "read-modify-write"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RACE-008: Race in lazy initialization singleton
// ---------------------------------------------------------------------------

type LazyInitRace struct{}

func (r *LazyInitRace) ID() string                     { return "BATOU-RACE-008" }
func (r *LazyInitRace) Name() string                   { return "LazyInitRace" }
func (r *LazyInitRace) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LazyInitRace) Description() string {
	return "Detects unsafe lazy initialization of singletons without proper synchronization, which can result in multiple instances being created."
}
func (r *LazyInitRace) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangCSharp}
}

func (r *LazyInitRace) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	switch ctx.Language {
	case rules.LangJava:
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if reLazyInitJava.MatchString(line) {
				// Check for null check followed by creation without sync
				if hasNearbyPattern(lines, i, 0, 20, reLazyInitCheck) {
					if hasNearbyPattern(lines, i, 5, 0, reLazySafe) {
						continue
					}
					if hasNearbyPattern(lines, i, 0, 20, reSyncBlock) {
						continue
					}
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "Unsafe lazy initialization of singleton",
						Description:   "Singleton instance is lazily initialized with a null check but without synchronization. Multiple threads can create separate instances, violating the singleton contract and potentially causing subtle bugs.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   truncate(trimmed, 120),
						Suggestion:    "Use the Initialization-on-demand holder idiom, an enum singleton, or declare the field volatile with double-checked locking. In Java 5+, volatile guarantees happen-before semantics.",
						CWEID:         "CWE-609",
						OWASPCategory: "A04:2021-Insecure Design",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"race-condition", "singleton", "lazy-init"},
					})
				}
			}
		}
	case rules.LangCSharp:
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if reLazyInitCS.MatchString(line) {
				if hasNearbyPattern(lines, i, 0, 20, reLazyInitCSCheck) {
					if hasNearbyPattern(lines, i, 5, 0, reLazySafe) {
						continue
					}
					if hasNearbyPattern(lines, i, 0, 20, reSyncBlock) {
						continue
					}
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "Unsafe lazy initialization of singleton",
						Description:   "Singleton instance is lazily initialized without proper thread safety. Multiple threads can race to create the instance, resulting in multiple instances or partially constructed objects.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   truncate(trimmed, 120),
						Suggestion:    "Use Lazy<T> for thread-safe lazy initialization, or use Interlocked.CompareExchange for lock-free initialization. Alternatively, use a static initializer which is guaranteed to be thread-safe.",
						CWEID:         "CWE-609",
						OWASPCategory: "A04:2021-Insecure Design",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"race-condition", "singleton", "lazy-init", "csharp"},
					})
				}
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&TOCTOU{})
	rules.Register(&CheckThenAct{})
	rules.Register(&BalanceRace{})
	rules.Register(&DoubleCheckedLocking{})
	rules.Register(&SignalHandlerRace{})
	rules.Register(&SharedMutableState{})
	rules.Register(&NonAtomicRMW{})
	rules.Register(&LazyInitRace{})
}
