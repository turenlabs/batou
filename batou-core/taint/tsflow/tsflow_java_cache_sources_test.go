package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// In-memory cache read sources — second-order taint tests.
//
// Java's catalog had Redis (Jedis) and MongoDB read sources for second-order
// taint, but none of the dominant JVM in-memory caching libraries: Guava
// Cache/LoadingCache, Caffeine (the default Spring Boot cache provider), JCache
// (javax.cache.Cache) and Ehcache 3. Attacker-influenced data written into one
// of these caches on one request and read back later flows into SQL/exec/
// response/deserialization sinks with no source coverage.
//
// Each positive test reads with a CONSTANT key (no tainted argument in scope and
// no method parameters), so the read value can only become tainted if the cache
// getter is registered as a source — this rules out the unknown-function
// arg→return propagation path and proves the new entries actually fire.
//
// getIfPresent / getAllPresent are matched with ObjectType "" (the method names
// are unique to Guava/Caffeine caches; java.util.Map has neither), so they fire
// on any receiver name. getUnchecked / getAll are scoped to ObjectType "Cache".

// --- Guava/Caffeine Cache.getIfPresent(key) → SQL injection (CWE-89) ---

func TestJava_Cache_GetIfPresent_SQLInjection(t *testing.T) {
	code := `
import com.github.benmanes.caffeine.cache.Cache;
import java.sql.*;

public class ProfileService {
    private Connection conn;
    private Cache<String, String> profileCache;

    public void render() throws Exception {
        String displayName = profileCache.getIfPresent("profile:welcome");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE name = '" + displayName + "'");
    }
}
`
	flows := Analyze(code, "/app/ProfileService.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Cache.getIfPresent -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Guava/Caffeine Cache.getAllPresent(keys) → command injection (CWE-78) ---

func TestJava_Cache_GetAllPresent_CommandInjection(t *testing.T) {
	code := `
import com.google.common.cache.Cache;
import java.util.*;

public class TaskRunner {
    private Cache<String, String> taskCache;

    public void runQueued() throws Exception {
        Map<String, String> tasks = taskCache.getAllPresent(Arrays.asList("task:1", "task:2"));
        String cmd = tasks.get("task:1");
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/TaskRunner.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Cache.getAllPresent -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Guava LoadingCache.getUnchecked(key) → SQL injection (CWE-89) ---

func TestJava_Cache_GetUnchecked_SQLInjection(t *testing.T) {
	code := `
import com.google.common.cache.LoadingCache;
import java.sql.*;

public class SettingsService {
    private Connection conn;
    private LoadingCache<String, String> cache;

    public void apply() throws Exception {
        String setting = cache.getUnchecked("settings:theme");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM themes WHERE key = '" + setting + "'");
    }
}
`
	flows := Analyze(code, "/app/SettingsService.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for LoadingCache.getUnchecked -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- JCache/Ehcache3 Cache.getAll(keys) → SSRF (CWE-918) ---

func TestJava_Cache_GetAll_SSRF(t *testing.T) {
	code := `
import javax.cache.Cache;
import java.net.*;
import java.util.*;

public class HookService {
    private Cache<String, String> cache;

    public void fire() throws Exception {
        Map<String, String> hooks = cache.getAll(new HashSet<>(Arrays.asList("hook:a")));
        String target = hooks.get("hook:a");
        URL url = new URL(target);
        url.openConnection();
    }
}
`
	flows := Analyze(code, "/app/HookService.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Cache.getAll -> URL.openConnection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative control: a constant value (no cache read) must NOT flow ---
// Proves the positive tests above are driven by the cache source entry and not
// by some pre-existing taint, and that a hardcoded value stays clean.

func TestJava_Cache_ConstantValue_NoFlow(t *testing.T) {
	code := `
import java.sql.*;

public class ReportService {
    private Connection conn;

    public void render() throws Exception {
        String label = "weekly-report";
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM reports WHERE label = '" + label + "'");
    }
}
`
	flows := Analyze(code, "/app/ReportService.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a hardcoded constant label")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative control: bare java.util.Map.get must NOT be treated as a cache
// source (proves we did not over-broaden — only the distinctive cache getters
// are registered, not generic Map.get). ---

func TestJava_Cache_PlainMapGet_NoFlow(t *testing.T) {
	code := `
import java.util.*;
import java.sql.*;

public class LookupService {
    private Connection conn;
    private Map<String, String> cache = new HashMap<>();

    public void render() throws Exception {
        String v = cache.get("static-key");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE x = '" + v + "'");
    }
}
`
	flows := Analyze(code, "/app/LookupService.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("plain Map.get must not be treated as a tainted cache source")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
