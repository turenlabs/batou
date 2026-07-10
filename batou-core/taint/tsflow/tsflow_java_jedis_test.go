package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Jedis (Redis) read sources — second-order taint tests.
//
// Java's catalog already has Jedis SINKS (java.jedis.eval, java.lettuce.dispatch)
// but no Jedis SOURCES. Redis is routinely used as a cache, session store, and
// queue for attacker-influenced data. Reading values back without sanitization
// and feeding them into SQL/exec/response writers is a real second-order
// injection path that goes undetected without source coverage.
//
// All tests use the canonical receiver name `jedis`, which is what redis.io's
// Jedis docs and the existing java.jedis.eval sink pattern use. The tsflow
// matcher matches `ObjectType: "Jedis"` against receivers `jedis`/`j`/`je`
// via the prefix-abbreviation heuristic in matcher.go:330.

// --- Jedis.get(key) → SQL injection (CWE-89) ---

func TestJava_Jedis_Get_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;

public class UserCache {
    private Connection conn;
    private Jedis jedis;

    public void process(String userId) throws Exception {
        String displayName = jedis.get("user:" + userId + ":name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE name = '" + displayName + "'");
    }
}
`
	flows := Analyze(code, "/app/UserCache.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.get -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.mget(keys...) → command injection (CWE-78) ---

func TestJava_Jedis_Mget_CommandInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.util.List;

public class CommandRunner {
    private Jedis jedis;

    public void runQueued() throws Exception {
        List<String> commands = jedis.mget("cmd:1", "cmd:2");
        String cmd = commands.get(0);
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/CommandRunner.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Jedis.mget -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hget(key, field) → SQL injection (CWE-89) ---

func TestJava_Jedis_Hget_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;

public class HashCache {
    private Connection conn;
    private Jedis jedis;

    public void lookup(String userId) throws Exception {
        String role = jedis.hget("roles", userId);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM permissions WHERE role = '" + role + "'");
    }
}
`
	flows := Analyze(code, "/app/HashCache.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hget -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hgetAll(key) → SQL injection (CWE-89) ---

func TestJava_Jedis_HgetAll_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.Map;

public class FullHashLoad {
    private Connection conn;
    private Jedis jedis;

    public void load(String key) throws Exception {
        Map<String, String> fields = jedis.hgetAll(key);
        String filter = fields.get("filter");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM rows WHERE val = '" + filter + "'");
    }
}
`
	flows := Analyze(code, "/app/FullHashLoad.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hgetAll -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hmget(key, fields...) → SQL injection (CWE-89) ---

func TestJava_Jedis_Hmget_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.List;

public class MultiField {
    private Connection conn;
    private Jedis jedis;

    public void load(String key) throws Exception {
        List<String> values = jedis.hmget(key, "f1", "f2");
        String first = values.get(0);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE c = '" + first + "'");
    }
}
`
	flows := Analyze(code, "/app/MultiField.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hmget -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hkeys(key) → SQL injection (CWE-89) ---
// Uses direct concatenation of the tainted Set rather than chained
// iterator().next() — the walker propagates taint through `+` concatenation
// of tainted values via implicit toString().

func TestJava_Jedis_Hkeys_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.Set;

public class KeyEnumerator {
    private Connection conn;
    private Jedis jedis;

    public void process(String hashName) throws Exception {
        Set<String> keys = jedis.hkeys(hashName);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM hashfields WHERE name IN ('" + keys + "')");
    }
}
`
	flows := Analyze(code, "/app/KeyEnumerator.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hkeys -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hvals(key) → SQL injection (CWE-89) ---

func TestJava_Jedis_Hvals_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.List;

public class ValueLoad {
    private Connection conn;
    private Jedis jedis;

    public void load(String key) throws Exception {
        List<String> vals = jedis.hvals(key);
        String firstVal = vals.get(0);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE c = '" + firstVal + "'");
    }
}
`
	flows := Analyze(code, "/app/ValueLoad.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hvals -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.lrange(key, start, end) → SQL injection (CWE-89) ---

func TestJava_Jedis_Lrange_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.List;

public class QueueDrain {
    private Connection conn;
    private Jedis jedis;

    public void drain() throws Exception {
        List<String> items = jedis.lrange("queue", 0, -1);
        String first = items.get(0);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM jobs WHERE name = '" + first + "'");
    }
}
`
	flows := Analyze(code, "/app/QueueDrain.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.lrange -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.lindex(key, idx) → command injection (CWE-78) ---

func TestJava_Jedis_Lindex_CommandInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;

public class IndexedRead {
    private Jedis jedis;

    public void execItem() throws Exception {
        String item = jedis.lindex("queue", 0);
        Runtime.getRuntime().exec(item);
    }
}
`
	flows := Analyze(code, "/app/IndexedRead.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Jedis.lindex -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.lpop(key) → command injection (CWE-78) ---

func TestJava_Jedis_Lpop_CommandInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;

public class JobConsumer {
    private Jedis jedis;

    public void runNext() throws Exception {
        String job = jedis.lpop("jobs");
        Runtime.getRuntime().exec(job);
    }
}
`
	flows := Analyze(code, "/app/JobConsumer.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Jedis.lpop -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.smembers(key) → SQL injection (CWE-89) ---

func TestJava_Jedis_Smembers_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.Set;

public class TagFilter {
    private Connection conn;
    private Jedis jedis;

    public void filterByTag() throws Exception {
        Set<String> tags = jedis.smembers("user:1:tags");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM articles WHERE tag IN ('" + tags + "')");
    }
}
`
	flows := Analyze(code, "/app/TagFilter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.smembers -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.zrange(key, start, end) → SQL injection (CWE-89) ---

func TestJava_Jedis_Zrange_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.Set;

public class Leaderboard {
    private Connection conn;
    private Jedis jedis;

    public void topN() throws Exception {
        Set<String> top = jedis.zrange("leaderboard", 0, 9);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name IN ('" + top + "')");
    }
}
`
	flows := Analyze(code, "/app/Leaderboard.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.zrange -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.zrangeByScore(key, min, max) → SQL injection (CWE-89) ---

func TestJava_Jedis_ZrangeByScore_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;
import java.util.Set;

public class ScoreFilter {
    private Connection conn;
    private Jedis jedis;

    public void byScore() throws Exception {
        Set<String> matching = jedis.zrangeByScore("scores", 100, 200);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE name IN ('" + matching + "')");
    }
}
`
	flows := Analyze(code, "/app/ScoreFilter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.zrangeByScore -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative test: constant Redis key, constant return path → no flow ---
// Verifies the new sources don't fire on hardcoded reads. We construct a SQL
// query from a string literal (no taint involved) and confirm zero flows.

func TestJava_Jedis_NoFlow_ConstantQuery(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis;
import java.sql.*;

public class StaticQuery {
    private Connection conn;
    private Jedis jedis;

    public void run() throws Exception {
        String unused = jedis.get("config");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT 1 FROM dual");
    }
}
`
	flows := Analyze(code, "/app/StaticQuery.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQL flow for constant query: source=%s sink=%s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
