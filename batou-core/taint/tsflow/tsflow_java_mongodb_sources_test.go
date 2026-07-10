package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java MongoDB BSON Document + org.json read sources — second-order /
// parsed-input taint tests.
//
// Java's catalog already has MongoDB SINKS (java.mongodb.collection.find,
// .aggregate, .updateOne, ..., java.mongodb.document.parse) but had no
// MongoDB SOURCES, so attacker bytes stored in a collection on one request
// and read back later did not propagate taint. org.json (JSONObject /
// JSONArray) — one of the most-used JSON libraries in Java — had no source
// coverage at all even though Gson/Jackson/JAXB/SnakeYAML do.
//
// All fixtures use the canonical receiver names (`doc` for org.bson.Document,
// `json`/`jsonArray` for org.json) so the tsflow matcher's prefix-abbreviation
// heuristic (matcher.go:330) anchors them to the catalog ObjectType. The
// `private Connection conn;` field + `Statement stmt = conn.createStatement();`
// shape is the same one tsflow_java_jedis_test.go uses — `executeQuery(` does
// trip isWebHandlerFunc, but the handler methods take no parameters so nothing
// is auto-seeded; the only taint source is the document/JSON read under test.
// =========================================================================

func TestJava_MongoDocumentSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"java.mongodb.document.getstring",
		"java.mongodb.document.getlist",
		"java.mongodb.document.getembedded",
		"java.mongodb.document.tojson",
		"java.orgjson.jsonobject.getstring",
		"java.orgjson.jsonobject.optstring",
		"java.orgjson.jsonarray.getstring",
		"java.orgjson.jsonarray.optstring",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// ---------- org.bson.Document.getString(key) → SQL injection (CWE-89) ----------

func TestJava_MongoDocument_GetString_SQLInjection(t *testing.T) {
	code := `
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import java.sql.*;

public class ProfileRepo {
    private Connection conn;
    private MongoCollection<Document> col;

    public void render() throws Exception {
        Document doc = col.find(new Document("active", true)).first();
        String displayName = doc.getString("displayName");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE name = '" + displayName + "'");
    }
}
`
	flows := Analyze(code, "/app/ProfileRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Document.getString -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.bson.Document.getList(key, clazz) → command injection (CWE-78) ----------

func TestJava_MongoDocument_GetList_CommandInjection(t *testing.T) {
	code := `
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import java.util.List;

public class JobRepo {
    private MongoCollection<Document> col;

    public void runQueued() throws Exception {
        Document doc = col.find(new Document("status", "pending")).first();
        List<String> commands = doc.getList("commands", String.class);
        String cmd = commands.get(0);
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/JobRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Document.getList -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.bson.Document.getEmbedded(keys, clazz) → SQL injection (CWE-89) ----------

func TestJava_MongoDocument_GetEmbedded_SQLInjection(t *testing.T) {
	code := `
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import java.sql.*;
import java.util.Arrays;

public class SettingsRepo {
    private Connection conn;
    private MongoCollection<Document> col;

    public void load() throws Exception {
        Document doc = col.find(new Document("type", "settings")).first();
        String table = doc.getEmbedded(Arrays.asList("query", "table"), String.class);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM " + table);
    }
}
`
	flows := Analyze(code, "/app/SettingsRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Document.getEmbedded -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.bson.Document.toJson() → SQL injection (CWE-89) ----------

func TestJava_MongoDocument_ToJson_SQLInjection(t *testing.T) {
	code := `
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import java.sql.*;

public class AuditRepo {
    private Connection conn;
    private MongoCollection<Document> col;

    public void mirror() throws Exception {
        Document doc = col.find(new Document("kind", "audit")).first();
        String raw = doc.toJson();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("INSERT INTO audit_mirror(body) VALUES ('" + raw + "')");
    }
}
`
	flows := Analyze(code, "/app/AuditRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Document.toJson -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.json.JSONObject.getString(key) → SQL injection (CWE-89) ----------

func TestJava_OrgJson_JSONObjectGetString_SQLInjection(t *testing.T) {
	code := `
import org.json.JSONObject;
import java.sql.*;

public class WebhookHandler {
    private Connection conn;

    public void handle() throws Exception {
        JSONObject json = new JSONObject("{}");
        String name = json.getString("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM customers WHERE name = '" + name + "'");
    }
}
`
	flows := Analyze(code, "/app/WebhookHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JSONObject.getString -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.json.JSONObject.optString(key) → command injection (CWE-78) ----------

func TestJava_OrgJson_JSONObjectOptString_CommandInjection(t *testing.T) {
	code := `
import org.json.JSONObject;

public class TaskHandler {
    public void run() throws Exception {
        JSONObject json = new JSONObject("{}");
        String script = json.optString("script");
        Runtime.getRuntime().exec(script);
    }
}
`
	flows := Analyze(code, "/app/TaskHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JSONObject.optString -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.json.JSONArray.getString(index) → SQL injection (CWE-89) ----------

func TestJava_OrgJson_JSONArrayGetString_SQLInjection(t *testing.T) {
	code := `
import org.json.JSONArray;
import java.sql.*;

public class BulkHandler {
    private Connection conn;

    public void handle() throws Exception {
        JSONArray jsonArray = new JSONArray("[]");
        String first = jsonArray.getString(0);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM items WHERE sku = '" + first + "'");
    }
}
`
	flows := Analyze(code, "/app/BulkHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JSONArray.getString -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- org.json.JSONArray.optString(index) → SQL injection (CWE-89) ----------

func TestJava_OrgJson_JSONArrayOptString_SQLInjection(t *testing.T) {
	code := `
import org.json.JSONArray;
import java.sql.*;

public class FeedHandler {
    private Connection conn;

    public void handle() throws Exception {
        JSONArray jsonArray = new JSONArray("[]");
        String tag = jsonArray.optString(0);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM articles WHERE tag = '" + tag + "'");
    }
}
`
	flows := Analyze(code, "/app/FeedHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JSONArray.optString -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Negative: hardcoded reads + a string-literal query → no flow ----------

func TestJava_MongoDocumentSources_NoFlow_ConstantQuery(t *testing.T) {
	code := `
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import org.json.JSONObject;
import java.sql.*;

public class StaticReport {
    private Connection conn;
    private MongoCollection<Document> col;

    public void run() throws Exception {
        Document doc = col.find(new Document("k", "v")).first();
        String unused = doc.getString("label");
        JSONObject json = new JSONObject("{}");
        String alsoUnused = json.optString("label");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT 1 FROM dual");
    }
}
`
	flows := Analyze(code, "/app/StaticReport.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQL flow for constant query: source=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}
