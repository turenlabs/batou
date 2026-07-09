package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Protocol Buffers / gRPC server-side input sources (second-order / external).
//
// Java's catalog modeled the gRPC/protobuf *write* side and many messaging
// consumers (Kafka, RabbitMQ, JMS, Pulsar, Camel) but had NO source for the
// most fundamental JVM RPC input: a protobuf message decoded from untrusted
// wire bytes. Go already models this (go.proto.unmarshal, go.grpc.metadata);
// Java had a parity gap despite grpc-java + protobuf-java being the dominant
// RPC stack on the JVM.
//
// protobuf-java generated message classes expose static parseFrom() /
// parseDelimitedFrom() factories that decode attacker-supplied bytes into a
// typed message; the decoded fields reach SQL/exec/SSRF sinks through the
// generated getters. grpc-java's io.grpc.Metadata carries client-set custom
// headers that are fully attacker-controlled.
//
// Each positive test decodes from a CONSTANT / untainted field (no tainted
// argument in scope) so the value can only become tainted if the new source
// entry fires — this rules out unknown-function arg->return propagation and
// proves the entry works. Sinks use executeUpdate (NOT executeQuery) so the
// function text contains no "Query(" substring, which would otherwise auto-taint
// the method parameters via the web-handler heuristic and make the test vacuous.

// --- protobuf parseFrom(bytes) -> getter -> SQL injection (CWE-89) ---

func TestJava_Protobuf_ParseFrom_SQLInjection(t *testing.T) {
	code := `
import com.acme.proto.OrderRequest;
import java.sql.*;

public class OrderStore {
    private Connection conn;
    private byte[] stored;

    public void persist() throws Exception {
        OrderRequest req = OrderRequest.parseFrom(stored);
        String note = req.getNote();
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("UPDATE orders SET note = '" + note + "'");
    }
}
`
	flows := Analyze(code, "/app/OrderStore.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for protobuf parseFrom -> getter -> executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- protobuf parseDelimitedFrom(stream) -> getter -> command injection (CWE-78) ---

func TestJava_Protobuf_ParseDelimitedFrom_CommandInjection(t *testing.T) {
	code := `
import com.acme.proto.JobRequest;
import java.io.InputStream;

public class JobRunner {
    private InputStream in;

    public void run() throws Exception {
        JobRequest job = JobRequest.parseDelimitedFrom(in);
        String cmd = job.getCommand();
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/JobRunner.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for protobuf parseDelimitedFrom -> getter -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- grpc-java Metadata.get(key) -> SQL injection (CWE-89) ---

func TestJava_Grpc_MetadataGet_SQLInjection(t *testing.T) {
	code := `
import io.grpc.Metadata;
import java.sql.*;

public class TenantInterceptor {
    private Connection conn;

    public void audit(Metadata metadata) throws Exception {
        String tenant = metadata.get(Metadata.Key.of("x-tenant", Metadata.ASCII_STRING_MARSHALLER));
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("UPDATE audit SET tenant = '" + tenant + "'");
    }
}
`
	flows := Analyze(code, "/app/TenantInterceptor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for io.grpc.Metadata.get -> executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative control: a constant value through the same sink shape must NOT
// produce a flow (proves the harness isn't spuriously flagging the sink). ---

func TestJava_Protobuf_NoSource_NoFlow(t *testing.T) {
	code := `
import java.sql.*;

public class CleanStore {
    private Connection conn;

    public void persist() throws Exception {
        String note = "fixed-note";
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("UPDATE orders SET note = '" + note + "'");
    }
}
`
	flows := Analyze(code, "/app/CleanStore.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("unexpected SQL flow for a constant note (no protobuf/gRPC source present)")
	}
}

// --- Catalog registration ---

func TestJava_ProtobufGrpcSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"java.protobuf.parsefrom",
		"java.protobuf.parsedelimitedfrom",
		"java.grpc.metadata.get",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}
