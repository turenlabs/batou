package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Apache Camel ProducerTemplate SSRF sinks added to java_sinks.go.
//
// Camel routes a payload to an endpoint identified by a URI string. The URI
// scheme picks the transport: http:/https:/jetty:/netty4-http: are HTTP
// requests (SSRF), exec: shells out (command injection), jdbc: opens a
// database connection (SQL injection), bean:/class: invoke arbitrary Java,
// file:/ftp: read or write files. Tainted input flowing into args[0] of any
// send/request method therefore lets an attacker pick the protocol.
//
// Sources are existing java.camel.exchange.* / java.camel.message.* sources
// from PR #537 (Camel cycle #696). Tests use the java.camel.exchange.getproperty
// pattern (returns Object) flowed via string concatenation into the URI arg —
// this is the canonical SSRF surface in Camel applications. ObjectType
// "ProducerTemplate" matches receiver names "producerTemplate" and "producer"
// via tsflow's prefix-abbreviation heuristic in matcher.go.

func TestJava_CamelProducerSendBodySSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class SendRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        producerTemplate.sendBody("http://" + dest, "payload");
    }
}
`
	flows := Analyze(code, "/app/SendRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.sendBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerSendBodyAndHeaderSSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class SendHdrRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        producerTemplate.sendBodyAndHeader("http://" + dest, "payload", "Content-Type", "text/plain");
    }
}
`
	flows := Analyze(code, "/app/SendHdrRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.sendBodyAndHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerSendBodyAndHeadersSSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;
import java.util.Map;
import java.util.HashMap;

public class SendHdrsRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        Map<String, Object> hdrs = new HashMap<>();
        producerTemplate.sendBodyAndHeaders("http://" + dest, "payload", hdrs);
    }
}
`
	flows := Analyze(code, "/app/SendHdrsRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.sendBodyAndHeaders")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerSendBodyAndPropertySSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class SendPropRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        producerTemplate.sendBodyAndProperty("http://" + dest, "payload", "CamelTraceId", "x");
    }
}
`
	flows := Analyze(code, "/app/SendPropRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.sendBodyAndProperty")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerRequestBodySSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class RequestRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        Object reply = producerTemplate.requestBody("http://" + dest, "payload");
    }
}
`
	flows := Analyze(code, "/app/RequestRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.requestBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerRequestBodyAndHeaderSSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class RequestHdrRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        producerTemplate.requestBodyAndHeader("http://" + dest, "payload", "X-Tenant", "acme");
    }
}
`
	flows := Analyze(code, "/app/RequestHdrRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.requestBodyAndHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerRequestBodyAndHeadersSSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;
import java.util.Map;
import java.util.HashMap;

public class RequestHdrsRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        Map<String, Object> hdrs = new HashMap<>();
        producerTemplate.requestBodyAndHeaders("http://" + dest, "payload", hdrs);
    }
}
`
	flows := Analyze(code, "/app/RequestHdrsRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.requestBodyAndHeaders")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerAsyncSendBodySSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class AsyncSendRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        producerTemplate.asyncSendBody("http://" + dest, "payload");
    }
}
`
	flows := Analyze(code, "/app/AsyncSendRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.asyncSendBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_CamelProducerAsyncRequestBodySSRF(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.Processor;

public class AsyncRequestRouter implements Processor {
    private ProducerTemplate producerTemplate;

    public void process(Exchange exchange) throws Exception {
        Object dest = exchange.getProperty("destUri");
        Object fut = producerTemplate.asyncRequestBody("http://" + dest, "payload");
    }
}
`
	flows := Analyze(code, "/app/AsyncRequestRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Camel Exchange.getProperty -> producerTemplate.asyncRequestBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: a constant endpoint URI must NOT produce a user-input SSRF
// flow. This proves the new ProducerTemplate sinks don't introduce over-broad
// matching when the first argument is a literal.
func TestJava_CamelProducerNoFlowOnConstantUri(t *testing.T) {
	code := `
import org.apache.camel.ProducerTemplate;

public class ConstRouter {
    private ProducerTemplate producerTemplate;

    public void run() throws Exception {
        String safe = "direct:internal";
        producerTemplate.sendBody(safe, "payload");
    }
}
`
	flows := Analyze(code, "/app/ConstRouter.java", rules.LangJava)
	for _, f := range flows {
		if f.Source.Category == taint.SrcUserInput && f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("unexpected user-input SSRF flow on constant URI: source=%s sink=%s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
