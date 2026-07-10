package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Java HTTP client SSRF sinks: JAX-RS Client, Retrofit, and extended
// Spring RestTemplate methods (CWE-918). These complement the existing
// java.spring.resttemplate (getForObject), java.apache.httpclient.*, and
// java.okhttp3.* sinks.

func TestJava_SSRF_JAXRSClient_Target(t *testing.T) {
	code := `
import javax.servlet.http.*;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("endpoint");
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(url);
        Response resp = target.request().get();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> Client.target()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_Retrofit_BaseUrl(t *testing.T) {
	code := `
import javax.servlet.http.*;
import retrofit2.Retrofit;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String baseUrl = request.getParameter("api");
        Retrofit.Builder builder = new Retrofit.Builder();
        builder.baseUrl(baseUrl);
        Retrofit retrofit = builder.build();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> Retrofit.Builder.baseUrl()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_RestTemplate_PostForObject(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        RestTemplate restTemplate = new RestTemplate();
        String result = restTemplate.postForObject(target, "{}", String.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> RestTemplate.postForObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_RestTemplate_Exchange(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpEntity;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> entity = new HttpEntity<>("body");
        restTemplate.exchange(target, HttpMethod.GET, entity, String.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> RestTemplate.exchange")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_RestTemplate_Delete(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;

public class Handler extends HttpServlet {
    public void doDelete(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.delete(target);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> RestTemplate.delete")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_RestTemplate_GetForEntity(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> result = restTemplate.getForEntity(target, String.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> RestTemplate.getForEntity")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_RestTemplate_Sanitized_Allowlist(t *testing.T) {
	// Sanity check: hardcoded URLs must NOT produce a flow.
	code := `
import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        RestTemplate restTemplate = new RestTemplate();
        String result = restTemplate.postForObject("https://api.example.com/status", "{}", String.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow when URL is a hardcoded constant")
	}
}
