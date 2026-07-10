package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Java WebSocket / Reactive Messaging / Netty inbound sources.
//
// These tests cover three families of attacker-controlled entry points that
// the Java taint catalog was missing before this cycle:
//
//   1. Spring Messaging Message<?>.getPayload() — the lower-level interface
//      that @MessageMapping STOMP handlers, Spring Cloud Stream Function beans,
//      and Spring Integration channel interceptors all resolve to.
//   2. Spring WebFlux ServerHttpRequest — used by WebFilter / HandlerFunction /
//      HandshakeWebSocketService code instead of the @-annotation surface.
//   3. JSR-356 jakarta.websocket.Session — the standard WebSocket API used by
//      Tomcat, Tyrus, Jetty, Undertow @ServerEndpoint methods.
//   4. Netty FullHttpRequest — raw uri()/headers()/content() inside custom
//      ChannelInboundHandlerAdapter / SimpleChannelInboundHandler subclasses.
//
// Tests use intermediate-variable assignment shapes (rather than chained
// receiver-call casts) because the tsflow walker propagates taint through
// assignments cleanly but does not see through casts that wrap a fresh source
// call (documented gotcha from earlier Java cycles).

// --- Spring Messaging Message.getPayload() → SQL injection ---

func TestJava_SpringMessage_GetPayload_SQLInjection(t *testing.T) {
	code := `
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import java.sql.*;

public class ChatHandler {
    private Connection conn;

    @MessageMapping("/chat")
    public void onChat(Message<String> message) throws Exception {
        Object payload = message.getPayload();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM rooms WHERE name = '" + payload + "'");
    }
}
`
	flows := Analyze(code, "/app/ChatHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Spring Message.getPayload() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring WebFlux ServerHttpRequest.getQueryParams() → command injection ---

func TestJava_SpringServerHttpRequest_QueryParams_CommandInjection(t *testing.T) {
	code := `
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.WebFilter;
import org.springframework.util.MultiValueMap;

public class CmdFilter {
    public void filter(ServerHttpRequest request) throws Exception {
        MultiValueMap<String, String> params = request.getQueryParams();
        Object cmd = params.getFirst("cmd");
        Runtime.getRuntime().exec(cmd.toString());
    }
}
`
	flows := Analyze(code, "/app/CmdFilter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ServerHttpRequest.getQueryParams() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring WebFlux ServerHttpRequest.getURI() → SSRF ---

func TestJava_SpringServerHttpRequest_GetURI_SSRF(t *testing.T) {
	code := `
import org.springframework.http.server.reactive.ServerHttpRequest;
import java.net.URL;
import java.net.URLConnection;

public class ProxyFilter {
    public void filter(ServerHttpRequest request) throws Exception {
        Object uri = request.getURI();
        URL u = new URL(uri.toString());
        URLConnection conn = u.openConnection();
        conn.connect();
    }
}
`
	flows := Analyze(code, "/app/ProxyFilter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerHttpRequest.getURI() -> URL.openConnection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring WebFlux ServerHttpRequest.getPath() → path traversal ---

func TestJava_SpringServerHttpRequest_GetPath_PathTraversal(t *testing.T) {
	code := `
import org.springframework.http.server.reactive.ServerHttpRequest;
import java.io.File;
import java.io.FileInputStream;

public class StaticFilter {
    public void filter(ServerHttpRequest request) throws Exception {
        Object path = request.getPath();
        File f = new File("/var/www/" + path);
        FileInputStream fis = new FileInputStream(f);
        fis.close();
    }
}
`
	flows := Analyze(code, "/app/StaticFilter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for ServerHttpRequest.getPath() -> FileInputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JSR-356 Session.getRequestParameterMap() → SQL injection ---

func TestJava_WebSocketSession_GetRequestParameterMap_SQLInjection(t *testing.T) {
	code := `
import jakarta.websocket.Session;
import jakarta.websocket.OnOpen;
import jakarta.websocket.server.ServerEndpoint;
import java.sql.*;
import java.util.List;
import java.util.Map;

@ServerEndpoint("/ws/{room}")
public class ChatEndpoint {
    private Connection conn;

    @OnOpen
    public void onOpen(Session session) throws Exception {
        Map<String, List<String>> params = session.getRequestParameterMap();
        List<String> tokens = params.get("token");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM sessions WHERE token = '" + tokens.get(0) + "'");
    }
}
`
	flows := Analyze(code, "/app/ChatEndpoint.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Session.getRequestParameterMap() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JSR-356 Session.getQueryString() → command injection ---

func TestJava_WebSocketSession_GetQueryString_CommandInjection(t *testing.T) {
	code := `
import jakarta.websocket.Session;
import jakarta.websocket.OnOpen;
import jakarta.websocket.server.ServerEndpoint;

@ServerEndpoint("/admin")
public class AdminEndpoint {
    @OnOpen
    public void onOpen(Session session) throws Exception {
        Object query = session.getQueryString();
        Runtime.getRuntime().exec("echo " + query);
    }
}
`
	flows := Analyze(code, "/app/AdminEndpoint.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Session.getQueryString() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JSR-356 Session.getPathParameters() → path traversal ---

func TestJava_WebSocketSession_GetPathParameters_PathTraversal(t *testing.T) {
	code := `
import jakarta.websocket.Session;
import jakarta.websocket.OnOpen;
import jakarta.websocket.server.ServerEndpoint;
import java.io.File;
import java.io.FileInputStream;
import java.util.Map;

@ServerEndpoint("/files/{name}")
public class FileEndpoint {
    @OnOpen
    public void onOpen(Session session) throws Exception {
        Map<String, String> path = session.getPathParameters();
        Object name = path.get("name");
        File f = new File("/srv/upload/" + name);
        FileInputStream fis = new FileInputStream(f);
        fis.close();
    }
}
`
	flows := Analyze(code, "/app/FileEndpoint.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for Session.getPathParameters() -> FileInputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JSR-356 Session.getUserProperties() → SQL injection ---

func TestJava_WebSocketSession_GetUserProperties_SQLInjection(t *testing.T) {
	code := `
import jakarta.websocket.Session;
import jakarta.websocket.OnMessage;
import jakarta.websocket.server.ServerEndpoint;
import java.sql.*;
import java.util.Map;

@ServerEndpoint("/notify")
public class NotifyEndpoint {
    private Connection conn;

    @OnMessage
    public void onMessage(Session session, String msg) throws Exception {
        Map<String, Object> props = session.getUserProperties();
        Object userId = props.get("userId");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM notifications WHERE user_id = '" + userId + "'");
    }
}
`
	flows := Analyze(code, "/app/NotifyEndpoint.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Session.getUserProperties() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Netty FullHttpRequest.uri() → SSRF ---

func TestJava_NettyFullHttpRequest_URI_SSRF(t *testing.T) {
	code := `
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import java.net.URL;
import java.net.URLConnection;

public class ProxyHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
        Object uri = request.uri();
        URL u = new URL(uri.toString());
        URLConnection conn = u.openConnection();
        conn.connect();
    }
}
`
	flows := Analyze(code, "/app/ProxyHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Netty FullHttpRequest.uri() -> URL.openConnection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Netty FullHttpRequest.headers() → SQL injection ---

func TestJava_NettyFullHttpRequest_Headers_SQLInjection(t *testing.T) {
	code := `
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import java.sql.*;

public class TenantHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private Connection conn;

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
        HttpHeaders headers = request.headers();
        Object tenant = headers.get("X-Tenant");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE tenant = '" + tenant + "'");
    }
}
`
	flows := Analyze(code, "/app/TenantHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Netty FullHttpRequest.headers() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Netty FullHttpRequest.content() → command injection ---

func TestJava_NettyFullHttpRequest_Content_CommandInjection(t *testing.T) {
	code := `
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.FullHttpRequest;

public class ExecHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
        Object body = request.content();
        Runtime.getRuntime().exec(body.toString());
    }
}
`
	flows := Analyze(code, "/app/ExecHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Netty FullHttpRequest.content() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative test: hardcoded payload should NOT trigger over-broad patterns ---

func TestJava_WebSocketSession_HardcodedQuery_NoFalsePositive(t *testing.T) {
	code := `
import java.sql.*;

public class SafeEndpoint {
    private Connection conn;

    public void safeQuery() throws Exception {
        String tenant = "PRODUCTION";
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE tenant = '" + tenant + "'");
    }
}
`
	flows := Analyze(code, "/app/SafeEndpoint.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow for hardcoded constant payload")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (source ID: %s)", f.Source.Category, f.Sink.Category, f.Source.ID)
		}
	}
}
