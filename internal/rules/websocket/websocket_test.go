package websocket

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-WS-001: WebSocket without origin validation ---

func TestWS001_CheckOriginTrue_Go(t *testing.T) {
	content := `upgrader := websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}
`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-WS-001")
}

func TestWS001_OriginWildcard_JS(t *testing.T) {
	content := `const wss = new WebSocketServer({ allowedOrigins: ["*"] });`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-001")
}

func TestWS001_NoOriginCheck_JS(t *testing.T) {
	content := `const wss = new WebSocketServer({ port: 8080 });
wss.on("connection", (ws) => {
    ws.send("hello");
});
`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-001")
}

func TestWS001_Safe_WithOriginCheck(t *testing.T) {
	content := `const wss = new WebSocketServer({ verifyOrigin: true, port: 8080 });
function checkOrigin(origin) { return origin === "https://example.com"; }
wss.on("connection", (ws) => { ws.send("hello"); });
`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-001")
}

// --- BATOU-WS-002: WebSocket without authentication ---

func TestWS002_NoAuth_JS(t *testing.T) {
	content := `.on("connection", (ws) => {
    ws.send("Welcome!");
    ws.on("message", (data) => {
        console.log(data);
    });
});
`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-002")
}

func TestWS002_NoAuth_Go(t *testing.T) {
	content := `func websocketHandler(w http.ResponseWriter, r *http.Request) {
    conn, _ := upgrader.Upgrade(w, r, nil)
    for {
        _, msg, _ := conn.ReadMessage()
        conn.WriteMessage(1, msg)
    }
}
`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-WS-002")
}

func TestWS002_Safe_WithAuth(t *testing.T) {
	content := `.on("connection", (ws) => {
    if (!req.user || !isAuthenticated(req)) {
        ws.close();
        return;
    }
    ws.send("Welcome!");
});
`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-002")
}

// --- BATOU-WS-003: WebSocket message used in eval/exec ---

func TestWS003_MsgToEval_JS(t *testing.T) {
	content := `eval(message);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-003")
}

func TestWS003_MsgToExec_Python(t *testing.T) {
	content := `def on_message(ws, msg):
    exec(msg)
`
	result := testutil.ScanContent(t, "/app/handler.py", content)
	testutil.MustFindRule(t, result, "BATOU-WS-003")
}

func TestWS003_Safe_JSONParse(t *testing.T) {
	content := `const data = JSON.parse(message);
switch (data.type) {
    case "ping": ws.send("pong"); break;
}
`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-003")
}

// --- BATOU-WS-005: WebSocket broadcasting sensitive data ---

func TestWS005_BroadcastPassword(t *testing.T) {
	content := `ws.send(JSON.stringify({ password: user.password }));`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-005")
}

func TestWS005_BroadcastToken(t *testing.T) {
	content := `broadcast({ token: user.authToken });`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-005")
}

func TestWS005_Safe_BroadcastPublic(t *testing.T) {
	content := `ws.send(JSON.stringify({ username: user.name, status: "online" }));`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-005")
}

// --- BATOU-WS-006: WebSocket without TLS ---

func TestWS006_InsecureURL(t *testing.T) {
	content := `const ws = new WebSocket("ws://api.example.com/ws");`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-006")
}

func TestWS006_InsecureConnect_Python(t *testing.T) {
	content := `ws = websocket.create_connection("ws://api.example.com/ws")`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "BATOU-WS-006")
}

func TestWS006_Safe_WSS(t *testing.T) {
	content := `const ws = new WebSocket("wss://api.example.com/ws");`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-006")
}

func TestWS006_Safe_Localhost(t *testing.T) {
	content := `const ws = new WebSocket("ws://localhost:8080/ws");`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-006")
}

// --- BATOU-WS-008: WebSocket message SQL/NoSQL injection ---

func TestWS008_SQLInjection(t *testing.T) {
	content := `db.query("SELECT * FROM users WHERE id=" + message);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-008")
}

func TestWS008_MongoInjection(t *testing.T) {
	content := `db.users.find(JSON.parse(message));`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-WS-008")
}

func TestWS008_Safe_Parameterized(t *testing.T) {
	content := `db.query("SELECT * FROM users WHERE id = ?", [userId]);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-WS-008")
}
