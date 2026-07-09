package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// C# IoT / RPC messaging source tests — validates that publisher-controlled
// MQTTnet ApplicationMessage payloads/topics and ZeroMQ (NetMQ) socket frames
// produce taint flows to known sinks. ZeroMQ has no built-in authentication
// (absent CurveZMQ), and MQTT brokers forward arbitrary publisher payloads,
// so all received frames must be treated as untrusted.
// ===========================================================================

// --- MQTTnet — payload bytes ---

func TestCSharp_Source_MQTTnet_PayloadSegment(t *testing.T) {
	code := `
using System;
using MQTTnet;
using System.Data.SqlClient;

public class TelemetryHandler {
    public void OnMessage(MqttApplicationMessageReceivedEventArgs args) {
        var payload = args.ApplicationMessage.PayloadSegment.ToArray();
        var s = System.Text.Encoding.UTF8.GetString(payload);
        var cmd = new SqlCommand("INSERT INTO telemetry VALUES ('" + s + "')");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/TelemetryHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for MqttApplicationMessage.PayloadSegment -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MQTTnet — converted-string payload ---

func TestCSharp_Source_MQTTnet_ConvertPayloadToString(t *testing.T) {
	code := `
using System;
using MQTTnet;
using System.Diagnostics;

public class CommandHandler {
    public void OnMessage(MqttApplicationMessageReceivedEventArgs args) {
        var data = args.ApplicationMessage.ConvertPayloadToString();
        Process.Start("sh", "-c " + data);
    }
}
`
	flows := Analyze(code, "/app/CommandHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for MqttApplicationMessage.ConvertPayloadToString -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MQTTnet — topic string ---

func TestCSharp_Source_MQTTnet_Topic(t *testing.T) {
	code := `
using System;
using MQTTnet;
using System.Data.SqlClient;

public class RouterHandler {
    public void OnMessage(MqttApplicationMessageReceivedEventArgs args) {
        var topic = args.ApplicationMessage.Topic;
        var cmd = new SqlCommand("SELECT * FROM routes WHERE topic = '" + topic + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/RouterHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for MqttApplicationMessage.Topic -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MQTTnet — legacy Payload byte[] API ---

func TestCSharp_Source_MQTTnet_Payload_LegacyAPI(t *testing.T) {
	code := `
using System;
using MQTTnet;
using System.Data.SqlClient;

public class LegacyHandler {
    public void OnMessage(MqttApplicationMessageReceivedEventArgs args) {
        var payload = args.ApplicationMessage.Payload;
        var s = System.Text.Encoding.UTF8.GetString(payload);
        var cmd = new SqlCommand("UPDATE devices SET state = '" + s + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/LegacyHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for MqttApplicationMessage.Payload -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MQTTnet — sanitized via parameterized query ---

func TestCSharp_Source_MQTTnet_Sanitized_Safe(t *testing.T) {
	code := `
using System;
using MQTTnet;
using System.Data.SqlClient;

public class SafeHandler {
    public void OnMessage(MqttApplicationMessageReceivedEventArgs args) {
        var data = args.ApplicationMessage.ConvertPayloadToString();
        var cmd = new SqlCommand("INSERT INTO telemetry VALUES (@data)");
        cmd.Parameters.AddWithValue("@data", data);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/SafeHandler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL flow when parameterizing MQTTnet payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NetMQ — single frame string receive ---

func TestCSharp_Source_NetMQ_ReceiveFrameString(t *testing.T) {
	code := `
using System;
using NetMQ;
using NetMQ.Sockets;
using System.Data.SqlClient;

public class ZmqWorker {
    public void Process(ResponseSocket socket) {
        string body = socket.ReceiveFrameString();
        var cmd = new SqlCommand("SELECT * FROM jobs WHERE name = '" + body + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/ZmqWorker.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for NetMQ ReceiveFrameString -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NetMQ — frame bytes receive ---

func TestCSharp_Source_NetMQ_ReceiveFrameBytes(t *testing.T) {
	code := `
using System;
using NetMQ;
using NetMQ.Sockets;
using System.Diagnostics;

public class ZmqExec {
    public void Run(PullSocket socket) {
        byte[] frame = socket.ReceiveFrameBytes();
        string s = System.Text.Encoding.UTF8.GetString(frame);
        Process.Start("/bin/sh", "-c " + s);
    }
}
`
	flows := Analyze(code, "/app/ZmqExec.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for NetMQ ReceiveFrameBytes -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NetMQ — multipart message receive ---

func TestCSharp_Source_NetMQ_ReceiveMultipartMessage(t *testing.T) {
	code := `
using System;
using NetMQ;
using NetMQ.Sockets;
using System.Data.SqlClient;

public class ZmqMultiPart {
    public void Handle(SubscriberSocket socket) {
        var msg = socket.ReceiveMultipartMessage();
        string body = msg.ToString();
        var cmd = new SqlCommand("SELECT * FROM events WHERE id = '" + body + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/ZmqMultiPart.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for NetMQ ReceiveMultipartMessage -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NetMQ — multipart strings receive ---

func TestCSharp_Source_NetMQ_ReceiveMultipartStrings(t *testing.T) {
	code := `
using System;
using NetMQ;
using NetMQ.Sockets;
using System.Data.SqlClient;

public class ZmqStrings {
    public void Handle(RouterSocket socket) {
        var frames = socket.ReceiveMultipartStrings();
        string body = frames[0];
        var cmd = new SqlCommand("DELETE FROM users WHERE name = '" + body + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/ZmqStrings.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for NetMQ ReceiveMultipartStrings -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NetMQ — sanitized via parameterized query ---

func TestCSharp_Source_NetMQ_Sanitized_Safe(t *testing.T) {
	code := `
using System;
using NetMQ;
using NetMQ.Sockets;
using System.Data.SqlClient;

public class ZmqSafe {
    public void Handle(ResponseSocket socket) {
        string body = socket.ReceiveFrameString();
        var cmd = new SqlCommand("SELECT * FROM jobs WHERE name = @name");
        cmd.Parameters.AddWithValue("@name", body);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/ZmqSafe.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL flow when parameterizing NetMQ frame")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
