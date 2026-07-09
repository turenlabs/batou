package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// C# source tests — validates new network, database, file, and
// deserialization source entries produce taint flows to known sinks.
// ===========================================================================

// --- Network sources ---

func TestCSharp_Source_HttpClient_GetStringAsync(t *testing.T) {
	code := `
using System;
using System.Net.Http;
using System.Data.SqlClient;

public class Handler {
    public async void Handle() {
        var client = new HttpClient();
        string data = await client.GetStringAsync("https://external.api/data");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + data + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for HttpClient.GetStringAsync -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_WebClient_DownloadString(t *testing.T) {
	code := `
using System;
using System.Net;
using System.Data.SqlClient;

public class Handler {
    public void Handle() {
        var client = new WebClient();
        string data = client.DownloadString("https://external.site/data");
        var cmd = new SqlCommand("SELECT * FROM t WHERE x = '" + data + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for WebClient.DownloadString -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_HttpWebRequest_GetResponse(t *testing.T) {
	code := `
using System;
using System.Net;
using System.IO;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        var request = WebRequest.Create("https://external.api/cmd");
        var response = request.GetResponse();
        var stream = response.GetResponseStream();
        var reader = new StreamReader(stream);
        string cmd = reader.ReadToEnd();
        Process.Start(cmd);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for GetResponse -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_WebSocket_ReceiveAsync(t *testing.T) {
	code := `
using System;
using System.Net.WebSockets;
using System.Data.SqlClient;

public class Handler {
    public async void Handle(WebSocket webSocket) {
        var buffer = new byte[1024];
        var result = await webSocket.ReceiveAsync(buffer, default);
        string message = result.ToString();
        var cmd = new SqlCommand("SELECT * FROM t WHERE x = '" + message + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for WebSocket.ReceiveAsync -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_TcpClient_GetStream(t *testing.T) {
	code := `
using System;
using System.Net.Sockets;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        var tcp = new TcpClient("host", 9000);
        var stream = tcp.GetStream();
        Process.Start(stream.ToString());
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for TcpClient.GetStream -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Database sources ---

func TestCSharp_Source_Dapper_Query(t *testing.T) {
	code := `
using System;
using Dapper;
using System.Data.SqlClient;

public class Handler {
    public void Handle(SqlConnection conn) {
        var name = conn.QueryFirst<string>("SELECT name FROM users WHERE id = 1");
        var cmd = new SqlCommand("SELECT * FROM orders WHERE customer = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for Dapper.QueryFirst -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_ExecuteScalar(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Handler {
    public void Handle(SqlConnection conn) {
        var cmd1 = new SqlCommand("SELECT template FROM pages WHERE id = 1", conn);
        var template = cmd1.ExecuteScalar();
        var cmd2 = new SqlCommand("SELECT * FROM data WHERE key = '" + template + "'");
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ExecuteScalar -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- File read sources ---

func TestCSharp_Source_File_ReadAllTextAsync(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Data.SqlClient;

public class Handler {
    public async void Handle() {
        string config = await File.ReadAllTextAsync("/data/config.txt");
        var cmd = new SqlCommand("SELECT * FROM t WHERE x = '" + config + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for File.ReadAllTextAsync -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_File_OpenRead(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        var stream = File.OpenRead("/data/commands.txt");
        var reader = new StreamReader(stream);
        string cmd = reader.ReadToEnd();
        Process.Start(cmd);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for File.OpenRead -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_BinaryReader(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Data.SqlClient;

public class Handler {
    public void Handle() {
        var fs = new FileStream("/data/input.bin", FileMode.Open);
        var reader = new BinaryReader(fs);
        string name = reader.ReadString();
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for BinaryReader.ReadString -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Deserialization sources ---

func TestCSharp_Source_BinaryFormatter_Deserialize(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Data.SqlClient;

public class Handler {
    public void Handle(Stream input) {
        var binaryFormatter = new BinaryFormatter();
        var obj = binaryFormatter.Deserialize(input);
        string name = obj.ToString();
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for BinaryFormatter.Deserialize -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_MessagePack_Deserialize(t *testing.T) {
	code := `
using System;
using MessagePack;
using System.Data.SqlClient;

public class Handler {
    public void Handle(byte[] data) {
        var obj = MessagePackSerializer.Deserialize<UserData>(data);
        var cmd = new SqlCommand("SELECT * FROM t WHERE x = '" + obj + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for MessagePackSerializer.Deserialize -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_Yaml_Deserialize(t *testing.T) {
	code := `
using System;
using YamlDotNet.Serialization;
using System.Data.SqlClient;

public class Handler {
    public void Handle(string yamlInput) {
        var deserializer = new DeserializerBuilder().Build();
        var config = deserializer.Deserialize<Config>(yamlInput);
        var cmd = new SqlCommand("SELECT * FROM t WHERE key = '" + config + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for YamlDotNet Deserialize -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe fixtures (sanitization breaks taint flow) ---

func TestCSharp_Source_HttpClient_Sanitized(t *testing.T) {
	code := `
using System;
using System.Net.Http;
using System.Data.SqlClient;

public class Handler {
    public async void Handle() {
        var client = new HttpClient();
        string data = await client.GetStringAsync("https://external.api/data");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name");
        cmd.Parameters.AddWithValue("@name", data);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL flow when using parameterized query with HttpClient data")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_Dapper_Query_Sanitized(t *testing.T) {
	code := `
using System;
using Dapper;
using System.Data.SqlClient;
using System.Web;

public class Handler {
    public void Handle(SqlConnection conn) {
        var name = conn.QueryFirst<string>("SELECT name FROM users WHERE id = 1");
        string safe = HttpUtility.HtmlEncode(name);
        Response.Write(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO XSS flow when Dapper result is HtmlEncoded")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
