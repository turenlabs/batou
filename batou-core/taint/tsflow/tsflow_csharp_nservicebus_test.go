package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# enterprise messaging trust-boundary source tests.
//
// Validates that sender-controlled metadata on NServiceBus
// IMessageHandlerContext and MassTransit ConsumeContext (Headers,
// MessageId, ReplyToAddress, CorrelationId, SourceAddress) is treated as
// untrusted input and produces taint flows to known sinks.
//
// CWE-501 (Trust Boundary Violation): a malicious upstream service can
// set arbitrary values in these properties; downstream code that uses them
// in SQL/HTML/log/file operations without sanitization is exploitable.
// =========================================================================

// --- NServiceBus: IMessageHandlerContext ---

func TestCSharp_Source_NServiceBus_Headers(t *testing.T) {
	code := `
using System.Threading.Tasks;
using NServiceBus;
using System.Data.SqlClient;

public class ChangeUserHandler : IHandleMessages<ChangeUser> {
    public async Task Handle(ChangeUser message, IMessageHandlerContext context) {
        string tenant = context.Headers["X-Tenant-Id"];
        var cmd = new SqlCommand("SELECT * FROM users WHERE tenant = '" + tenant + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/ChangeUserHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for IMessageHandlerContext.Headers -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_NServiceBus_MessageId(t *testing.T) {
	code := `
using System.Threading.Tasks;
using NServiceBus;
using System.Data.SqlClient;

public class AuditHandler : IHandleMessages<AuditEvent> {
    public async Task Handle(AuditEvent message, IMessageHandlerContext context) {
        string mid = context.MessageId;
        var cmd = new SqlCommand("INSERT INTO audit (msg_id) VALUES ('" + mid + "')");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/AuditHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for IMessageHandlerContext.MessageId -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_NServiceBus_ReplyToAddress(t *testing.T) {
	code := `
using System.Threading.Tasks;
using NServiceBus;
using System.Data.SqlClient;

public class CallbackHandler : IHandleMessages<CallbackRequest> {
    public async Task Handle(CallbackRequest message, IMessageHandlerContext context) {
        string reply = context.ReplyToAddress;
        var cmd = new SqlCommand("UPDATE callbacks SET endpoint = '" + reply + "' WHERE id = 1");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/CallbackHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for IMessageHandlerContext.ReplyToAddress -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MassTransit: extended ConsumeContext properties ---

func TestCSharp_Source_MassTransit_Headers(t *testing.T) {
	code := `
using System.Threading.Tasks;
using MassTransit;
using System.Data.SqlClient;

public class TenantConsumer : IConsumer<TenantOp> {
    public async Task Consume(ConsumeContext<TenantOp> context) {
        string region = context.Headers.Get<string>("region");
        var cmd = new SqlCommand("SELECT * FROM regions WHERE name = '" + region + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/TenantConsumer.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ConsumeContext.Headers -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_MassTransit_CorrelationId(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using MassTransit;
using System.Data.SqlClient;

public class TraceConsumer : IConsumer<TraceEvent> {
    public async Task Consume(ConsumeContext<TraceEvent> context) {
        Guid? cid = context.CorrelationId;
        var cmd = new SqlCommand("SELECT * FROM traces WHERE corr = '" + cid.ToString() + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/TraceConsumer.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ConsumeContext.CorrelationId -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_MassTransit_SourceAddress(t *testing.T) {
	code := `
using System.Threading.Tasks;
using MassTransit;
using System.Data.SqlClient;

public class OriginConsumer : IConsumer<OriginPing> {
    public async Task Consume(ConsumeContext<OriginPing> context) {
        var src = context.SourceAddress.ToString();
        var cmd = new SqlCommand("INSERT INTO pings (origin) VALUES ('" + src + "')");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/OriginConsumer.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ConsumeContext.SourceAddress -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: constant string should not produce a flow (over-broadness regression) ---

func TestCSharp_Source_NServiceBus_ConstantSafe(t *testing.T) {
	code := `
using System.Threading.Tasks;
using NServiceBus;
using System.Data.SqlClient;

public class StaticHandler : IHandleMessages<NoOp> {
    public async Task Handle(NoOp message, IMessageHandlerContext context) {
        string fixedTenant = "default";
        var cmd = new SqlCommand("SELECT * FROM users WHERE tenant = '" + fixedTenant + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/StaticHandler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a constant-string SqlCommand argument")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
