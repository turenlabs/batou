package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// C# messaging/cloud/cache source tests — validates that external data from
// Azure Service Bus, Queue Storage, Event Hubs, Event Grid, RabbitMQ,
// MassTransit, Kafka, Redis, and AWS SQS produces taint flows to known sinks.
// ===========================================================================

// --- Azure Service Bus ---

func TestCSharp_Source_AzureServiceBus_Body(t *testing.T) {
	code := `
using System;
using Azure.Messaging.ServiceBus;
using System.Data.SqlClient;

public class OrderProcessor {
    public async void ProcessMessage(ServiceBusReceivedMessage receivedMessage) {
        string body = receivedMessage.Body.ToString();
        var cmd = new SqlCommand("SELECT * FROM orders WHERE ref = '" + body + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/OrderProcessor.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ServiceBusReceivedMessage.Body -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_AzureServiceBus_Body_Safe(t *testing.T) {
	code := `
using System;
using Azure.Messaging.ServiceBus;
using System.Data.SqlClient;

public class OrderProcessor {
    public async void ProcessMessage(ServiceBusReceivedMessage receivedMessage) {
        string body = receivedMessage.Body.ToString();
        var cmd = new SqlCommand("SELECT * FROM orders WHERE ref = @ref");
        cmd.Parameters.AddWithValue("@ref", body);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/OrderProcessor.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL flow when using parameterized query with Service Bus data")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Queue Storage ---

func TestCSharp_Source_AzureQueue_Body(t *testing.T) {
	code := `
using System;
using Azure.Storage.Queues.Models;
using System.Diagnostics;

public class QueueHandler {
    public void Handle(QueueMessage queueMessage) {
        string body = queueMessage.Body.ToString();
        Process.Start("cmd.exe", "/c " + body);
    }
}
`
	flows := Analyze(code, "/app/QueueHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for QueueMessage.Body -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Event Hubs ---

func TestCSharp_Source_AzureEventHub_Body(t *testing.T) {
	code := `
using System;
using Azure.Messaging.EventHubs;
using System.Data.SqlClient;

public class EventProcessor {
    public void ProcessEvent(EventData eventData) {
        string payload = eventData.EventBody.ToString();
        var cmd = new SqlCommand("SELECT * FROM events WHERE data = '" + payload + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/EventProcessor.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for EventData.EventBody -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Event Grid ---

func TestCSharp_Source_AzureEventGrid_Data(t *testing.T) {
	code := `
using System;
using Azure.Messaging.EventGrid;
using System.Data.SqlClient;

public class GridHandler {
    public void Handle(EventGridEvent eventGridEvent) {
        string data = eventGridEvent.Data.ToString();
        var cmd = new SqlCommand("SELECT * FROM t WHERE payload = '" + data + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/GridHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for EventGridEvent.Data -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- RabbitMQ ---

func TestCSharp_Source_RabbitMQ_Body(t *testing.T) {
	code := `
using System;
using RabbitMQ.Client.Events;
using System.Data.SqlClient;

public class RabbitConsumer {
    public void OnReceived(BasicDeliverEventArgs ea) {
        string message = ea.Body.ToString();
        var cmd = new SqlCommand("INSERT INTO messages VALUES ('" + message + "')");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/RabbitConsumer.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for BasicDeliverEventArgs.Body -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MassTransit ---

func TestCSharp_Source_MassTransit_Message(t *testing.T) {
	code := `
using System;
using MassTransit;
using System.Data.SqlClient;

public class OrderConsumer : IConsumer<SubmitOrder> {
    public async Task Consume(ConsumeContext<SubmitOrder> context) {
        string name = context.Message.ToString();
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/OrderConsumer.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ConsumeContext.Message -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Confluent Kafka ---

func TestCSharp_Source_Kafka_ConsumeValue(t *testing.T) {
	code := `
using System;
using Confluent.Kafka;
using System.Data.SqlClient;

public class KafkaHandler {
    public void Handle(IConsumer<string, string> consumer) {
        var consumeResult = consumer.Consume();
        string value = consumeResult.Message.Value;
        var cmd = new SqlCommand("SELECT * FROM events WHERE data = '" + value + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/KafkaHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ConsumeResult.Message.Value -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- StackExchange.Redis ---

func TestCSharp_Source_Redis_StringGet(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;
using System.Data.SqlClient;

public class CacheHandler {
    public void Handle(IDatabase db) {
        string cached = db.StringGet("user:profile");
        var cmd = new SqlCommand("SELECT * FROM users WHERE profile = '" + cached + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for Redis StringGet -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_Redis_StringGet_Safe(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;
using System.Data.SqlClient;

public class CacheHandler {
    public void Handle(IDatabase db) {
        string cached = db.StringGet("user:profile");
        var cmd = new SqlCommand("SELECT * FROM users WHERE profile = @p");
        cmd.Parameters.AddWithValue("@p", cached);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL flow when using parameterized query with Redis data")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- AWS SQS ---

func TestCSharp_Source_AWS_SQS_ReceiveMessage(t *testing.T) {
	code := `
using System;
using Amazon.SQS;
using Amazon.SQS.Model;
using System.Diagnostics;

public class SqsHandler {
    public async void Handle(AmazonSQSClient sqsClient) {
        var response = await sqsClient.ReceiveMessageAsync(new ReceiveMessageRequest());
        string body = response.ToString();
        Process.Start("sh", "-c " + body);
    }
}
`
	flows := Analyze(code, "/app/SqsHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for SQS ReceiveMessageAsync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
