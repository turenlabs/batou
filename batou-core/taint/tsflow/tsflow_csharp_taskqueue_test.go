package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# — Message broker / task queue producer trust boundary (CWE-501)
// =========================================================================
//
// Producer side: a web handler publishes user-controlled values into a
// broker (RabbitMQ / Kafka / Azure Service Bus / Event Grid / AWS SQS).
// The payload is serialized into the broker and later deserialized +
// re-processed by a consumer running in a privileged context — crossing a
// trust boundary.
//
// C# already has the consumer-side sources (csharp.rabbitmq.body,
// csharp.kafka.consume.value, csharp.azure.servicebus.body,
// csharp.azure.eventgrid.data, csharp.aws.sqs.receivemessage, etc.) but no
// producer-side sink until now — this mirrors Java (PR #426), Rust (PR #424),
// Kotlin, Python Celery/RQ, Ruby Sidekiq/ActiveJob, and JS BullMQ.

// --- RabbitMQ.Client IModel.BasicPublish ---

func TestCSharp_TaskQueue_RabbitMQBasicPublish(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using RabbitMQ.Client;

public class OrderController : Controller {
    private readonly IModel channel;

    public IActionResult CreateOrder() {
        string payload = Request.QueryString.Value;
        channel.BasicPublish("exchange", "orders", null, payload);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/OrderController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> channel.BasicPublish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_TaskQueue_RabbitMQBasicPublish_Hardcoded_Safe(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using RabbitMQ.Client;

public class HeartbeatController : Controller {
    private readonly IModel channel;

    public IActionResult Ping() {
        channel.BasicPublish("exchange", "heartbeat", null, "ping");
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/HeartbeatController.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Errorf("hardcoded BasicPublish should not produce trust-boundary flow: %s", f.Sink.ID)
		}
	}
}

// --- Confluent.Kafka IProducer.ProduceAsync ---

func TestCSharp_TaskQueue_KafkaProduceAsync(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using Confluent.Kafka;

public class EventController : Controller {
    private readonly IProducer<string, string> producer;

    public async Task<IActionResult> Publish() {
        string val = Request.QueryString.Value;
        await producer.ProduceAsync("events", val);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/EventController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> producer.ProduceAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Service Bus ServiceBusSender.SendMessageAsync ---

func TestCSharp_TaskQueue_AzureServiceBusSendMessageAsync(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using Azure.Messaging.ServiceBus;

public class NotificationController : Controller {
    private readonly ServiceBusSender sender;

    public async Task<IActionResult> Notify() {
        string text = Request.QueryString.Value;
        await sender.SendMessageAsync(text);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/NotificationController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> ServiceBusSender.SendMessageAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Service Bus ServiceBusSender.SendMessagesAsync (batch) ---

func TestCSharp_TaskQueue_AzureServiceBusSendMessagesAsync(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using Azure.Messaging.ServiceBus;

public class BulkController : Controller {
    private readonly ServiceBusSender sender;

    public async Task<IActionResult> SendBulk() {
        string raw = Request.QueryString.Value;
        await sender.SendMessagesAsync(raw);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/BulkController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> ServiceBusSender.SendMessagesAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- AWS SQS AmazonSQSClient.SendMessageAsync (shared method name) ---

func TestCSharp_TaskQueue_AWSSQSSendMessageAsync(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using Amazon.SQS;

public class QueueController : Controller {
    private readonly AmazonSQSClient sqsClient;

    public async Task<IActionResult> Enqueue() {
        string body = Request.QueryString.Value;
        await sqsClient.SendMessageAsync("q-url", body);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/QueueController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> AmazonSQSClient.SendMessageAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Event Grid EventGridPublisherClient.SendEventAsync ---

func TestCSharp_TaskQueue_AzureEventGridSendEventAsync(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using Azure.Messaging.EventGrid;

public class EventGridController : Controller {
    private readonly EventGridPublisherClient client;

    public async Task<IActionResult> Send() {
        string data = Request.QueryString.Value;
        await client.SendEventAsync(data);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/EventGridController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> EventGridPublisherClient.SendEventAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Azure Event Grid SendEventsAsync (batch) ---

func TestCSharp_TaskQueue_AzureEventGridSendEventsAsync(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using Azure.Messaging.EventGrid;

public class EventGridBatchController : Controller {
    private readonly EventGridPublisherClient client;

    public async Task<IActionResult> SendBatch() {
        string data = Request.QueryString.Value;
        await client.SendEventsAsync(data);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/EventGridBatchController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for Request.QueryString -> EventGridPublisherClient.SendEventsAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
