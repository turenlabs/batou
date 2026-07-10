package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasRustEmailSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.Category == taint.SnkHeader {
			return true
		}
	}
	return false
}

// lettre MessageBuilder::raw_header with tainted header value -> CRLF injection
func TestRust_LettreRawHeader_Tainted(t *testing.T) {
	code := `
use std::env;
use lettre::Message;

fn build() -> Message {
    let user = env::var("X_CUSTOM").unwrap();
    Message::builder()
        .raw_header(user)
        .body(String::from("hi"))
        .unwrap()
}
`
	flows := Analyze(code, "/app/mailer.rs", rules.LangRust)
	if !hasRustEmailSinkID(flows, "rust.lettre.message.raw_header") {
		t.Error("expected SnkHeader flow for env::var -> lettre raw_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// lettre MessageBuilder::in_reply_to with tainted message-id -> RFC 5322 header injection
func TestRust_LettreInReplyTo_Tainted(t *testing.T) {
	code := `
use std::env;
use lettre::Message;

fn build() -> Message {
    let mid = env::var("MSG_ID").unwrap();
    Message::builder()
        .in_reply_to(mid)
        .body(String::from("reply"))
        .unwrap()
}
`
	flows := Analyze(code, "/app/mailer.rs", rules.LangRust)
	if !hasRustEmailSinkID(flows, "rust.lettre.message.in_reply_to") {
		t.Error("expected SnkHeader flow for env::var -> lettre in_reply_to")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// lettre Mailbox::new with tainted display name (first arg) -> CRLF in name injects headers
func TestRust_LettreMailboxNew_Tainted(t *testing.T) {
	code := `
use std::env;
use lettre::message::Mailbox;
use lettre::Address;

fn make() -> Mailbox {
    let display = env::var("DISPLAY_NAME").unwrap();
    let addr: Address = "user@example.com".parse().unwrap();
    Mailbox::new(Some(display), addr)
}
`
	flows := Analyze(code, "/app/mailer.rs", rules.LangRust)
	if !hasRustEmailSinkID(flows, "rust.lettre.mailbox.new") {
		t.Error("expected SnkHeader flow for env::var -> Mailbox::new display name")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Safe: hardcoded header value should NOT produce a header flow.
func TestRust_LettreRawHeader_Safe(t *testing.T) {
	code := `
use lettre::Message;

fn build() -> Message {
    Message::builder()
        .raw_header("X-App: turen")
        .body(String::from("hi"))
        .unwrap()
}
`
	flows := Analyze(code, "/app/mailer.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.lettre.message.raw_header" {
			t.Errorf("hardcoded header should not produce flow, got sink=%s", f.Sink.ID)
		}
	}
}

// Safe: Address::new sanitizes the local/domain parts before flowing into Mailbox::new.
// Uses the `?` operator so Address::new is the top-level RHS call (walker.processAssign
// recognises direct sanitizer calls but does not unwrap `.unwrap()` chains).
func TestRust_LettreAddressNew_Sanitizes(t *testing.T) {
	code := `
use std::env;
use lettre::message::Mailbox;
use lettre::Address;

fn make() -> Result<Mailbox, Box<dyn std::error::Error>> {
    let local = env::var("LOCAL_PART")?;
    let addr = Address::new(&local, "example.com")?;
    Ok(Mailbox::new(None, addr))
}
`
	flows := Analyze(code, "/app/mailer.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.lettre.mailbox.new" {
			t.Errorf("Address::new should sanitize the local-part; got flow sink=%s source=%s", f.Sink.ID, f.Source.ID)
		}
	}
}
