package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Email Header Injection (CWE-93) ---

func TestKotlin_EmailInjection_JavaMail_SetSubject(t *testing.T) {
	code := `
fun handler() {
    val subject = call.request.queryParameters["subject"]
    val mimeMessage = MimeMessage(session)
    mimeMessage.setSubject(subject)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> mimeMessage.setSubject()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_JavaMail_SetFrom(t *testing.T) {
	code := `
fun handler() {
    val from = call.request.queryParameters["from"]
    val mimeMessage = MimeMessage(session)
    mimeMessage.setFrom(from)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> mimeMessage.setFrom()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_JavaMail_AddHeader(t *testing.T) {
	code := `
fun handler() {
    val replyTo = call.request.queryParameters["replyTo"]
    val mimeMessage = MimeMessage(session)
    mimeMessage.addHeader("Reply-To", replyTo)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> mimeMessage.addHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_JavaMail_Recipients(t *testing.T) {
	code := `
fun handler() {
    val recipient = call.request.queryParameters["to"]
    val mimeMessage = MimeMessage(session)
    mimeMessage.setRecipients(Message.RecipientType.TO, recipient)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> mimeMessage.setRecipients()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_ReplyTo(t *testing.T) {
	code := `
fun handler() {
    val replyTo = call.request.queryParameters["replyTo"]
    val mimeMessage = MimeMessage(session)
    mimeMessage.setReplyTo(replyTo)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> setReplyTo()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_Bcc(t *testing.T) {
	code := `
fun handler() {
    val bcc = call.request.queryParameters["bcc"]
    val mimeMessageHelper = MimeMessageHelper(mimeMessage, true)
    mimeMessageHelper.setBcc(bcc)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> setBcc()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_Transport_Send(t *testing.T) {
	code := `
fun handler() {
    val subject = call.request.queryParameters["subject"]
    val mimeMessage = MimeMessage(session)
    mimeMessage.setSubject(subject)
    Transport.send(mimeMessage)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow through Transport.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_SpringHelper_SetTo(t *testing.T) {
	code := `
fun handler() {
    val recipient = call.request.queryParameters["to"]
    val mimeMessageHelper = MimeMessageHelper(mimeMessage, true)
    mimeMessageHelper.setTo(recipient)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for queryParameters -> mimeMessageHelper.setTo()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe cases: must NOT trigger ---

func TestKotlin_EmailInjection_InternetAddressParse_Safe(t *testing.T) {
	code := `
fun handler() {
    val from = call.request.queryParameters["from"]
    val safe = InternetAddress.parse(from, true)
    val mimeMessage = MimeMessage(session)
    mimeMessage.setFrom(safe)
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected no header flow after InternetAddress.parse() sanitization")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_EmailInjection_HardcodedSubject_Safe(t *testing.T) {
	code := `
fun handler() {
    val mimeMessage = MimeMessage(session)
    mimeMessage.setSubject("System Notification")
    mimeMessage.setFrom("noreply@example.com")
}
`
	flows := Analyze(code, "/app/Mailer.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected no header flow for hardcoded values")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
