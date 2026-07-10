package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Trust boundary: background job enqueue (CWE-501)
// =========================================================================
//
// Enqueueing untrusted data into Sidekiq/ActiveJob/Resque queues crosses the
// trust boundary: args are serialized to Redis (or DB/SQS), later deserialized
// and executed by a worker in a privileged context. Sidekiq explicitly warns
// on JSON-unsafe args; ActiveJob restricts args to a GlobalID-safe allowlist.

func TestRuby_TrustBoundary_SidekiqPerformAsync(t *testing.T) {
	code := `
def create(params)
  email = params[:email]
  NotifyWorker.perform_async(email)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Worker.perform_async()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_TrustBoundary_SidekiqPerformIn(t *testing.T) {
	code := `
def update(params)
  payload = params[:payload]
  EmailWorker.perform_in(30.minutes, payload)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Worker.perform_in()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_TrustBoundary_SidekiqPerformAt(t *testing.T) {
	code := `
def schedule(params)
  msg = params[:message]
  ReminderWorker.perform_at(1.hour.from_now, msg)
end
`
	flows := Analyze(code, "/app/controllers/reminders_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Worker.perform_at()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_TrustBoundary_ActiveJobPerformLater(t *testing.T) {
	code := `
def create(params)
  body = params[:body]
  CleanupJob.perform_later(body)
end
`
	flows := Analyze(code, "/app/controllers/cleanups_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Job.perform_later()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_TrustBoundary_ResqueEnqueue(t *testing.T) {
	code := `
def create(params)
  msg = params[:msg]
  Resque.enqueue(SendWorker, msg)
end
`
	flows := Analyze(code, "/app/controllers/jobs_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Resque.enqueue()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_TrustBoundary_ResqueEnqueueIn(t *testing.T) {
	code := `
def create(params)
  data = params[:data]
  Resque.enqueue_in(60, SendWorker, data)
end
`
	flows := Analyze(code, "/app/controllers/jobs_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Resque.enqueue_in()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_TrustBoundary_RailsCacheWriteMulti(t *testing.T) {
	code := `
def update(params)
  data = params[:data]
  Rails.cache.write_multi({"user_prefs" => data})
end
`
	flows := Analyze(code, "/app/controllers/prefs_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Rails.cache.write_multi()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: coercing to int before enqueue neutralizes the trust boundary ---

func TestRuby_TrustBoundary_SidekiqPerformAsync_Sanitized_ToI(t *testing.T) {
	code := `
def create(params)
  user_id = params[:user_id].to_i
  NotifyWorker.perform_async(user_id)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected NO trust boundary flow — .to_i should coerce to integer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
