package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — Temporal-parse return-value sanitizers (CWE-89, CWE-77/78, CWE-79,
// CWE-117, CWE-22, CWE-601)
//
// Date.parse / Date.iso8601 / Date.rfc3339 / Date.strptime,
// DateTime.parse / DateTime.iso8601 / DateTime.rfc3339 / DateTime.rfc2822 /
// DateTime.strptime, and Time.parse / Time.iso8601 / Time.xmlschema /
// Time.rfc2822 / Time.httpdate all accept a user-controlled string and
// return a strongly-typed Date / DateTime / Time value whose #to_s output is
// a constrained format (digits, dashes, colons, 'T', 'Z', '+', spaces — no
// quotes, no shell metacharacters, no angle brackets, no path-traversal
// sequences, no CRLF). Each test asserts that the parsed value flowing into
// a SQL / command / log / file / HTML / redirect sink does NOT produce a
// taint flow at the matching SinkCategory.
//
// SnkURLFetch is intentionally NOT covered — see ruby_sanitizers.go.
//
// Same model as cycle #757 (the matcher only sanitizes the LHS of an
// assignment, not the original tainted argument), so every fixture follows
// the canonical `lhs = Class.method(tainted)` shape.
// =========================================================================

// -------------------------------------------------------------------------
// Date stdlib (require 'date') — class methods returning Date
// -------------------------------------------------------------------------

func TestRuby_Sanitizer_DateParse_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:day]
  d = Date.parse(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE day = '" + d.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Date.parse should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateIso8601_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:day]
  d = Date.iso8601(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE day = '" + d.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Date.iso8601 should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateRfc3339_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:day]
  d = Date.rfc3339(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE day = '" + d.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Date.rfc3339 should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateStrptime_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:day]
  d = Date.strptime(raw, "%Y-%m-%d")
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE day = '" + d.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Date.strptime should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// DateTime stdlib (require 'date') — class methods returning DateTime
// -------------------------------------------------------------------------

func TestRuby_Sanitizer_DateTimeParse_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:when]
  dt = DateTime.parse(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + dt.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("DateTime.parse should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateTimeIso8601_NeutralizesCommand(t *testing.T) {
	code := `
require "date"

def archive(params)
  raw = params[:when]
  dt = DateTime.iso8601(raw)
  system("tar -czf /backups/snap-" + dt.to_s + ".tgz /data")
end
`
	flows := Analyze(code, "/app/controllers/backups_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("DateTime.iso8601 should neutralize SnkCommand flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateTimeRfc3339_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:when]
  dt = DateTime.rfc3339(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + dt.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("DateTime.rfc3339 should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateTimeRfc2822_NeutralizesLog(t *testing.T) {
	code := `
require "date"
require "logger"

def audit(params)
  raw = params[:when]
  dt = DateTime.rfc2822(raw)
  logger = Logger.new(STDOUT)
  logger.info("event recorded at " + dt.to_s)
end
`
	flows := Analyze(code, "/app/controllers/audit_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("DateTime.rfc2822 should neutralize SnkLog flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_DateTimeStrptime_NeutralizesSQL(t *testing.T) {
	code := `
require "date"
require "pg"

def search(params)
  raw = params[:when]
  dt = DateTime.strptime(raw, "%Y-%m-%dT%H:%M:%S%z")
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + dt.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("DateTime.strptime should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Time stdlib (require 'time') — class methods returning Time
// -------------------------------------------------------------------------

func TestRuby_Sanitizer_TimeParse_NeutralizesSQL(t *testing.T) {
	code := `
require "time"
require "pg"

def search(params)
  raw = params[:when]
  t = Time.parse(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + t.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Time.parse should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_TimeIso8601_NeutralizesFileWrite(t *testing.T) {
	code := `
require "time"

def snapshot(params)
  raw = params[:when]
  t = Time.iso8601(raw)
  File.write("/var/snapshots/" + t.to_s + ".log", "ok")
end
`
	flows := Analyze(code, "/app/controllers/snap_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("Time.iso8601 should neutralize SnkFileWrite flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_TimeXmlschema_NeutralizesSQL(t *testing.T) {
	code := `
require "time"
require "pg"

def search(params)
  raw = params[:when]
  t = Time.xmlschema(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + t.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Time.xmlschema should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_TimeRfc2822_NeutralizesSQL(t *testing.T) {
	code := `
require "time"
require "pg"

def search(params)
  raw = params[:when]
  t = Time.rfc2822(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + t.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Time.rfc2822 should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_TimeHttpdate_NeutralizesSQL(t *testing.T) {
	code := `
require "time"
require "pg"

def search(params)
  raw = params[:when]
  t = Time.httpdate(raw)
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE created_at >= '" + t.to_s + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("Time.httpdate should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Negative control — no sanitizer, the same code path SHOULD produce a
// SnkSQLQuery flow. Proves the test harness is wired up correctly so the
// neutralization tests above are not silently passing for the wrong reason.
// -------------------------------------------------------------------------

func TestRuby_Sanitizer_NegativeControl_NoSanitizerStillFlows(t *testing.T) {
	code := `
require "pg"

def search(params)
  raw = params[:day]
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM events WHERE day = '" + raw + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/events_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("negative control: without a sanitizer, params[:day] -> exec_params should flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
