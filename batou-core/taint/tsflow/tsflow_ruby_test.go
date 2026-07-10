package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Redirect sinks (CWE-601)
// =========================================================================

func TestRuby_Redirect_SinatraRedirect(t *testing.T) {
	code := `
def handler(params)
  url = params[:url]
  redirect(url)
end
`
	flows := Analyze(code, "/app/server.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> Sinatra redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Redirect_RailsRedirectBack(t *testing.T) {
	code := `
def update(params)
  target = params[:return_to]
  redirect_back(fallback_location: target)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> redirect_back()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Redirect_RailsRedirectToNoParen(t *testing.T) {
	code := `
def show(params)
  url = params[:return_url]
  redirect_to url
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> redirect_to without parens")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Redirect_SinatraRedirectNoParen(t *testing.T) {
	code := `
def handler(params)
  target = params[:url]
  redirect target
end
`
	flows := Analyze(code, "/app/server.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> Sinatra redirect without parens")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Redirect_RailsRedirectBackOrTo(t *testing.T) {
	code := `
def destroy(params)
  url = params[:return_to]
  redirect_back_or_to(url)
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> redirect_back_or_to()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Redirect_RodaRedirect(t *testing.T) {
	code := `
def handler(r, params)
  target = params[:url]
  r.redirect(target)
end
`
	flows := Analyze(code, "/app/routes.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> Roda r.redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Redirect_RackResponseRedirect(t *testing.T) {
	code := `
def handler(params, response)
  url = params[:url]
  response.redirect(url)
end
`
	flows := Analyze(code, "/app/middleware.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for params -> Rack response.redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Note: response['Location'] = url is an assignment node, not a call,
// so tsflow cannot detect it. The regex-based taint engine handles this
// pattern via the ruby.rack.location.header sink entry.

func TestRuby_Redirect_Safe_RedirectToFixedPath(t *testing.T) {
	code := `
def handler(params)
  redirect_to root_path
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected NO redirect flow for redirect_to with non-tainted path helper")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Trust boundary sinks (CWE-501)
// =========================================================================

func TestRuby_TrustBoundary_CacheWrite(t *testing.T) {
	code := `
def update(params)
  data = params[:data]
  Rails.cache.write("user_prefs", data)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for params -> Rails.cache.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Weak random (CWE-338)
// =========================================================================

func TestRuby_WeakRandom_RandomRand(t *testing.T) {
	code := `
def handler(params)
  seed = params[:seed]
  Random.rand(seed)
end
`
	flows := Analyze(code, "/app/auth.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for params -> Random.rand() (weak random)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Header injection (CWE-113)
// =========================================================================

func TestRuby_Header_RackSetCookieHeader(t *testing.T) {
	code := `
def handler(params)
  val = params[:val]
  Rack::Utils.set_cookie_header(val)
end
`
	flows := Analyze(code, "/app/middleware.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for params -> Rack::Utils.set_cookie_header()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Additional sources
// =========================================================================

func TestRuby_Source_RequestQueryString(t *testing.T) {
	code := `
def index
  qs = request.query_string
  system(qs)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.query_string -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Source_RequestOriginalURL(t *testing.T) {
	code := `
def index
  url = request.original_url
  system(url)
end
`
	flows := Analyze(code, "/app/controllers/log_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.original_url -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Sanitizer: strip_tags prevents XSS
// =========================================================================

// =========================================================================
// Ruby — Log injection (CWE-117) — unsanitized
// =========================================================================

func TestRuby_Log_LogInjection(t *testing.T) {
	code := `
def create(params)
  username = params[:username]
  logger.info("Login attempt: " + username)
end
`
	flows := Analyze(code, "/app/controllers/auth_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for params -> logger.info()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Header injection sanitized by .delete("\r\n")
// =========================================================================

func TestRuby_Header_Sanitized_DeleteCRLF(t *testing.T) {
	code := `
def handler(params)
  val = params[:val]
  safe = val.delete("\r\n")
  Rack::Utils.set_cookie_header(safe)
end
`
	flows := Analyze(code, "/app/controllers/api_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected NO header flow — .delete(\"\\r\\n\") should sanitize")
	}
}

// =========================================================================
// Ruby — Log injection sanitized by .gsub(/[\r\n]/, '')
// =========================================================================

func TestRuby_Log_Sanitized_GsubCRLF(t *testing.T) {
	code := `
def create(params)
  username = params[:username]
  safe = username.gsub(/[\r\n]/, '')
  logger.info("Login: " + safe)
end
`
	flows := Analyze(code, "/app/controllers/auth_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected NO log flow — .gsub(/[\\r\\n]/, '') should sanitize")
	}
}

// =========================================================================
// Ruby — Trust boundary sanitized by cookies.signed[]
// =========================================================================

func TestRuby_TrustBoundary_Sanitized_SignedCookies(t *testing.T) {
	code := `
def show
  user_id = cookies.signed[:user_id]
  session[:current_user] = user_id
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected NO trust boundary flow — cookies.signed[] should sanitize")
	}
}

func TestRuby_HTMLOutput_Sanitized_StripTagsNew(t *testing.T) {
	code := `
def show(params)
  input = params[:html]
  safe = strip_tags(input)
  render html: safe
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO HTML output flow — strip_tags() should sanitize")
	}
}

// =========================================================================
// Ruby — Database result sources (second-order injection, CWE-89/CWE-79)
// =========================================================================

func TestRuby_SecondOrder_ActiveRecordFindByToEval(t *testing.T) {
	code := `
def show
  data = User.find_by(id: 1)
  eval(data)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for ActiveRecord find_by result -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_SecondOrder_ActiveRecordPluckToEval(t *testing.T) {
	code := `
def execute_stored
  data = User.pluck(:command)
  eval(data)
end
`
	flows := Analyze(code, "/app/workers/job.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for ActiveRecord pluck result -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_SecondOrder_ActiveRecordPickToSystem(t *testing.T) {
	code := `
def run_job
  cmd = Job.pick(:shell_command)
  system(cmd)
end
`
	flows := Analyze(code, "/app/workers/runner.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ActiveRecord pick result -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_SecondOrder_PGExecParamsToSystem(t *testing.T) {
	code := `
def run
  data = conn.exec_params("SELECT cmd FROM jobs WHERE id = $1", [id])
  system(data)
end
`
	flows := Analyze(code, "/app/workers/runner.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PG exec_params result -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_SecondOrder_SQLite3GetFirstValueToEval(t *testing.T) {
	code := `
def run_script
  code = db.get_first_value("SELECT code FROM scripts WHERE id = ?", [id])
  eval(code)
end
`
	flows := Analyze(code, "/app/services/script_runner.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for SQLite3 get_first_value result -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_SecondOrder_Safe_PluckWithSanitize(t *testing.T) {
	code := `
def show
  names = User.pluck(:name)
  safe = CGI.escapeHTML(names.first)
  render html: safe
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO XSS flow — CGI.escapeHTML should sanitize pluck result")
	}
}
