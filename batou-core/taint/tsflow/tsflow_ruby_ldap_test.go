package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Net::LDAP injection sinks (CWE-90)
// =========================================================================

func TestRuby_LDAP_NetLdapAddWithTaintedDN(t *testing.T) {
	code := `
def create(params)
  user = params[:username]
  ldap.add(dn: "cn=" + user + ",ou=People,dc=example,dc=com", attributes: {cn: user})
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> ldap.add(dn:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_NetLdapModifyWithTaintedDN(t *testing.T) {
	code := `
def update(params)
  target = params[:dn]
  ldap.modify(dn: target, operations: [[:replace, :mail, "new@example.com"]])
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> ldap.modify(dn:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_NetLdapDeleteWithTaintedDN(t *testing.T) {
	code := `
def destroy(params)
  victim = params[:dn]
  ldap.delete(dn: victim)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> ldap.delete(dn:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_NetLdapBindAsWithTaintedFilter(t *testing.T) {
	code := `
def login(params)
  username = params[:username]
  password = params[:password]
  filter = "(uid=" + username + ")"
  ldap.bind_as(base: "dc=example,dc=com", filter: filter, password: password)
end
`
	flows := Analyze(code, "/app/controllers/auth_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> ldap.bind_as()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_NetLdapModifyRdnWithTaintedDN(t *testing.T) {
	code := `
def rename_entry(params)
  newrdn = params[:newrdn]
  ldap.modify_rdn(olddn: "cn=user,ou=People", newrdn: newrdn, delete_on_rdn: true)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> ldap.modify_rdn()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_FilterContains(t *testing.T) {
	code := `
def search(params)
  q = params[:q]
  filter = Net::LDAP::Filter.contains("cn", q)
  ldap.search(filter: filter)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> Net::LDAP::Filter.contains()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_FilterBegins(t *testing.T) {
	code := `
def autocomplete(params)
  prefix = params[:prefix]
  filter = Net::LDAP::Filter.begins("uid", prefix)
  ldap.search(filter: filter)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> Net::LDAP::Filter.begins()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_FilterEnds(t *testing.T) {
	code := `
def suffix_match(params)
	suffix = params[:suffix]
	filter = Net::LDAP::Filter.ends("mail", suffix)
	ldap.search(filter: filter)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> Net::LDAP::Filter.ends()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_FilterExtensible(t *testing.T) {
	code := `
def ext_match(params)
  val = params[:val]
  filter = Net::LDAP::Filter.ex("cn:caseExactMatch:", val)
  ldap.search(filter: filter)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> Net::LDAP::Filter.ex()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_LDAP_FilterConstruct(t *testing.T) {
	code := `
def raw_filter(params)
  expr = params[:filter]
  filter = Net::LDAP::Filter.construct(expr)
  ldap.search(filter: filter)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for params -> Net::LDAP::Filter.construct()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — LDAP sanitizer (Net::LDAP::DN.escape neutralizes DN taint)
// =========================================================================

func TestRuby_LDAP_DNEscapeSanitizer(t *testing.T) {
	code := `
def create(params)
  user = params[:username]
  safe = Net::LDAP::DN.escape(user)
  ldap.add(dn: "cn=" + safe + ",ou=People", attributes: {cn: safe})
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected Net::LDAP::DN.escape to neutralize LDAP taint")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
