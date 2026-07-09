package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// JavaScript — ldapjs / ldapts / activedirectory LDAP injection sinks (CWE-90)
// =========================================================================

func TestJS_LDAPjs_AddWithTaintedDN(t *testing.T) {
	code := `
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.post('/users', (req, res) => {
  const username = req.body.username;
  const dn = "cn=" + username + ",ou=people,dc=example,dc=com";
  const client = ldap.createClient({ url: 'ldap://localhost' });
  client.add(dn, { cn: username, objectclass: 'person' }, (err) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.body -> client.add()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_LDAPjs_DelWithTaintedDN(t *testing.T) {
	code := `
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.delete('/users/:id', (req, res) => {
  const id = req.params.id;
  const dn = "cn=" + id + ",ou=people,dc=example,dc=com";
  const client = ldap.createClient({ url: 'ldap://localhost' });
  client.del(dn, (err) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.params -> client.del()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_LDAPjs_ModifyDNWithTaintedDN(t *testing.T) {
	code := `
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.post('/rename', (req, res) => {
  const oldName = req.body.oldName;
  const newName = req.body.newName;
  const oldDN = "cn=" + oldName + ",ou=people,dc=example,dc=com";
  const newDN = "cn=" + newName + ",ou=people,dc=example,dc=com";
  const client = ldap.createClient({ url: 'ldap://localhost' });
  client.modifyDN(oldDN, newDN, (err) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.body -> client.modifyDN()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_LDAPjs_CompareWithTaintedDN(t *testing.T) {
	code := `
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.post('/verify', (req, res) => {
  const username = req.body.username;
  const pass = req.body.password;
  const dn = "cn=" + username + ",ou=people,dc=example,dc=com";
  const client = ldap.createClient({ url: 'ldap://localhost' });
  client.compare(dn, 'userPassword', pass, (err, matched) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.body -> client.compare()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_LDAPjs_ExopWithTaintedValue(t *testing.T) {
	code := `
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.post('/exop', (req, res) => {
  const token = req.body.token;
  const client = ldap.createClient({ url: 'ldap://localhost' });
  client.exop('1.3.6.1.4.1.4203.1.11.3', token, (err, value) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.body -> client.exop()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ActiveDirectory_AuthenticateWithTaintedUser(t *testing.T) {
	code := `
const express = require('express');
const ActiveDirectory = require('activedirectory2');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const ad = new ActiveDirectory({ url: 'ldap://dc.example.com' });
  ad.authenticate(username, password, (err, authenticated) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.body -> ad.authenticate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ActiveDirectory_FindUserWithTaintedFilter(t *testing.T) {
	code := `
const express = require('express');
const ActiveDirectory = require('activedirectory2');
const app = express();

app.get('/find', (req, res) => {
  const q = req.query.q;
  const filter = "(&(objectClass=user)(sAMAccountName=" + q + "))";
  const ad = new ActiveDirectory({ url: 'ldap://dc.example.com' });
  ad.findUser(filter, (err, user) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.query -> ad.findUser()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ActiveDirectory_FindGroupWithTaintedFilter(t *testing.T) {
	code := `
const express = require('express');
const ActiveDirectory = require('activedirectory2');
const app = express();

app.get('/group', (req, res) => {
  const groupName = req.query.group;
  const filter = "(&(objectClass=group)(cn=" + groupName + "))";
  const ad = new ActiveDirectory({ url: 'ldap://dc.example.com' });
  ad.findGroup(filter, (err, group) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow for req.query -> ad.findGroup()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_LDAPjs_AddWithSanitizedDN(t *testing.T) {
	code := `
const express = require('express');
const ldap = require('ldapjs');
const ldapEscape = require('ldap-escape');
const app = express();

app.post('/users', (req, res) => {
  const username = req.body.username;
  const escaped = ldapEscape.dn(username);
  const dn = "cn=" + escaped + ",ou=people,dc=example,dc=com";
  const client = ldap.createClient({ url: 'ldap://localhost' });
  client.add(dn, { objectclass: 'person' }, (err) => {});
});
`
	flows := Analyze(code, "/app/routes.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected NO LDAP flow when ldapEscape.dn sanitizer is used")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
