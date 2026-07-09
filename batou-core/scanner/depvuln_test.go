package scanner_test

// DEPENDENCY DATAFLOW-REACHABILITY (BATOU-DEPVULN-*).
//
// These tests drive the full scanner pipeline (regex + AST + taint + dedup)
// and assert that:
//
//   - When UNTRUSTED data reaches a known-vulnerable library function (a sink
//     tagged with an Advisory in the taint catalog), the finding is re-labelled
//     BATOU-DEPVULN-<category>, cites the published advisory (CVE/GHSA/CWE), and
//     carries source/sink taint metadata + the structured taint_path.
//   - The SAME function called with a CONSTANT / trusted argument is NOT flagged
//     by DEPVULN (reachability, not mere usage).
//   - Exactly ONE finding lands per (line, CWE) even when a usage-based AST rule
//     also matches the dangerous call (no double-firing — dedup keeps the
//     higher-tier DEPVULN/taint winner, which carries the advisory).
//
// File paths are deliberately non-test (/app/...) so fpfilter.IsTestFile does
// not cap confidence and suppress the findings.
import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/deser"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/xss"

	// AST analyzers — exercise the no-double-fire path: these flag the
	// dangerous function on usage, so dedup must collapse with the DEPVULN
	// taint finding on the same line+CWE.
	_ "github.com/turenlabs/batou-core/analyzer/javaast"
	_ "github.com/turenlabs/batou-core/analyzer/pyast"

	// Taint engine + language catalogs (where Advisory metadata lives) +
	// the taint rule that converts flows into findings.
	_ "github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
)

// depvulnFinding returns the first BATOU-DEPVULN-* finding in the result, or
// nil if none fired.
func depvulnFinding(r *testutil.ScanResult) *rules.Finding {
	for i := range r.Findings {
		if strings.HasPrefix(r.Findings[i].RuleID, "BATOU-DEPVULN-") {
			return &r.Findings[i]
		}
	}
	return nil
}

// hasDepvuln reports whether any DEPVULN finding cites the wanted advisory ID.
func hasDepvulnWithAdvisory(r *testutil.ScanResult, advisoryID string) bool {
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, "BATOU-DEPVULN-") && f.AdvisoryID == advisoryID {
			return true
		}
	}
	return false
}

type depvulnCase struct {
	name       string
	path       string // non-test path so findings are not confidence-capped
	content    string
	advisoryID string // expected AdvisoryID on the DEPVULN finding
	cwe        string // expected CWE
}

// vulnerableCases: untrusted data reaches a known-vulnerable library function.
var vulnerableCases = []depvulnCase{
	{
		name:       "python_pickle_loads",
		path:       "/app/handlers/profile.py",
		advisoryID: "CWE-502",
		cwe:        "CWE-502",
		content: `import pickle
from flask import request


def load_profile():
    blob = request.data
    obj = pickle.loads(blob)
    return obj
`,
	},
	{
		name:       "python_yaml_load",
		path:       "/app/handlers/config.py",
		advisoryID: "CVE-2017-18342",
		cwe:        "CWE-502",
		content: `import yaml
from flask import request


def parse_config():
    body = request.form["config"]
    cfg = yaml.load(body)
    return cfg
`,
	},
	{
		name:       "java_log4shell_jndimanager",
		path:       "/app/LogController.java",
		advisoryID: "CVE-2021-44228",
		cwe:        "CWE-917",
		content: `import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.core.net.JndiManager;

public class LogController {
    public Object handle(HttpServletRequest request) {
        String name = request.getHeader("X-Resource");
        JndiManager jndiManager = JndiManager.getDefaultManager();
        Object o = jndiManager.lookup(name);
        return o;
    }
}
`,
	},
	{
		name:       "java_snakeyaml_load",
		path:       "/app/YamlController.java",
		advisoryID: "CVE-2022-1471",
		cwe:        "CWE-502",
		content: `import javax.servlet.http.HttpServletRequest;
import org.yaml.snakeyaml.Yaml;

public class YamlController {
    public Object handle(HttpServletRequest request) {
        String body = request.getParameter("doc");
        Yaml yaml = new Yaml();
        Object o = yaml.load(body);
        return o;
    }
}
`,
	},
	{
		name:       "ruby_marshal_load",
		path:       "/app/jobs_controller.rb",
		advisoryID: "CWE-502",
		cwe:        "CWE-502",
		content: `class JobsController < ApplicationController
  def restore
    blob = params[:state]
    obj = Marshal.load(blob)
    render json: obj
  end
end
`,
	},
	{
		name:       "ruby_yaml_load",
		path:       "/app/imports_controller.rb",
		advisoryID: "CVE-2013-0156",
		cwe:        "CWE-502",
		content: `class ImportsController < ApplicationController
  def import
    doc = request.raw_post
    cfg = YAML.load(doc)
    render json: cfg
  end
end
`,
	},
	{
		name:       "js_node_serialize_unserialize",
		path:       "/app/server.js",
		advisoryID: "CVE-2017-5941",
		cwe:        "CWE-502",
		content: `const serialize = require('node-serialize');

function restore(req) {
  const payload = req.body.state;
  const obj = serialize.unserialize(payload);
  return obj;
}
`,
	},
}

// TestDepVuln_ReachableKnownVuln_Fires asserts that each vulnerable case
// produces a BATOU-DEPVULN-* finding citing the correct advisory + CWE, with
// taint metadata and a structured taint_path.
func TestDepVuln_ReachableKnownVuln_Fires(t *testing.T) {
	for _, tc := range vulnerableCases {
		t.Run(tc.name, func(t *testing.T) {
			r := testutil.ScanContent(t, tc.path, tc.content)

			f := depvulnFinding(r)
			if f == nil {
				t.Fatalf("%s: no BATOU-DEPVULN-* finding; got %d findings: %s",
					tc.name, len(r.Findings), summarize(r.Findings))
			}
			if f.AdvisoryID != tc.advisoryID {
				t.Errorf("advisory_id = %q, want %q", f.AdvisoryID, tc.advisoryID)
			}
			if f.Advisory == "" {
				t.Errorf("advisory text is empty; want a citation referencing %s", tc.advisoryID)
			}
			if !strings.Contains(f.Advisory, tc.advisoryID) {
				t.Errorf("advisory %q does not mention %q", f.Advisory, tc.advisoryID)
			}
			if f.CWEID != tc.cwe {
				t.Errorf("cwe = %q, want %q", f.CWEID, tc.cwe)
			}
			// Reachability finding must carry the data-flow evidence.
			if f.SourceCategory == "" || f.SinkCategory == "" {
				t.Errorf("missing taint metadata: source=%q sink=%q", f.SourceCategory, f.SinkCategory)
			}
			if len(f.TaintPath) < 2 {
				t.Errorf("expected a source→sink taint_path, got %d steps", len(f.TaintPath))
			}
			// The finding must stay TierTaint (carry the taint-analysis tag) so
			// `batou scan` does not drop it as a regex-tier hit.
			if !hasTag(f.Tags, "taint-analysis") {
				t.Errorf("DEPVULN finding lost the taint-analysis tag; tags=%v", f.Tags)
			}
			if !hasTag(f.Tags, "known-vuln") {
				t.Errorf("DEPVULN finding missing known-vuln tag; tags=%v", f.Tags)
			}
			// Title cites the advisory for the AI feedback loop.
			if !strings.Contains(f.Title, tc.advisoryID) {
				t.Errorf("title %q does not cite advisory %q", f.Title, tc.advisoryID)
			}
		})
	}
}

// safeCases: the SAME known-vulnerable function called with a constant /
// trusted argument. No untrusted source reaches it, so DEPVULN must NOT fire
// (reachability, not usage).
var safeCases = []depvulnCase{
	{
		name: "python_pickle_constant",
		path: "/app/bootstrap_pickle.py",
		content: `import pickle


def load_builtin():
    constant = b"\x80\x04K\x01."
    return pickle.loads(constant)
`,
	},
	{
		name: "python_yaml_literal",
		path: "/app/bootstrap_yaml.py",
		content: `import yaml


def parse_builtin():
    literal = "name: batou"
    return yaml.load(literal)
`,
	},
	{
		name: "java_jndi_constant",
		path: "/app/Bootstrap.java",
		content: `import org.apache.logging.log4j.core.net.JndiManager;

public class Bootstrap {
    public Object resolve() {
        String constant = "java:comp/env/jdbc/primary";
        JndiManager jndiManager = JndiManager.getDefaultManager();
        return jndiManager.lookup(constant);
    }
}
`,
	},
	{
		name: "java_snakeyaml_literal",
		path: "/app/Defaults.java",
		content: `import org.yaml.snakeyaml.Yaml;

public class Defaults {
    public Object config() {
        String literal = "name: batou";
        Yaml yaml = new Yaml();
        return yaml.load(literal);
    }
}
`,
	},
	{
		name: "ruby_marshal_constant",
		path: "/app/seed_marshal.rb",
		content: `class SeedMarshal
  def restore_default
    constant = "\x04\b0"
    Marshal.load(constant)
  end
end
`,
	},
	{
		name: "js_node_serialize_literal",
		path: "/app/bootstrap.js",
		content: `const serialize = require('node-serialize');

function loadDefault() {
  const constant = '{"name":"batou"}';
  return serialize.unserialize(constant);
}
`,
	},
}

// TestDepVuln_ConstantArg_NotFlagged asserts that a known-vulnerable function
// reached only by a constant / trusted argument does NOT produce a DEPVULN
// finding. (Usage-based AST findings without an advisory may still appear; we
// only assert the absence of the reachability-based DEPVULN finding.)
func TestDepVuln_ConstantArg_NotFlagged(t *testing.T) {
	for _, tc := range safeCases {
		t.Run(tc.name, func(t *testing.T) {
			r := testutil.ScanContent(t, tc.path, tc.content)
			if f := depvulnFinding(r); f != nil {
				t.Errorf("%s: unexpected BATOU-DEPVULN finding (%s, advisory=%q) on a constant-arg call; reachability requires untrusted input",
					tc.name, f.RuleID, f.AdvisoryID)
			}
			// Sanity: no DEPVULN finding for any advisory.
			for _, id := range []string{"CVE-2021-44228", "CVE-2022-1471", "CVE-2017-18342", "CVE-2013-0156", "CVE-2017-5941", "CWE-502"} {
				if hasDepvulnWithAdvisory(r, id) {
					t.Errorf("%s: DEPVULN finding cited %s on a safe constant-arg call", tc.name, id)
				}
			}
		})
	}
}

// TestDepVuln_NoDoubleFire asserts the no-double-firing invariant: a known-vuln
// function (SnakeYAML / pickle) that a usage-based AST rule ALSO matches yields
// exactly ONE finding per (line, CWE) — dedup keeps the higher-tier DEPVULN
// winner carrying the advisory, not two findings on one line.
func TestDepVuln_NoDoubleFire(t *testing.T) {
	cases := []depvulnCase{
		{
			name:       "java_snakeyaml_single_finding",
			path:       "/app/YamlController.java",
			advisoryID: "CVE-2022-1471",
			cwe:        "CWE-502",
			content: `import javax.servlet.http.HttpServletRequest;
import org.yaml.snakeyaml.Yaml;

public class YamlController {
    public Object handle(HttpServletRequest request) {
        String body = request.getParameter("doc");
        Yaml yaml = new Yaml();
        Object o = yaml.load(body);
        return o;
    }
}
`,
		},
		{
			name:       "python_pickle_single_finding",
			path:       "/app/profile.py",
			advisoryID: "CWE-502",
			cwe:        "CWE-502",
			content: `import pickle
from flask import request


def load_profile():
    blob = request.data
    obj = pickle.loads(blob)
    return obj
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testutil.ScanContent(t, tc.path, tc.content)

			// Count distinct findings on the sink line carrying this CWE.
			var sinkLine int
			for _, f := range r.Findings {
				if strings.HasPrefix(f.RuleID, "BATOU-DEPVULN-") {
					sinkLine = f.LineNumber
				}
			}
			if sinkLine == 0 {
				t.Fatalf("%s: no DEPVULN finding fired; got: %s", tc.name, summarize(r.Findings))
			}

			n := 0
			for _, f := range r.Findings {
				if f.LineNumber == sinkLine && f.CWEID == tc.cwe {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%s: expected exactly 1 finding on line %d for %s (no double-fire), got %d: %s",
					tc.name, sinkLine, tc.cwe, n, summarize(r.Findings))
			}

			// And the surviving winner must be the DEPVULN one with the advisory.
			if !hasDepvulnWithAdvisory(r, tc.advisoryID) {
				t.Errorf("%s: dedup winner is not the advisory-bearing DEPVULN finding", tc.name)
			}
		})
	}
}

func hasTag(tags []string, want string) bool {
	for _, tg := range tags {
		if tg == want {
			return true
		}
	}
	return false
}

func summarize(findings []rules.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.RuleID)
		b.WriteString("@L")
		b.WriteString(itoa(f.LineNumber))
		if f.AdvisoryID != "" {
			b.WriteString("(" + f.AdvisoryID + ")")
		}
		b.WriteString(" ")
	}
	if b.Len() == 0 {
		return "<none>"
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
