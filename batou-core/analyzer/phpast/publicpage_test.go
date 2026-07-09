package phpast

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// scanPublicPage runs the PublicPageSinkAnalyzer in isolation against the
// given PHP source, returning all findings it produced.
func scanPublicPage(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangPHP)
	if tree == nil {
		t.Fatal("ast.Parse returned nil tree")
	}
	ctx := &rules.ScanContext{
		FilePath: "/app/Controller.php",
		Content:  code,
		Language: rules.LangPHP,
		Tree:     tree,
	}
	a := &PublicPageSinkAnalyzer{}
	return a.Scan(ctx)
}

func hasFinding(findings []rules.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findingsForRule(findings []rules.Finding, ruleID string) []rules.Finding {
	var out []rules.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// --- AT 1: Docblock @PublicPage + direct HTTP-client sink fires. ---
func TestPublicPage_Docblock_HTTPClient(t *testing.T) {
	code := `<?php
namespace OCA\Test;
use OCP\AppFramework\Controller;

class TestRemoteController extends Controller {
    /**
     * @PublicPage
     * @NoCSRFRequired
     */
    public function testRemote($remote) {
        $url = "https://" . $remote . "/path";
        $response = $this->client->get($url);
        return $response->getBody();
    }
}`
	findings := scanPublicPage(t, code)
	if !hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("expected BATOU-OWNCLOUD-AST-001, got %d findings", len(findings))
	}
	for _, f := range findings {
		if f.RuleID != "BATOU-OWNCLOUD-AST-001" {
			continue
		}
		if f.Severity != rules.Critical {
			t.Errorf("expected Critical, got %s", f.Severity)
		}
		if f.CWEID != "CWE-918" {
			t.Errorf("expected CWE-918 (SSRF), got %s", f.CWEID)
		}
		if f.SinkCategory != "http_client" {
			t.Errorf("expected SinkCategory http_client, got %q", f.SinkCategory)
		}
		if f.SourceCategory != "user_input" {
			t.Errorf("expected SourceCategory user_input, got %q", f.SourceCategory)
		}
		if f.ConfidenceScore < 0.8 {
			t.Errorf("expected ConfidenceScore >= 0.8, got %f", f.ConfidenceScore)
		}
	}
}

// --- AT 2: PHP-8 #[PublicPage] attribute + HTTP-client sink fires. ---
func TestPublicPage_Attribute_HTTPClient(t *testing.T) {
	code := `<?php
namespace OCA\Test;
use OCP\AppFramework\Controller;

class TestRemoteController extends Controller {
    #[PublicPage]
    #[NoCSRFRequired]
    public function ping($host) {
        return $this->httpClient->post("https://" . $host . "/probe");
    }
}`
	findings := scanPublicPage(t, code)
	if !hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("expected BATOU-OWNCLOUD-AST-001 on #[PublicPage], got: %v", findings)
	}
}

// --- Fully-qualified attribute name. ---
func TestPublicPage_QualifiedAttribute_HTTPClient(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    #[\OCP\AppFramework\Http\Attribute\PublicPage]
    public function probe($url) {
        $this->client->get($url);
    }
}`
	findings := scanPublicPage(t, code)
	if !hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("expected BATOU-OWNCLOUD-AST-001 on qualified attribute, got: %v", findings)
	}
}

// --- AT 3: Method WITHOUT @PublicPage with the same SSRF pattern does NOT fire. ---
func TestPublicPage_NotPublic_NoFire(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /**
     * Internal helper. No annotation.
     */
    public function fetchPrivate($remote) {
        $url = "https://" . $remote . "/path";
        $response = $this->client->get($url);
        return $response;
    }
}`
	findings := scanPublicPage(t, code)
	if hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("did not expect BATOU-OWNCLOUD-AST-001 on non-public method, got: %+v", findings)
	}
}

// --- AT 4: NoAdminRequired alone should NOT count as @PublicPage. ---
func TestPublicPage_NoAdminRequired_Alone_NoFire(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /**
     * @NoAdminRequired
     */
    public function adminish($remote) {
        $this->client->get($remote);
    }
}`
	findings := scanPublicPage(t, code)
	if hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("did not expect BATOU-OWNCLOUD-AST-001 on @NoAdminRequired-only method")
	}
}

// --- Public-page method using non-parameter variable is ignored. ---
func TestPublicPage_NoParamFlow_NoFire(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /** @PublicPage */
    public function status() {
        $this->client->get("https://example.com/status");
    }
}`
	findings := scanPublicPage(t, code)
	if hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("did not expect a finding when param doesn't flow to sink")
	}
}

// --- File-read sink (file_get_contents on local path) fires with CWE-22. ---
func TestPublicPage_FileRead_CWE22(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /** @PublicPage */
    public function show($file) {
        return file_get_contents("/var/data/" . $file);
    }
}`
	findings := scanPublicPage(t, code)
	frs := findingsForRule(findings, "BATOU-OWNCLOUD-AST-001")
	if len(frs) == 0 {
		t.Fatalf("expected file-read finding, got: %v", findings)
	}
	if frs[0].CWEID != "CWE-22" {
		t.Errorf("expected CWE-22, got %s", frs[0].CWEID)
	}
	if frs[0].SinkCategory != "file_read" {
		t.Errorf("expected file_read, got %q", frs[0].SinkCategory)
	}
}

// --- file_get_contents with an http:// URL is reclassified as HTTP/SSRF. ---
func TestPublicPage_FileGetContents_URL_isSSRF(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /** @PublicPage */
    public function probe($host) {
        return file_get_contents("https://" . $host . "/.well-known/x");
    }
}`
	findings := scanPublicPage(t, code)
	frs := findingsForRule(findings, "BATOU-OWNCLOUD-AST-001")
	if len(frs) == 0 {
		t.Fatalf("expected SSRF finding via file_get_contents URL, got nothing")
	}
	if frs[0].CWEID != "CWE-918" {
		t.Errorf("expected CWE-918 (SSRF) for file_get_contents URL, got %s", frs[0].CWEID)
	}
}

// --- Process-exec sink fires with CWE-78. ---
func TestPublicPage_Exec_CWE78(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /** @PublicPage */
    public function run($cmd) {
        shell_exec("echo " . $cmd);
    }
}`
	findings := scanPublicPage(t, code)
	frs := findingsForRule(findings, "BATOU-OWNCLOUD-AST-001")
	if len(frs) == 0 {
		t.Fatalf("expected process_exec finding")
	}
	if frs[0].CWEID != "CWE-78" {
		t.Errorf("expected CWE-78, got %s", frs[0].CWEID)
	}
	if frs[0].SinkCategory != "process_exec" {
		t.Errorf("expected process_exec, got %q", frs[0].SinkCategory)
	}
}

// --- File-write sink fires with CWE-22. ---
func TestPublicPage_FileWrite(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /** @PublicPage */
    public function upload($name, $blob) {
        file_put_contents("/tmp/" . $name, $blob);
    }
}`
	findings := scanPublicPage(t, code)
	frs := findingsForRule(findings, "BATOU-OWNCLOUD-AST-001")
	if len(frs) == 0 {
		t.Fatalf("expected file_write finding")
	}
	if frs[0].SinkCategory != "file_write" {
		t.Errorf("expected file_write, got %q", frs[0].SinkCategory)
	}
}

// --- curl_setopt(CURLOPT_URL, $param) is SSRF. ---
func TestPublicPage_CurlSetopt(t *testing.T) {
	code := `<?php
namespace OCA\Test;
class C {
    /** @PublicPage */
    public function fetch($u) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $u);
        curl_exec($ch);
    }
}`
	findings := scanPublicPage(t, code)
	frs := findingsForRule(findings, "BATOU-OWNCLOUD-AST-001")
	if len(frs) == 0 {
		t.Fatalf("expected SSRF finding for curl_setopt(CURLOPT_URL,$u)")
	}
	if frs[0].CWEID != "CWE-918" {
		t.Errorf("expected CWE-918, got %s", frs[0].CWEID)
	}
}

// --- testRemote-shape pattern: helper call takes the public param AND an
// HTTP client as siblings — fires (this is the ownCloud headline miss). ---
func TestPublicPage_TestRemotePattern(t *testing.T) {
	code := `<?php
namespace OCA\Files_Sharing\Controllers;

class ExternalSharesController {
    /**
     * @PublicPage
     * @NoOutgoingFederatedSharingRequired
     * @param string $remote
     */
    public function testRemote($remote) {
        $response = $this->externalManager->testRemoteUrl($this->clientService, $remote);
        return $response;
    }
}`
	findings := scanPublicPage(t, code)
	frs := findingsForRule(findings, "BATOU-OWNCLOUD-AST-001")
	if len(frs) == 0 {
		t.Fatalf("expected BATOU-OWNCLOUD-AST-001 on testRemote helper-call pattern; got: %v", findings)
	}
	if !strings.Contains(frs[0].Description, "testRemote") {
		t.Errorf("description should name the method, got: %s", frs[0].Description)
	}
}

// --- File without @PublicPage anywhere is fast-pathed (no findings). ---
func TestPublicPage_FastPath_NoAnnotation(t *testing.T) {
	code := `<?php
class C {
    public function f($x) {
        $this->client->get($x);
        shell_exec("ls " . $x);
    }
}`
	findings := scanPublicPage(t, code)
	if hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("expected no findings when @PublicPage absent")
	}
}

// --- Variable name boundary: $remote should not match $remoteHost. ---
func TestPublicPage_VariableBoundary(t *testing.T) {
	code := `<?php
class C {
    /** @PublicPage */
    public function f($x) {
        // local variable $xLong should NOT count as $x
        $xLong = "https://example.com/safe";
        $this->client->get($xLong);
    }
}`
	findings := scanPublicPage(t, code)
	if hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("expected no findings — $x not used (prefix-match guard)")
	}
}

// --- @PublicPage appearing only as a textual mention in a @param description
// should not count. ---
func TestPublicPage_TextualMentionInOtherTag(t *testing.T) {
	code := `<?php
class C {
    /**
     * @param string $remote The remote URL (this is not a @PublicPage method despite mentioning it)
     */
    public function f($remote) {
        $this->client->get($remote);
    }
}`
	// We *do* expect this NOT to fire: the comment line doesn't start with
	// @PublicPage, only mentions it inside a @param description.
	findings := scanPublicPage(t, code)
	if hasFinding(findings, "BATOU-OWNCLOUD-AST-001") {
		t.Fatalf("expected no finding when @PublicPage is only textually mentioned in a @param description")
	}
}
