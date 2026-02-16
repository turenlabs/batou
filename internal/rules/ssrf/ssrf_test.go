package ssrf

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-SSRF-001: URL From User Input ---

func TestSSRF001_Go_HTTPGet(t *testing.T) {
	content := `url := r.URL.Query().Get("url")
resp, _ := http.Get(targetURL)`
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Python_Requests(t *testing.T) {
	content := `url = request.args.get('url')
resp = requests.get(url)`
	result := testutil.ScanContent(t, "/app/proxy.py", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_JS_Fetch(t *testing.T) {
	content := `const url = req.query.url;
const response = await fetch(url);`
	result := testutil.ScanContent(t, "/app/proxy.ts", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_JS_Axios(t *testing.T) {
	content := `const url = req.query.target;
const resp = await axios.get(url);`
	result := testutil.ScanContent(t, "/app/proxy.ts", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_PHP_Curl(t *testing.T) {
	content := `<?php
curl_setopt($ch, CURLOPT_URL, $_GET['url']);`
	result := testutil.ScanContent(t, "/app/proxy.php", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Fixture_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/ssrf_basic.go")
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	hasSSRF := testutil.HasFinding(result, "BATOU-SSRF-001") || testutil.HasFinding(result, "BATOU-SSRF-004")
	if !hasSSRF {
		t.Errorf("expected SSRF finding in ssrf_basic.go, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestSSRF001_Fixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/ssrf_basic.ts")
	result := testutil.ScanContent(t, "/app/proxy.ts", content)
	hasSSRF := testutil.HasFinding(result, "BATOU-SSRF-001") || testutil.HasFinding(result, "BATOU-SSRF-004")
	if !hasSSRF {
		t.Errorf("expected SSRF finding in ssrf_basic.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- BATOU-SSRF-002: Internal Network Access ---

func TestSSRF002_CloudMetadata(t *testing.T) {
	content := `resp = requests.get("http://169.254.169.254/latest/meta-data/")`
	result := testutil.ScanContent(t, "/app/cloud.py", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-002")
}

func TestSSRF002_InternalIP_JS(t *testing.T) {
	content := `const resp = await fetch("http://192.168.1.100:8080/admin");`
	result := testutil.ScanContent(t, "/app/internal.ts", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-002")
}

// --- BATOU-SSRF-003: DNS Rebinding ---

func TestSSRF003_Go_DNSLookupThenRequest(t *testing.T) {
	content := `ips, _ := net.LookupHost(hostname)
// validate IPs
resp, _ := http.Get("http://" + hostname + "/api")`
	result := testutil.ScanContent(t, "/app/resolver.go", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-SSRF-003", "BATOU-SSRF-005")
}

func TestSSRF003_Python_SocketResolve(t *testing.T) {
	content := `ip = socket.gethostbyname(hostname)
resp = requests.get("http://" + hostname + "/api")`
	result := testutil.ScanContent(t, "/app/resolver.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-SSRF-003", "BATOU-SSRF-005")
}

func TestSSRF003_JS_DNSResolve(t *testing.T) {
	content := `dns.resolve(hostname, (err, ips) => {
	fetch("http://" + hostname + "/api");
});`
	result := testutil.ScanContent(t, "/app/resolver.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-SSRF-003", "BATOU-SSRF-005")
}

// --- BATOU-SSRF-004: Redirect Following ---

func TestSSRF004_Go_NoCheckRedirect(t *testing.T) {
	content := `func proxy(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	client := &http.Client{}
	resp, _ := client.Get(url)
}`
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-004")
}

func TestSSRF004_Python_AllowRedirects(t *testing.T) {
	content := `url = request.args.get('url')
resp = requests.get(url, allow_redirects=True)`
	result := testutil.ScanContent(t, "/app/proxy.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-SSRF-001", "BATOU-SSRF-004")
}

func TestSSRF004_JS_FollowRedirects(t *testing.T) {
	content := `const url = req.query.url;
const resp = await got(url, { followRedirects: true });`
	result := testutil.ScanContent(t, "/app/proxy.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-SSRF-001", "BATOU-SSRF-004")
}

// --- BATOU-SSRF-001: Angular false positive exclusion ---

func TestSSRF001_Angular_HttpClient_Safe(t *testing.T) {
	// Angular HttpClient calls should NOT trigger SSRF — they are frontend HTTP calls
	content := `import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class UserService {
  constructor(private http: HttpClient) {}

  getUsers(): Observable<User[]> {
    return this.http.get<User[]>(apiUrl);
  }

  updateUser(user: User): Observable<User> {
    return this.http.put<User>(endpoint, user);
  }

  deleteUser(id: string): Observable<void> {
    return this.http.delete<void>(url);
  }
}`
	result := testutil.ScanContent(t, "/app/user.service.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Angular_HttpClient_Post_Safe(t *testing.T) {
	content := `import { HttpClient } from '@angular/common/http';

export class ApiService {
  constructor(private http: HttpClient) {}

  submitData(data: any): Observable<any> {
    return this.http.post<any>(targetUrl, data);
  }
}`
	result := testutil.ScanContent(t, "/app/api.service.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_NonAngular_Fetch_StillDetected(t *testing.T) {
	// Server-side fetch should still be detected even in .ts files
	content := `const url = req.query.url;
const response = await fetch(url);`
	result := testutil.ScanContent(t, "/app/proxy.ts", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

// --- BATOU-SSRF-001: Java server-side SSRF detection ---

func TestSSRF001_Java_URLOpenStream(t *testing.T) {
	content := `String url = request.getParameter("url");
InputStream is = new URL(url).openStream();`
	result := testutil.ScanContent(t, "/app/SsrfHandler.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Java_URLOpenConnection(t *testing.T) {
	content := `@RequestParam String targetUrl
URL url = new URL(targetUrl).openConnection();`
	result := testutil.ScanContent(t, "/app/ProxyController.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Java_RestTemplate(t *testing.T) {
	content := `String url = request.getParameter("url");
String result = restTemplate.getForObject(url, String.class);`
	result := testutil.ScanContent(t, "/app/ApiController.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Java_WebClient(t *testing.T) {
	content := `@RequestParam String serviceUrl
WebClient client = WebClient.create(serviceUrl);`
	result := testutil.ScanContent(t, "/app/WebClientController.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF001_Java_Fixture(t *testing.T) {
	if !testutil.FixtureExists("java/vulnerable/SsrfBasic.java") {
		t.Skip("Java SSRF fixture not available")
	}
	content := testutil.LoadFixture(t, "java/vulnerable/SsrfBasic.java")
	result := testutil.ScanContent(t, "/app/SsrfBasic.java", content)
	testutil.MustFindRule(t, result, "BATOU-SSRF-001")
}

// --- Safe fixture tests ---

func TestSSRF_Safe_Go(t *testing.T) {
	if !testutil.FixtureExists("go/safe/ssrf_safe.go") {
		t.Skip("safe SSRF fixture not available")
	}
	content := testutil.LoadFixture(t, "go/safe/ssrf_safe.go")
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSRF-001")
}

func TestSSRF_Safe_JS(t *testing.T) {
	if !testutil.FixtureExists("javascript/safe/ssrf_safe.ts") {
		t.Skip("safe SSRF fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/safe/ssrf_safe.ts")
	result := testutil.ScanContent(t, "/app/proxy.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-SSRF-001")
}
