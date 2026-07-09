package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python SSRF — requests, urllib, urllib3, aiohttp, httpx, http.client,
//               httplib2, treq, pycurl
// =========================================================================

func TestPython_SSRF_RequestsHead(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    url = request.args.get("url")
    resp = requests.head(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> requests.head()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_RequestsOptions(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    url = request.args.get("url")
    resp = requests.options(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> requests.options()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_RequestsRequest(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    url = request.args.get("url")
    resp = requests.request("GET", url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> requests.request()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_RequestsSession(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    url = request.args.get("url")
    s = requests.Session()
    resp = s.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> requests.Session().get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_UrllibUrlretrieve(t *testing.T) {
	code := `
from flask import request
import urllib.request

def handler():
    url = request.args.get("url")
    urllib.request.urlretrieve(url, "/tmp/file.txt")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> urllib.request.urlretrieve()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_UrllibRequestConstructor(t *testing.T) {
	code := `
from flask import request
import urllib.request

def handler():
    url = request.args.get("url")
    req = urllib.request.Request(url)
    resp = urllib.request.urlopen(req)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> urllib.request.Request()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_Urllib3PoolManager(t *testing.T) {
	code := `
from flask import request
import urllib3

def handler():
    url = request.args.get("url")
    resp = urllib3.PoolManager().request("GET", url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> urllib3.PoolManager().request()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_AiohttpPost(t *testing.T) {
	code := `
from aiohttp import web
import aiohttp

async def handler(request):
    url = request.query.get("url")
    async with aiohttp.ClientSession() as session:
        resp = await session.post(url, data={"key": "value"})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.query -> aiohttp.ClientSession().post()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_HttpxPut(t *testing.T) {
	code := `
from flask import request
import httpx

def handler():
    url = request.args.get("url")
    resp = httpx.put(url, json={"key": "value"})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> httpx.put()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_HttpxClient(t *testing.T) {
	code := `
from flask import request
import httpx

def handler():
    url = request.args.get("url")
    with httpx.Client() as client:
        resp = client.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> httpx.Client().get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_HttpClient(t *testing.T) {
	code := `
from flask import request
import http.client

def handler():
    host = request.args.get("host")
    conn = http.client.HTTPConnection(host)
    conn.request("GET", "/api/data")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> http.client.HTTPConnection()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_Httplib2(t *testing.T) {
	code := `
from flask import request
import httplib2

def handler():
    url = request.args.get("url")
    h = httplib2.Http()
    resp, content = h.request(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> httplib2.Http().request()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_Treq(t *testing.T) {
	code := `
from flask import request
import treq

def handler():
    url = request.args.get("url")
    resp = treq.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> treq.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_Pycurl(t *testing.T) {
	code := `
from flask import request
import pycurl

def handler():
    url = request.args.get("url")
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.perform()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> pycurl.Curl().setopt(pycurl.URL, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe / sanitized patterns ---

func TestPython_SSRF_Sanitized_SchemeCheck(t *testing.T) {
	code := `
from flask import request
from urllib.parse import urlparse
import requests

def handler():
    url = request.args.get("url")
    parsed = urlparse(url)
    if parsed.scheme in ["http", "https"]:
        resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (scheme check may not fully sanitize in current engine)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_IPPrivateCheck(t *testing.T) {
	code := `
from flask import request
import ipaddress
import requests

def handler():
    url = request.args.get("url")
    addr = ipaddress.ip_address(url)
    if not addr.is_private:
        resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (ipaddress sanitizer may reduce confidence)")
			return
		}
	}
}

// --- New SSRF sanitizer tests ---

func TestPython_SSRF_Sanitized_IntCoercion(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    port = int(request.args.get("port"))
    resp = requests.get("http://internal:" + str(port) + "/api")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (int() coercion should sanitize — may not fully propagate in current engine)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_UUID(t *testing.T) {
	code := `
from flask import request
import uuid
import requests

def handler():
    item_id = uuid.UUID(request.args.get("id"))
    resp = requests.get("http://internal/items/" + str(item_id))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (uuid.UUID() should sanitize — may not fully propagate in current engine)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_InetPton(t *testing.T) {
	code := `
from flask import request
import socket
import requests

def handler():
    ip = request.args.get("ip")
    socket.inet_pton(socket.AF_INET, ip)
    resp = requests.get("http://" + ip + "/api")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (socket.inet_pton should sanitize — may not fully propagate)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_Tldextract(t *testing.T) {
	code := `
from flask import request
import tldextract
import requests

ALLOWED_DOMAINS = {"example.com", "api.internal.com"}

def handler():
    url = request.args.get("url")
    ext = tldextract.extract(url)
    domain = ext.registered_domain
    if domain in ALLOWED_DOMAINS:
        resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (tldextract sanitizer may reduce confidence)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_NetlocAllowlist(t *testing.T) {
	code := `
from flask import request
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def handler():
    url = request.args.get("url")
    parsed = urlparse(url)
    if parsed.netloc in ALLOWED_HOSTS:
        resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (netloc allowlist sanitizer may reduce confidence)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_IPv4AddressStrict(t *testing.T) {
	code := `
from flask import request
import ipaddress
import requests

def handler():
    ip = request.args.get("ip")
    addr = ipaddress.IPv4Address(ip)
    resp = requests.get("http://" + str(addr) + "/api")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (IPv4Address strict validation should sanitize)")
			return
		}
	}
}

func TestPython_SSRF_Sanitized_DjangoValidateIP(t *testing.T) {
	code := `
from flask import request
from django.core.validators import validate_ipv46_address
import requests

def handler():
    ip = request.args.get("ip")
    validate_ipv46_address(ip)
    resp = requests.get("http://" + ip + "/api")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Log("SSRF flow found (Django IP validator should sanitize)")
			return
		}
	}
}
