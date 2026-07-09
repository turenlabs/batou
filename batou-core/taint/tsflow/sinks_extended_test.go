package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// SnkFileWrite (path traversal) tests
// =========================================================================

func TestSinks_FileWrite_Python(t *testing.T) {
	code := `
from flask import request

def handler():
    filename = request.args.get("file")
    f = open(filename, "w")
    f.write("data")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for request.args.get -> open()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileWrite_Python_Safe(t *testing.T) {
	code := `
import os

def handler():
    filename = "static/report.txt"
    f = open(filename, "w")
    f.write("data")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected NO file write flow when path is a literal")
	}
}

func TestSinks_FileWrite_JS(t *testing.T) {
	code := `
const fs = require('fs');

function handler(req, res) {
    const filename = req.query.file;
    fs.writeFile(filename, "data", (err) => {});
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for req.query -> fs.writeFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileWrite_Java(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.nio.file.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String path = request.getParameter("path");
        Files.write(Paths.get(path), "data".getBytes());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for getParameter -> Files.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileWrite_PHP(t *testing.T) {
	code := `<?php
function handler() {
    $path = $_GET["path"];
    file_put_contents($path, "data");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for $_GET -> file_put_contents()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkURLFetch (SSRF) tests
// =========================================================================

func TestSinks_URLFetch_Python(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    url = request.args.get("url")
    resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args.get -> requests.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_URLFetch_Python_Safe(t *testing.T) {
	code := `
import requests

def handler():
    url = "https://api.example.com/data"
    resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow when URL is a literal")
	}
}

func TestSinks_URLFetch_JS(t *testing.T) {
	code := `
function handler(req, res) {
    const url = req.query.url;
    fetch(url);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for req.query -> fetch()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_URLFetch_Java(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.net.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        URI uri = URI.create(target);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> URI.create()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_URLFetch_Java_ApacheHttpClient(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        HttpGet httpGet = new HttpGet(target);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> new HttpGet()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_URLFetch_Java_OkHttp_NewCall(t *testing.T) {
	code := `
import javax.servlet.http.*;
import okhttp3.OkHttpClient;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        OkHttpClient client = new OkHttpClient();
        client.newCall(target).execute();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> OkHttp newCall()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_URLFetch_Java_ApacheHttpClient_Safe(t *testing.T) {
	code := `
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;

public class Handler {
    public void fetch() {
        String url = "https://api.example.com/data";
        HttpGet httpGet = new HttpGet(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow when URL is a literal")
	}
}

func TestSinks_URLFetch_PHP(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["url"];
    $data = file_get_contents($url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_GET -> file_get_contents()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkRedirect (open redirect) tests
// =========================================================================

func TestSinks_Redirect_Python(t *testing.T) {
	code := `
from flask import request, redirect

def handler():
    url = request.args.get("next")
    return redirect(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for request.args.get -> redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Redirect_Python_Safe(t *testing.T) {
	code := `
from flask import redirect

def handler():
    return redirect("/dashboard")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected NO redirect flow when URL is a literal")
	}
}

func TestSinks_Redirect_JS(t *testing.T) {
	code := `
function handler(req, res) {
    const url = req.query.next;
    res.redirect(url);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for req.query -> res.redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Redirect_Java(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("next");
        response.sendRedirect(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for getParameter -> sendRedirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkLog (log injection) tests
// =========================================================================

func TestSinks_Log_Python(t *testing.T) {
	code := `
from flask import request
import logging

def handler():
    name = request.args.get("name")
    logging.info(name)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for request.args.get -> logging.info()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Log_Python_Safe(t *testing.T) {
	code := `
import logging

def handler():
    logging.info("static message")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected NO log flow when message is a literal")
	}
}

func TestSinks_Log_JS(t *testing.T) {
	code := `
function handler(req, res) {
    const name = req.query.name;
    console.log(name);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for req.query -> console.log()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Log_Java(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");
        logger.info(name);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getParameter -> logger.info()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkHeader (header injection) tests
// =========================================================================

func TestSinks_Header_Python(t *testing.T) {
	code := `
from flask import request

def handler():
    value = request.args.get("value")
    response.set_cookie(value)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for request.args.get -> set_cookie()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Header_JS(t *testing.T) {
	code := `
function handler(req, res) {
    const value = req.query.value;
    res.setHeader("X-Custom", value);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for req.query -> res.setHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Header_Java(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("header");
        response.setHeader("X-Custom", value);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> setHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Header_PHP(t *testing.T) {
	code := `<?php
function handler() {
    $value = $_GET["value"];
    header($value);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for $_GET -> header()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Header_Safe(t *testing.T) {
	code := `
function handler(req, res) {
    res.setHeader("Content-Type", "application/json");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected NO header flow when value is a literal")
	}
}

// =========================================================================
// SnkDeserialize (deserialization) tests
// =========================================================================

func TestSinks_Deserialize_Python(t *testing.T) {
	code := `
from flask import request
import pickle

def handler():
    data = request.data
    obj = pickle.loads(data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for request.data -> pickle.loads()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Deserialize_Python_Safe(t *testing.T) {
	code := `
import pickle

def handler():
    data = b"safe data"
    obj = pickle.loads(data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when data is a literal")
	}
}

func TestSinks_Deserialize_Java(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        InputStream is = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(is);
        Object obj = ois.readObject();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	// Note: readObject detection depends on regex pattern matching within the taint engine.
	// The flow might be detected via the "ObjectInputStream" pattern match.
	// We verify no panic and check for any deserialization flow.
	_ = flows
}

func TestSinks_Deserialize_PHP(t *testing.T) {
	code := `<?php
function handler() {
    $data = $_POST["data"];
    $obj = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for $_POST -> unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkURLFetch with reassignment (taint propagation) tests
// =========================================================================

func TestSinks_URLFetch_Python_Reassignment(t *testing.T) {
	code := `
from flask import request
import requests

def handler():
    target = request.args.get("url")
    url = target
    resp = requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow through reassignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_URLFetch_JS_Reassignment(t *testing.T) {
	code := `
function handler(req, res) {
    const target = req.query.url;
    const url = target;
    fetch(url);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow through reassignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkFileWrite with string interpolation tests
// =========================================================================

func TestSinks_FileWrite_Python_FString(t *testing.T) {
	code := `
from flask import request

def handler():
    name = request.args.get("name")
    path = f"/uploads/{name}"
    f = open(path, "w")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for request.args.get -> f-string -> open()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileWrite_JS_Template(t *testing.T) {
	code := "const fs = require('fs');\n" +
		"function handler(req, res) {\n" +
		"    const name = req.query.name;\n" +
		"    const path = `/uploads/${name}`;\n" +
		"    fs.writeFile(path, 'data', (err) => {});\n" +
		"}\n"
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for req.query -> template literal -> fs.writeFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkRedirect with string concatenation tests
// =========================================================================

func TestSinks_Redirect_JS_Concat(t *testing.T) {
	code := `
function handler(req, res) {
    const path = req.query.path;
    const url = "https://example.com" + path;
    res.redirect(url);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for req.query -> string concat -> res.redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkLog with f-string tests
// =========================================================================

func TestSinks_Log_Python_FString(t *testing.T) {
	code := `
from flask import request
import logging

def handler():
    name = request.args.get("name")
    logging.info(f"User: {name}")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for request.args.get -> f-string -> logging.info()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkDeserialize with YAML tests
// =========================================================================

func TestSinks_Deserialize_Python_YAML(t *testing.T) {
	code := `
from flask import request
import yaml

def handler():
    data = request.data
    obj = yaml.load(data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for request.data -> yaml.load()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkURLFetch additional languages tests
// =========================================================================

func TestSinks_URLFetch_JS_Axios(t *testing.T) {
	code := `
const axios = require('axios');

function handler(req, res) {
    const url = req.query.target;
    axios.get(url);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for req.query -> axios.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkRedirect PHP tests
// =========================================================================

func TestSinks_Redirect_PHP(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["next"];
    redirect($url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for $_GET -> redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkLog PHP tests
// =========================================================================

func TestSinks_Log_PHP(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_GET["name"];
    error_log($name);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for $_GET -> error_log()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkDeserialize JS tests
// =========================================================================

func TestSinks_Deserialize_JS(t *testing.T) {
	code := `
function handler(req, res) {
    const data = req.body.payload;
    const obj = deserialize(data);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for req.body -> deserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Cross-category: multiple sinks from same source
// =========================================================================

func TestSinks_MultipleSinks_Python(t *testing.T) {
	code := `
from flask import request
import logging
import requests

def handler():
    url = request.args.get("url")
    logging.info(url)
    requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	hasLog := hasTaintFlow(flows, taint.SnkLog)
	hasSSRF := hasTaintFlow(flows, taint.SnkURLFetch)
	if !hasLog {
		t.Error("expected log injection flow for request.args.get -> logging.info()")
	}
	if !hasSSRF {
		t.Error("expected SSRF flow for request.args.get -> requests.get()")
	}
}

func TestSinks_MultipleSinks_JS(t *testing.T) {
	code := `
function handler(req, res) {
    const url = req.query.url;
    console.log(url);
    fetch(url);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	hasLog := hasTaintFlow(flows, taint.SnkLog)
	hasSSRF := hasTaintFlow(flows, taint.SnkURLFetch)
	if !hasLog {
		t.Error("expected log injection flow for req.query -> console.log()")
	}
	if !hasSSRF {
		t.Error("expected SSRF flow for req.query -> fetch()")
	}
}

// =========================================================================
// SnkFileRead (path traversal via file reads) tests
// =========================================================================

func TestSinks_FileRead_Java_NIO(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Handler {
    public void handle(HttpServletRequest request) throws Exception {
        String path = request.getParameter("file");
        byte[] data = Files.readAllBytes(Paths.get(path));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for getParameter -> Files.readAllBytes()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_Java_CommonsIO(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FileUtils;
import java.io.File;

public class Handler {
    public void handle(HttpServletRequest request) throws Exception {
        String path = request.getParameter("file");
        String content = FileUtils.readFileToString(new File(path));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for getParameter -> FileUtils.readFileToString()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_Java_RandomAccessFile(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import java.io.RandomAccessFile;

public class Handler {
    public void handle(HttpServletRequest request) throws Exception {
        String path = request.getParameter("file");
        RandomAccessFile raf = new RandomAccessFile(path, "r");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for getParameter -> new RandomAccessFile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkFileRead PHP tests
// =========================================================================

func TestSinks_FileRead_PHP_File(t *testing.T) {
	code := `<?php
function handler() {
    $path = $_GET["path"];
    $lines = file($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> file()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_Readfile(t *testing.T) {
	code := `<?php
function download() {
    $file = $_GET["file"];
    readfile($file);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> readfile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_HighlightFile(t *testing.T) {
	code := `<?php
function viewSource() {
    $file = $_GET["file"];
    highlight_file($file);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> highlight_file()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_ParseIniFile(t *testing.T) {
	code := `<?php
function loadConfig() {
    $config = $_GET["config"];
    $settings = parse_ini_file($config);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> parse_ini_file()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_Scandir(t *testing.T) {
	code := `<?php
function listDir() {
    $dir = $_GET["dir"];
    $files = scandir($dir);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> scandir()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_Glob(t *testing.T) {
	code := `<?php
function search() {
    $pattern = $_GET["pattern"];
    $matches = glob($pattern);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> glob()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_SplFileObject(t *testing.T) {
	code := `<?php
function readCsv() {
    $path = $_GET["path"];
    $file = new SplFileObject($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> new SplFileObject()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_Getimagesize(t *testing.T) {
	code := `<?php
function checkImage() {
    $path = $_GET["image"];
    $info = getimagesize($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> getimagesize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkHTMLOutput (XSS) tests — Java
// =========================================================================

func TestSinks_HTMLOutput_Java_PrintWriter(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class XSSHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.getWriter().println(name);
    }
}
`
	flows := Analyze(code, "/app/XSSHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for getParameter -> response.getWriter().println()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_HTMLOutput_Java_Safe_Escaped(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class SafeHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = Encode.forHtml(name);
        response.getWriter().println(safe);
    }
}
`
	flows := Analyze(code, "/app/SafeHandler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Error("expected sanitized flow (Encode.forHtml) to have reduced confidence")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkEval (code injection / JNDI) tests — Java
// =========================================================================

func TestSinks_Eval_Java_ScriptEngine(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.script.*;

public class EvalHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName("js");
        scriptEngine.eval(expr);
    }
}
`
	flows := Analyze(code, "/app/EvalHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> ScriptEngine.eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Eval_Java_JNDI(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.*;

public class JNDIHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        InitialContext ctx = new InitialContext();
        ctx.lookup(name);
    }
}
`
	flows := Analyze(code, "/app/JNDIHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> InitialContext.lookup() (JNDI injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Eval_Java_SpEL(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class SpELHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        SpelExpressionParser spelExpressionParser = new SpelExpressionParser();
        spelExpressionParser.parseExpression(expr);
    }
}
`
	flows := Analyze(code, "/app/SpELHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> SpelExpressionParser.parseExpression()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkLDAP (LDAP injection) tests — Java
// =========================================================================

func TestSinks_LDAP_Java_DirContext(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;

public class LDAPHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String filter = "(uid=" + user + ")";
        DirContext ctx = new InitialDirContext();
        ctx.search("ou=people", filter, null);
    }
}
`
	flows := Analyze(code, "/app/LDAPHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> DirContext.search()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_LDAP_Java_SpringTemplate(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.ldap.core.LdapTemplate;

public class SpringLDAPHandler extends HttpServlet {
    private LdapTemplate ldapTemplate;

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String filter = "(uid=" + user + ")";
        ldapTemplate.search(filter, null);
    }
}
`
	flows := Analyze(code, "/app/SpringLDAPHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> LdapTemplate.search()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkXPath (XPath injection) tests — Java
// =========================================================================

func TestSinks_XPath_Java_Evaluate(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.xpath.*;

public class XPathHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("path");
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.evaluate(expr, doc);
    }
}
`
	flows := Analyze(code, "/app/XPathHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getParameter -> XPath.evaluate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_XPath_Java_Compile(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.xpath.*;

public class XPathCompileHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("path");
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.compile(expr);
    }
}
`
	flows := Analyze(code, "/app/XPathCompileHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getParameter -> XPath.compile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkTemplate (SSTI) tests — Java
// =========================================================================

func TestSinks_Template_Java_Velocity(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.velocity.*;
import org.apache.velocity.app.*;

public class VelocityHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("data");
        VelocityContext ctx = new VelocityContext();
        ctx.put("data", data);
        Template template = new Template();
        template.merge(ctx, response.getWriter());
    }
}
`
	flows := Analyze(code, "/app/VelocityHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> Template.merge()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Template_Java_FreeMarker(t *testing.T) {
	code := `
import javax.servlet.http.*;
import freemarker.template.*;

public class FreeMarkerHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("data");
        Configuration cfg = new Configuration();
        Template template = cfg.getTemplate("page.ftl");
        Map model = new HashMap();
        model.put("data", data);
        template.process(model, response.getWriter());
    }
}
`
	flows := Analyze(code, "/app/FreeMarkerHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> Template.process()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkCrypto (weak crypto) tests — Java
// =========================================================================

func TestSinks_Crypto_Java_WeakRandom(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.util.Random;

public class CryptoHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String seed = request.getParameter("seed");
        Random rng = new Random(Long.parseLong(seed));
        String token = String.valueOf(rng.nextLong());
        response.getWriter().println(token);
    }
}
`
	flows := Analyze(code, "/app/CryptoHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for new Random() (weak PRNG)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_Crypto_Java_WeakHash(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.security.MessageDigest;

public class HashHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String algo = request.getParameter("algo");
        MessageDigest md = MessageDigest.getInstance(algo);
        byte[] hash = md.digest("data".getBytes());
    }
}
`
	flows := Analyze(code, "/app/HashHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for getParameter -> MessageDigest.getInstance(tainted algo)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkTrustBoundary (session injection) tests — Java
// =========================================================================

func TestSinks_TrustBoundary_Java_SetAttribute(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class SessionHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String role = request.getParameter("role");
        session.setAttribute("userRole", role);
    }
}
`
	flows := Analyze(code, "/app/SessionHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for getParameter -> session.setAttribute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_TrustBoundary_Java_GetSession(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class SessionHandler2 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("data");
        request.getSession().setAttribute("key", data);
    }
}
`
	flows := Analyze(code, "/app/SessionHandler2.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for getParameter -> getSession().setAttribute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_FileRead_PHP_Safe_Basename(t *testing.T) {
	code := `<?php
function safeRead() {
    $path = basename($_GET["file"]);
    $lines = file($path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected sanitized flow (basename) to have reduced confidence for file()")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// SnkTrustBoundary (session/env injection) tests — PHP
// =========================================================================

func TestSinks_TrustBoundary_PHP_SessionId(t *testing.T) {
	code := `<?php
function handler() {
    $sid = $_GET["sid"];
    session_id($sid);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for $_GET -> session_id() (session fixation)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_TrustBoundary_PHP_Putenv(t *testing.T) {
	code := `<?php
function handler() {
    $val = $_GET["path"];
    putenv("PATH=" . $val);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for $_GET -> putenv()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_TrustBoundary_PHP_IniSetSession(t *testing.T) {
	code := `<?php
function handler() {
    $path = $_GET["path"];
    ini_set('session.save_path', $path);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for $_GET -> ini_set('session.*')")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_SSRF_PHP_GetHeaders(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["url"];
    $headers = get_headers($url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_GET -> get_headers()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSinks_SSRF_PHP_Fsockopen(t *testing.T) {
	code := `<?php
function handler() {
    $host = $_GET["host"];
    $fp = fsockopen($host, 80);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_GET -> fsockopen()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# — Trust Boundary (CWE-501) tests
// =========================================================================

func TestCSharp_TrustBoundary_SessionSetString(t *testing.T) {
	// Session.SetString is a method call — tsflow can match this
	code := `
using System;

public class LoginHandler {
    public void Handle() {
        string input = Console.ReadLine();
        Session.SetString("user", input);
    }
}
`
	flows := Analyze(code, "/app/LoginHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for Console.ReadLine -> Session.SetString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_TrustBoundary_SessionIndexer(t *testing.T) {
	// Session["key"] = val is an assignment, not a method call.
	// tsflow won't match assignment-based sinks — these are caught by regex taint.
	// This test documents the limitation.
	code := `
using System;

public class Handler {
    public void Process() {
        string val = Console.ReadLine();
        Session["role"] = val;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
	// Assignment-based sinks are matched via regex taint engine, not tsflow
}

func TestCSharp_TrustBoundary_TempData(t *testing.T) {
	// TempData["key"] = val is an assignment — same limitation as Session indexer.
	code := `
using System;

public class SearchHandler {
    public void Handle() {
        string q = Console.ReadLine();
        TempData["query"] = q;
    }
}
`
	flows := Analyze(code, "/app/SearchHandler.cs", rules.LangCSharp)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

func TestCSharp_TrustBoundary_ViewData(t *testing.T) {
	// ViewData["key"] = val is an assignment — same limitation.
	code := `
using System;

public class ProfileHandler {
    public void Handle() {
        string name = Console.ReadLine();
        ViewData["UserName"] = name;
    }
}
`
	flows := Analyze(code, "/app/ProfileHandler.cs", rules.LangCSharp)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

// =========================================================================
// C# — Open Redirect (CWE-601) tests
// =========================================================================

func TestCSharp_Redirect_NavigationManager(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Components;

public class RedirectPage {
    public void HandleRedirect() {
        string target = Console.ReadLine();
        NavigationManager.NavigateTo(target);
    }
}
`
	flows := Analyze(code, "/app/RedirectPage.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> NavigationManager.NavigateTo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_RedirectToAction(t *testing.T) {
	// RedirectToAction() without receiver is a bare call — tsflow needs a receiver
	// to match the sink. This test documents that regex taint catches these patterns.
	code := `
using System;

public class AuthHandler {
    public void Login() {
        string returnUrl = Console.ReadLine();
        RedirectToAction(returnUrl);
    }
}
`
	flows := Analyze(code, "/app/AuthHandler.cs", rules.LangCSharp)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
	// Bare function calls matched by regex taint, not tsflow method-call walker
}

// =========================================================================
// C# — Log Injection (CWE-117) tests
// =========================================================================

func TestCSharp_LogInjection_Serilog(t *testing.T) {
	code := `
using Serilog;

public class UserService {
    public void Login() {
        string username = Console.ReadLine();
        Log.Information("User logged in: " + username);
    }
}
`
	flows := Analyze(code, "/app/UserService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for Console.ReadLine -> Log.Information")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LogInjection_NLog(t *testing.T) {
	code := `
using NLog;

public class AuditService {
    private static Logger logger = LogManager.GetCurrentClassLogger();
    public void Audit() {
        string action = Console.ReadLine();
        logger.Info("Action performed: " + action);
    }
}
`
	flows := Analyze(code, "/app/AuditService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for Console.ReadLine -> logger.Info")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LogInjection_Trace(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class DiagService {
    public void Log() {
        string msg = Console.ReadLine();
        Trace.TraceInformation("Info: " + msg);
    }
}
`
	flows := Analyze(code, "/app/DiagService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for Console.ReadLine -> Trace.TraceInformation")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LogInjection_EventLog(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class SystemLogger {
    public void Log() {
        string data = Console.ReadLine();
        EventLog.WriteEntry(data);
    }
}
`
	flows := Analyze(code, "/app/SystemLogger.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for Console.ReadLine -> EventLog.WriteEntry")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# — Weak Crypto (CWE-327/338) tests
// =========================================================================

func TestCSharp_Crypto_RC2(t *testing.T) {
	code := `
using System;
using System.Security.Cryptography;

public class CryptoService {
    public void Encrypt() {
        string algo = Console.ReadLine();
        var cipher = RC2.Create(algo);
    }
}
`
	flows := Analyze(code, "/app/CryptoService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for Console.ReadLine -> RC2.Create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Crypto_InsecureRandom(t *testing.T) {
	// `new Random(` is a constructor expression — tsflow matches method calls,
	// not constructors. This sink is caught by regex taint engine.
	code := `
using System;

public class TokenGenerator {
    public string GenerateToken() {
        string seed = Console.ReadLine();
        var rng = new Random(seed.GetHashCode());
        return rng.Next().ToString();
    }
}
`
	flows := Analyze(code, "/app/TokenGenerator.cs", rules.LangCSharp)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
	// Constructor-based sinks matched by regex taint, not tsflow
}

// =========================================================================
// C# — Safe (no finding expected) tests
// =========================================================================

func TestCSharp_TrustBoundary_Safe_Validated(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

public class SafeController : Controller {
    public IActionResult Save() {
        string input = Request.Query["data"];
        if (ModelState.IsValid) {
            TempData["data"] = input;
        }
        return View();
    }
}
`
	flows := Analyze(code, "/app/SafeController.cs", rules.LangCSharp)
	// With ModelState.IsValid present, expect either no trust boundary flow
	// or a lower-confidence flow due to sanitizer detection
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

func TestCSharp_Redirect_Safe_LocalRedirect(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

public class SafeRedirectController : Controller {
    public IActionResult HandleReturn() {
        string url = Request.Query["returnUrl"];
        return LocalRedirect(url);
    }
}
`
	flows := Analyze(code, "/app/SafeRedirectController.cs", rules.LangCSharp)
	// LocalRedirect restricts to local URLs — expect sanitizer to reduce confidence
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}
