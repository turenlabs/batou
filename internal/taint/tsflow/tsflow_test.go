package tsflow

import (
	"testing"

	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"

	// Import taint language catalogs.
	_ "github.com/turenio/gtss/internal/taint/languages"
)

func hasTaintFlow(flows []taint.TaintFlow, sinkCategory taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == sinkCategory {
			return true
		}
	}
	return false
}

// =========================================================================
// Python tests
// =========================================================================

func TestPython_SQLInjection_FlaskFormValue(t *testing.T) {
	code := `
from flask import request
import sqlite3

def handler():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for request.args.get -> string concat -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_SQLInjection_DjangoRequest(t *testing.T) {
	code := `
def view(request):
    name = request.GET.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for request.GET.get -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_CommandInjection(t *testing.T) {
	code := `
import os

def handler():
    cmd = input()
    os.system(cmd)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for input() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Sanitized_NoFlow(t *testing.T) {
	code := `
from flask import request
import html

def handler():
    name = request.args.get("name")
    safe = html.escape(name)
    render(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when html.escape is used")
		}
	}
}

func TestPython_Reassignment(t *testing.T) {
	code := `
import os

def handler():
    cmd = input()
    alias = cmd
    os.system(alias)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow through reassignment")
	}
}

func TestPython_NoSource_NoFlow(t *testing.T) {
	code := `
def handler():
    query = "SELECT 1"
    cursor.execute(query)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow when query uses only literals")
	}
}

func TestPython_FlaskDirectAttr(t *testing.T) {
	code := `
from flask import request

def handler():
    data = request.data
    cursor.execute(data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for request.data -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_EnvVar(t *testing.T) {
	code := `
import os

def handler():
    val = os.getenv("CMD")
    os.system(val)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for os.getenv -> os.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// JavaScript tests
// =========================================================================

func TestJS_SQLInjection_Express(t *testing.T) {
	code := `
const express = require('express');

function handler(req, res) {
    const name = req.query.name;
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    db.query(query);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for req.query -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_CommandInjection(t *testing.T) {
	code := `
const { exec } = require('child_process');

function handler(req, res) {
    const cmd = req.body.cmd;
    exec(cmd);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for req.body -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_Reassignment(t *testing.T) {
	code := `
function handler(req, res) {
    const userInput = req.query.name;
    const alias = userInput;
    db.query("SELECT * FROM users WHERE name = '" + alias + "'");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through reassignment")
	}
}

func TestJS_NoSource_NoFlow(t *testing.T) {
	code := `
function handler(req, res) {
    const query = "SELECT 1";
    db.query(query);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow when query uses only literals")
	}
}

func TestJS_ProcessEnv(t *testing.T) {
	code := `
const { exec } = require('child_process');

function handler() {
    const cmd = process.env.CMD;
    exec(cmd);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for process.env -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Java tests
// =========================================================================

func TestJava_SQLInjection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.sql.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.executeQuery(query);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Reassignment(t *testing.T) {
	code := `
public class Handler {
    public void handle(HttpServletRequest request) {
        String input = request.getParameter("cmd");
        String alias = input;
        Runtime.getRuntime().exec(alias);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow through reassignment")
	}
}

func TestJava_NoSource_NoFlow(t *testing.T) {
	code := `
public class Handler {
    public void handle() {
        String query = "SELECT 1";
        stmt.executeQuery(query);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow when query uses only literals")
	}
}

// =========================================================================
// PHP tests
// =========================================================================

func TestPHP_SQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_GET["name"];
    $query = "SELECT * FROM users WHERE name = '" . $name . "'";
    mysqli_query($conn, $query);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_GET -> mysqli_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby tests
// =========================================================================

func TestRuby_CommandInjection(t *testing.T) {
	code := `
def handler(params)
    cmd = params[:cmd]
    system(cmd)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// C tests
// =========================================================================

func TestC_CommandInjection(t *testing.T) {
	code := `
#include <stdlib.h>

void handler() {
    char *cmd = getenv("CMD");
    system(cmd);
}
`
	flows := Analyze(code, "/app/handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_NoSource_NoFlow(t *testing.T) {
	code := `
void handler() {
    char *cmd = "ls";
    system(cmd);
}
`
	flows := Analyze(code, "/app/handler.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow when command is a literal")
	}
}

// =========================================================================
// C++ tests
// =========================================================================

func TestCPP_CommandInjection(t *testing.T) {
	code := `
#include <cstdlib>

void handler() {
    char *cmd = getenv("CMD");
    system(cmd);
}
`
	flows := Analyze(code, "/app/handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# tests
// =========================================================================

func TestCSharp_CommandInjection(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        string cmd = Console.ReadLine();
        Process.Start(cmd);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Console.ReadLine -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Kotlin tests
// =========================================================================

func TestKotlin_CommandInjection(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    runtime.exec(cmd)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Rust tests
// =========================================================================

func TestRust_CommandInjection(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn handler() {
    let cmd = env::var("CMD").unwrap();
    Command::new(cmd);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for env::var -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift tests
// =========================================================================

func TestSwift_SQLInjection(t *testing.T) {
	code := `
import SQLite3

func handler(input: String) {
    sqlite3_exec(db, input, nil, nil, nil)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for parameter input -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua tests
// =========================================================================

func TestLua_CommandInjection(t *testing.T) {
	code := `
function handler()
    cmd = io.read()
    os.execute(cmd)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for io.read -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Groovy tests
// =========================================================================

func TestGroovy_SQLInjection(t *testing.T) {
	code := `
def handler(input) {
    sql.execute(input)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for parameter input -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Supports tests
// =========================================================================

func TestSupports(t *testing.T) {
	supported := []rules.Language{
		rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby,
		rules.LangC, rules.LangCPP, rules.LangCSharp,
		rules.LangKotlin, rules.LangRust, rules.LangSwift,
		rules.LangLua, rules.LangGroovy,
	}
	for _, lang := range supported {
		if !Supports(lang) {
			t.Errorf("expected Supports(%s) = true", lang)
		}
	}

	unsupported := []rules.Language{rules.LangGo}
	for _, lang := range unsupported {
		if Supports(lang) {
			t.Errorf("expected Supports(%s) = false", lang)
		}
	}
}

func TestAnalyze_UnsupportedLanguage(t *testing.T) {
	flows := Analyze("package main", "/app/main.go", rules.LangGo)
	if flows != nil {
		t.Error("expected nil for unsupported language")
	}
}

func TestAnalyze_EmptyContent(t *testing.T) {
	flows := Analyze("", "/app/empty.py", rules.LangPython)
	if len(flows) != 0 {
		t.Errorf("expected no flows for empty content, got %d", len(flows))
	}
}

func TestAnalyze_InvalidSyntax(t *testing.T) {
	// Tree-sitter is error-tolerant, so it might still parse.
	// Just verify it doesn't panic.
	flows := Analyze("def {{{{ broken", "/app/bad.py", rules.LangPython)
	_ = flows
}

// =========================================================================
// Flow metadata tests
// =========================================================================

func TestPython_FlowMetadata(t *testing.T) {
	code := `
import os

def handler():
    cmd = input()
    os.system(cmd)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if len(flows) == 0 {
		t.Fatal("expected at least one flow")
	}

	flow := flows[0]
	if flow.FilePath != "/app/handler.py" {
		t.Errorf("expected FilePath /app/handler.py, got %s", flow.FilePath)
	}
	if flow.ScopeName != "handler" {
		t.Errorf("expected ScopeName handler, got %s", flow.ScopeName)
	}
	if flow.Confidence <= 0 || flow.Confidence > 1.0 {
		t.Errorf("expected confidence in (0, 1.0], got %f", flow.Confidence)
	}
	if len(flow.Steps) == 0 {
		t.Error("expected at least one flow step")
	}
}
