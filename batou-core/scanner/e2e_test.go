//go:build e2e

package scanner_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// buildOnce ensures the binary is built exactly once across all e2e subtests.
var buildOnce sync.Once
var buildErr error

func ensureBinaryBuilt(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	binary := filepath.Join(root, "bin", "batou")

	buildOnce.Do(func() {
		binDir := filepath.Join(root, "bin")
		_ = os.MkdirAll(binDir, 0o755)
		cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(binDir, "batou"), "./batou-core/cmd/batou")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		buildErr = cmd.Run()
	})

	if buildErr != nil {
		t.Fatalf("make build failed: %v", buildErr)
	}
	return binary
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// filename is .../batou-core/scanner/e2e_test.go
	// repo root is two directories up from batou-core/
	dir := filepath.Dir(filename)            // .../batou-core/scanner
	dir = filepath.Dir(dir)                  // .../batou-core
	dir = filepath.Dir(dir)                  // repo root
	return dir
}

// hookJSON builds a PostToolUse hook payload for a Write tool call.
func hookJSON(filePath, content string) []byte {
	payload := map[string]any{
		"session_id":      "e2e-test",
		"hook_event_name": "PostToolUse",
		"tool_name":       "Write",
		"tool_input": map[string]any{
			"file_path": filePath,
			"content":   content,
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// postToolOutput matches the JSON output from the binary for PostToolUse.
type postToolOutput struct {
	AdditionalContext string `json:"additionalContext"`
}

// runBinary executes the batou binary with the given stdin and returns the parsed output.
func runBinary(t *testing.T, binary string, stdin []byte) postToolOutput {
	t.Helper()
	cmd := exec.Command(binary)
	cmd.Stdin = bytes.NewReader(stdin)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Exit code 2 means block — still has output we can parse.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			// blocked write — parse stdout anyway
		} else {
			t.Logf("stderr: %s", stderr.String())
			t.Fatalf("binary execution failed: %v", err)
		}
	}

	var out postToolOutput
	if stdout.Len() > 0 {
		if jsonErr := json.Unmarshal(stdout.Bytes(), &out); jsonErr != nil {
			// Might have preToolOutput format for blocks — try that too.
			var preOut map[string]any
			if json.Unmarshal(stdout.Bytes(), &preOut) == nil {
				if hso, ok := preOut["hookSpecificOutput"].(map[string]any); ok {
					if ac, ok := hso["additionalContext"].(string); ok {
						out.AdditionalContext = ac
					}
				}
			}
			if out.AdditionalContext == "" {
				t.Logf("raw stdout: %s", stdout.String())
			}
		}
	}
	return out
}

// hasSecurityContent checks if the output contains evidence of security findings.
func hasSecurityContent(output string) bool {
	if output == "" {
		return false
	}
	indicators := []string{
		"BATOU-",
		"TAINT",
		"taint-analysis",
		"CWE-",
		"Injection",
		"injection",
		"Command",
		"command",
		"SQL",
		"eval",
		"Eval",
		"XSS",
		"xss",
		"vulnerability",
		"Vulnerability",
		"finding",
		"Finding",
		"severity",
		"Severity",
		"critical",
		"Critical",
		"high",
		"High",
		"dangerous",
	}
	for _, ind := range indicators {
		if strings.Contains(output, ind) {
			return true
		}
	}
	return false
}

type langCase struct {
	name     string
	filePath string
	content  string
}

func TestE2E_TaintDetection(t *testing.T) {
	binary := ensureBinaryBuilt(t)

	cases := []langCase{
		{
			name:     "python_sqli",
			filePath: "/app/handler.py",
			content: `import sqlite3

def handle():
    conn = sqlite3.connect('mydb.sqlite')
    cursor = conn.cursor()
    user_input = input("Enter ID: ")
    cursor.execute("SELECT * FROM users WHERE id=" + user_input)
    return cursor.fetchall()
`,
		},
		{
			name:     "go_cmdi",
			filePath: "/app/handler.go",
			content: `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", cmd).Output()
	w.Write(out)
}
`,
		},
		{
			name:     "javascript_eval",
			filePath: "/app/handler.js",
			content: `const express = require('express');
const app = express();

app.get('/run', (req, res) => {
    const search = req.query.search;
    const result = eval(search);
    res.send(result);
});
`,
		},
		{
			name:     "java_sqli",
			filePath: "/app/Handler.java",
			content: `import java.sql.*;
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String id = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
    }
}
`,
		},
		{
			name:     "php_sqli",
			filePath: "/app/handler.php",
			content: `<?php
$conn = mysqli_connect("localhost", "root", "", "mydb");
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);
while ($row = mysqli_fetch_assoc($result)) {
    echo $row['name'];
}
?>
`,
		},
		{
			name:     "ruby_cmdi",
			filePath: "/app/handler.rb",
			content: `require 'sinatra'

get '/run' do
  cmd = params[:cmd]
  output = system(cmd)
  output.to_s
end
`,
		},
		{
			name:     "c_cmdi",
			filePath: "/app/handler.c",
			content: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buf[256];
    sprintf(buf, "ls %s", argv[1]);
    system(buf);
    return 0;
}
`,
		},
		{
			name:     "cpp_cmdi",
			filePath: "/app/handler.cpp",
			content: `#include <cstdlib>
#include <string>

int main(int argc, char* argv[]) {
    std::string cmd = "ls ";
    cmd += argv[1];
    system(cmd.c_str());
    return 0;
}
`,
		},
		{
			name:     "csharp_sqli",
			filePath: "/app/Handler.cs",
			content: `using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class Handler : Controller {
    public IActionResult Get() {
        string id = Request.Query["id"];
        var conn = new SqlConnection("Server=localhost;Database=mydb;");
        conn.Open();
        var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + id, conn);
        var reader = cmd.ExecuteReader();
        return Ok();
    }
}
`,
		},
		{
			name:     "kotlin_sqli",
			filePath: "/app/Handler.kt",
			content: `import java.sql.DriverManager
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun handle(request: HttpServletRequest, response: HttpServletResponse) {
    val id = request.getParameter("id")
    val conn = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val stmt = conn.createStatement()
    val rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id)
}
`,
		},
		{
			name:     "rust_cmdi",
			filePath: "/app/handler.rs",
			content: `use std::process::Command;

fn handle(query: &str) {
    let cmd = query;
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
`,
		},
		{
			name:     "swift_cmdi",
			filePath: "/app/Handler.swift",
			content: `import Foundation

func handle(request: URLRequest) {
    let cmd = request.url?.queryParameters?["cmd"] ?? ""
    let process = Process()
    process.launchPath = "/bin/sh"
    process.arguments = ["-c", cmd]
    process.launch()
    process.waitUntilExit()
}
`,
		},
		{
			name:     "lua_cmdi",
			filePath: "/app/handler.lua",
			content: `local cmd = ngx.var.arg_cmd
os.execute(cmd)
ngx.say("executed: " .. cmd)
`,
		},
		{
			name:     "groovy_cmdi",
			filePath: "/app/Handler.groovy",
			content: `def cmd = params.cmd
def result = cmd.execute()
println result.text
`,
		},
		{
			name:     "perl_cmdi",
			filePath: "/app/handler.pl",
			content: `use CGI;

my $cgi = CGI->new;
my $cmd = $cgi->param('cmd');
system($cmd);
print "Content-type: text/html\n\n";
print "Done";
`,
		},
		{
			name:     "zig_cmdi",
			filePath: "/app/handler.zig",
			content: `const std = @import("std");

pub fn handle(request: anytype) !void {
    const cmd = request.uri;
    const result = try std.process.Child.init(.{
        .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
    }, std.heap.page_allocator);
    _ = result;
}
`,
		},
	}

	results := make(map[string]bool, len(cases))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := hookJSON(tc.filePath, tc.content)
			output := runBinary(t, binary, input)

			detected := hasSecurityContent(output.AdditionalContext)
			results[tc.name] = detected

			if detected {
				// Truncate for readability in logs.
				ctx := output.AdditionalContext
				if len(ctx) > 300 {
					ctx = ctx[:300] + "..."
				}
				t.Logf("DETECTED: %s", ctx)
			} else {
				t.Logf("NO DETECTION (informational) - additionalContext length: %d", len(output.AdditionalContext))
				if output.AdditionalContext != "" {
					ctx := output.AdditionalContext
					if len(ctx) > 300 {
						ctx = ctx[:300] + "..."
					}
					t.Logf("output: %s", ctx)
				}
			}
		})
	}

	// Print detection matrix.
	t.Run("detection_matrix", func(t *testing.T) {
		var passed, total int
		var matrix strings.Builder
		matrix.WriteString("\n=== E2E Taint Detection Matrix ===\n")
		for _, tc := range cases {
			total++
			status := "MISS"
			if results[tc.name] {
				status = "PASS"
				passed++
			}
			matrix.WriteString(fmt.Sprintf("  %-20s %s\n", tc.name, status))
		}
		matrix.WriteString(fmt.Sprintf("\nTotal: %d/%d languages detected\n", passed, total))
		matrix.WriteString("==================================\n")
		t.Log(matrix.String())

		if passed == 0 {
			t.Fatal("no languages detected any findings — pipeline may be broken")
		}
	})
}
