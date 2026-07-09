package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Electron taint flow tests — desktop API sinks
// =========================================================================

// --- Positive tests: taint flows from known sources to Electron sinks ---

func TestJS_Electron_ShellOpenExternal_Express(t *testing.T) {
	code := `
const { shell } = require('electron');

function handler(req, res) {
    const url = req.query.url;
    shell.openExternal(url);
}
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for req.query -> shell.openExternal (CVE-2018-1000006)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Electron_LoadURL_Express(t *testing.T) {
	code := `
const { BrowserWindow } = require('electron');

function handler(req, res) {
    const url = req.query.url;
    const win = new BrowserWindow();
    win.loadURL(url);
}
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for req.query -> BrowserWindow.loadURL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Electron_LoadFile_Express(t *testing.T) {
	code := `
const { BrowserWindow } = require('electron');

function handler(req, res) {
    const filePath = req.query.path;
    const win = new BrowserWindow();
    win.loadFile(filePath);
}
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for req.query -> BrowserWindow.loadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Electron_ExecuteJavaScript_Express(t *testing.T) {
	code := `
const { BrowserWindow } = require('electron');

function handler(req, res) {
    const code = req.body.script;
    const win = BrowserWindow.getFocusedWindow();
    win.webContents.executeJavaScript(code);
}
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for req.body -> webContents.executeJavaScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Electron_InsertCSS_Express(t *testing.T) {
	code := `
const { BrowserWindow } = require('electron');

function handler(req, res) {
    const css = req.body.theme;
    const win = BrowserWindow.getFocusedWindow();
    win.webContents.insertCSS(css);
}
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for req.body -> webContents.insertCSS")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestTS_Electron_ShellOpenExternal(t *testing.T) {
	code := `
import { shell } from 'electron';

function handler(req, res) {
    const url = req.query.url;
    shell.openExternal(url);
}
`
	flows := Analyze(code, "/app/main.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for req.query -> shell.openExternal (TypeScript)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative tests: safe patterns should NOT produce flows ---

func TestJS_Electron_Safe_Hardcoded_URL(t *testing.T) {
	code := `
const { BrowserWindow } = require('electron');

const win = new BrowserWindow();
win.loadURL('https://example.com');
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("hardcoded URL in loadURL should not produce a taint flow — false positive")
	}
}

func TestJS_Electron_Safe_ContextBridge(t *testing.T) {
	code := `
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    getData: () => ipcRenderer.invoke('get-data')
});
`
	flows := Analyze(code, "/app/preload.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("contextBridge.exposeInMainWorld should sanitize eval risk — false positive")
	}
}

func TestJS_Electron_Safe_ShellOpenExternal_Hardcoded(t *testing.T) {
	code := `
const { shell } = require('electron');

function openDocs() {
    shell.openExternal('https://docs.example.com');
}
`
	flows := Analyze(code, "/app/main.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("hardcoded URL in shell.openExternal should not produce a taint flow — false positive")
	}
}
