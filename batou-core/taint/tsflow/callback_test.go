package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func analyzeJS(code string) []taint.TaintFlow {
	return Analyze(code, "/app/handler.js", rules.LangJavaScript)
}

func analyzeTS(code string) []taint.TaintFlow {
	return Analyze(code, "/app/handler.ts", rules.LangTypeScript)
}

func TestCallback_PromiseThen(t *testing.T) {
	code := `
const express = require('express');
const app = express();
const db = require('./db');

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id)
    .then(result => {
      res.send(result);
    });
});
`
	flows := analyzeJS(code)
	if len(flows) == 0 {
		t.Fatal("expected taint flows through .then() callback")
	}
	// Should detect the sql_query sink from the tainted id
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected sql_query sink from tainted req.query.id")
	}
}

func TestCallback_ArrayMap(t *testing.T) {
	code := `
const express = require('express');
const app = express();
const { execSync } = require('child_process');

app.post('/batch', (req, res) => {
  const commands = req.body.commands;
  commands.map(cmd => {
    execSync(cmd);
  });
});
`
	flows := analyzeJS(code)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command_exec sink from tainted array element via .map()")
	}
}

func TestCallback_PromiseChain(t *testing.T) {
	code := `
const express = require('express');
const app = express();
const db = require('./db');

app.get('/search', (req, res) => {
  const term = req.query.q;
  fetch('/api?q=' + term)
    .then(resp => resp.json())
    .then(data => {
      db.query("SELECT * FROM items WHERE name = '" + data.name + "'");
    });
});
`
	flows := analyzeJS(code)
	if len(flows) == 0 {
		t.Fatal("expected taint flows through promise chain .then().then()")
	}
}

func TestCallback_TypeScript(t *testing.T) {
	code := `
import express from 'express';
import { execSync } from 'child_process';

const app = express();

app.get('/run', (req, res) => {
  const items = req.body.items;
  items.forEach(item => {
    execSync(item);
  });
});
`
	flows := analyzeTS(code)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command_exec sink from tainted .forEach() callback in TypeScript")
	}
}

func TestCallback_IsCallbackPropagation(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"then", true},
		{"catch", true},
		{"map", true},
		{"flatMap", true},
		{"filter", true},
		{"forEach", true},
		{"reduce", true},
		{"on", true},
		{"subscribe", true},
		{"push", false},
		{"splice", false},
		{"toString", false},
	}

	for _, tt := range tests {
		p := isCallbackPropagationCall(tt.method)
		got := p != nil
		if got != tt.want {
			t.Errorf("isCallbackPropagationCall(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}
