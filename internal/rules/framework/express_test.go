package framework

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-FW-EXPRESS-001: Missing Helmet ---

func TestExpress001_MissingHelmet(t *testing.T) {
	content := `const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000);`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-001")
}

func TestExpress001_MissingHelmet_ESModule(t *testing.T) {
	content := `import express from 'express';
const app = express();

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});`
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-001")
}

func TestExpress001_WithHelmet_Safe(t *testing.T) {
	content := `const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());

app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-001")
}

func TestExpress001_WithHelmet_ESModule_Safe(t *testing.T) {
	content := `import express from 'express';
import helmet from 'helmet';
const app = express();

app.use(helmet());
app.listen(3000);`
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-001")
}

func TestExpress001_NonExpressApp_Safe(t *testing.T) {
	content := `const http = require('http');
const server = http.createServer((req, res) => {
  res.end('hello');
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-001")
}

// --- GTSS-FW-EXPRESS-002: Insecure Session Configuration ---

func TestExpress002_SecureFalse(t *testing.T) {
	content := `const session = require('express-session');
app.use(session({
  secret: 'mysecret',
  cookie: {
    secure: false,
    httpOnly: true,
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-002")
}

func TestExpress002_HttpOnlyFalse(t *testing.T) {
	content := `app.use(session({
  secret: 'mysecret',
  cookie: {
    httpOnly: false,
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-002")
}

func TestExpress002_SameSiteNone(t *testing.T) {
	content := `app.use(session({
  secret: 'mysecret',
  cookie: {
    sameSite: 'none',
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-002")
}

func TestExpress002_SecureConfig_Safe(t *testing.T) {
	content := `app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 86400000,
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-002")
}

// --- GTSS-FW-EXPRESS-003: Stack Trace Leak ---

func TestExpress003_StackTraceLeak_ErrStack(t *testing.T) {
	content := `app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-003")
}

func TestExpress003_StackTraceLeak_ErrMessage(t *testing.T) {
	content := `app.use((err, req, res, next) => {
  res.status(500).json(err.message);
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-003")
}

func TestExpress003_StackTraceLeak_ErrObject(t *testing.T) {
	content := `app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-003")
}

func TestExpress003_WithEnvCheck_Safe(t *testing.T) {
	content := `app.use((err, req, res, next) => {
  console.error(err.stack);
  if (process.env.NODE_ENV !== 'production') {
    res.status(500).send(err.stack);
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-003")
}

func TestExpress003_GenericError_Safe(t *testing.T) {
	content := `app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-003")
}

// --- GTSS-FW-EXPRESS-004: Dynamic Require ---

func TestExpress004_RequireWithReqParams(t *testing.T) {
	content := `app.get('/plugin/:name', (req, res) => {
  const plugin = require(req.params.name);
  plugin.run();
});`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-004")
}

func TestExpress004_RequireWithReqQuery(t *testing.T) {
	content := `app.get('/load', (req, res) => {
  const mod = require(req.query.module);
  res.json(mod.data);
});`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-004")
}

func TestExpress004_RequireWithConcatenation(t *testing.T) {
	content := `app.get('/theme', (req, res) => {
  const theme = require('./themes/' + req.query.name);
  res.json(theme);
});`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-004")
}

func TestExpress004_DynamicImportWithUserInput(t *testing.T) {
	content := `app.get('/plugin/:name', async (req, res) => {
  const plugin = await import(req.params.name);
  res.json(plugin.default());
});`
	result := testutil.ScanContent(t, "/app/loader.ts", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-004")
}

func TestExpress004_StaticRequire_Safe(t *testing.T) {
	content := `const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

app.use(helmet());
app.use(cors());`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-004")
}

func TestExpress004_RequireVariableWithUserInput(t *testing.T) {
	content := `app.post('/api/process', (req, res) => {
  const moduleName = req.body.processor;
  function loadProcessor() {
    const processor = require(moduleName);
    return processor.run();
  }
  res.json(loadProcessor());
});`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-004")
}

// --- GTSS-FW-EXPRESS-005: Sensitive Static Directory ---

func TestExpress005_StaticRoot(t *testing.T) {
	content := `const express = require('express');
const app = express();
app.use(express.static('/'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

func TestExpress005_StaticDot(t *testing.T) {
	content := `app.use(express.static('.'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

func TestExpress005_StaticGitDir(t *testing.T) {
	content := `app.use(express.static('.git'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

func TestExpress005_StaticNodeModules(t *testing.T) {
	content := `app.use(express.static('node_modules'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

func TestExpress005_StaticEnvDir(t *testing.T) {
	content := `app.use(express.static('.env'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

func TestExpress005_StaticPublic_Safe(t *testing.T) {
	content := `app.use(express.static('public'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

func TestExpress005_StaticDist_Safe(t *testing.T) {
	content := `app.use(express.static('dist'));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-005")
}

// --- GTSS-FW-EXPRESS-006: Trust Proxy Misconfiguration ---

func TestExpress006_TrustProxyTrue(t *testing.T) {
	content := `const express = require('express');
const app = express();
app.set('trust proxy', true);`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-006")
}

func TestExpress006_TrustProxyNumber_Safe(t *testing.T) {
	content := `const express = require('express');
const app = express();
app.set('trust proxy', 1);`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-006")
}

func TestExpress006_TrustProxySubnet_Safe(t *testing.T) {
	content := `app.set('trust proxy', '10.0.0.0/8');`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-006")
}

// --- GTSS-FW-EXPRESS-007: Missing Session Expiration ---

func TestExpress007_SessionNoExpiry(t *testing.T) {
	content := `app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-007")
}

func TestExpress007_SessionWithMaxAge_Safe(t *testing.T) {
	content := `app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 86400000,
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-007")
}

func TestExpress007_SessionWithExpires_Safe(t *testing.T) {
	content := `app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    expires: new Date(Date.now() + 86400000),
  }
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-007")
}

// --- GTSS-FW-EXPRESS-008: Process.env Leak ---

func TestExpress008_ProcessEnvInResponse(t *testing.T) {
	content := `app.get('/debug', (req, res) => {
  res.json(process.env);
});`
	result := testutil.ScanContent(t, "/app/debug.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-008")
}

func TestExpress008_ProcessEnvInSend(t *testing.T) {
	content := `app.get('/config', (req, res) => {
  res.send(process.env);
});`
	result := testutil.ScanContent(t, "/app/debug.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-008")
}

func TestExpress008_SpecificEnvVar_Safe(t *testing.T) {
	content := `app.get('/config', (req, res) => {
  res.json({ port: process.env.PORT, host: process.env.HOST });
});`
	result := testutil.ScanContent(t, "/app/config.js", content)
	// Specific env vars are a different pattern - this tests the regex doesn't over-match
	// The regex should only match process.env without a specific property access in res.json()
	// This is an acceptable pattern (though debatable)
	testutil.MustNotFindRule(t, result, "GTSS-FW-EXPRESS-008")
}

func TestExpress008_ProcessEnvSpreadInResponse(t *testing.T) {
	content := `app.get('/debug', (req, res) => {
  res.json({ ...process.env, timestamp: Date.now() });
});`
	result := testutil.ScanContent(t, "/app/debug.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-EXPRESS-008")
}
