package header

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ==========================================================================
// HDR-001–009: Route handler file suppression
// ==========================================================================

func TestHDR001_RouteHandler_WithHelmet_Safe(t *testing.T) {
	content := `const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.get('/api/users', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json(users);
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-001")
}

func TestHDR001_RouteOnlyFile_Safe(t *testing.T) {
	content := `const router = require('express').Router();
router.get('/users', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json(users);
});
module.exports = router;`
	result := testutil.ScanContent(t, "/app/routes/users.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-001")
}

func TestHDR001_ServerSetup_NoMiddleware_StillTriggers(t *testing.T) {
	content := `const express = require('express');
const app = express();
app.get('/api', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json({ok: true});
});
app.listen(3000);`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-001")
}

func TestHDR002_RouteOnlyFile_Safe(t *testing.T) {
	content := `const router = require('express').Router();
router.get('/users', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json(users);
});
module.exports = router;`
	result := testutil.ScanContent(t, "/app/routes/users.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-002")
}

func TestHDR003_RouteOnlyFile_Safe(t *testing.T) {
	content := `const router = require('express').Router();
router.get('/users', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json(users);
});
module.exports = router;`
	result := testutil.ScanContent(t, "/app/routes/users.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-003")
}

func TestHDR004_SecurityMiddleware_Safe(t *testing.T) {
	content := `const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.get('/api', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json({ok: true});
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-004")
}

func TestHDR010_ServerHeader_StillTriggers_InRouteFile(t *testing.T) {
	// HDR-010 (disclosure) should NOT be suppressed by route handler check
	content := `const router = require('express').Router();
router.get('/users', (req, res) => {
    res.setHeader('Server', 'MyApp/1.0');
    res.json(users);
});
module.exports = router;`
	result := testutil.ScanContent(t, "/app/routes/users.js", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-010")
}
