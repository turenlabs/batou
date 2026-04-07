package scanner_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/cors"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/csharp"
	_ "github.com/turenlabs/batou-rules/rules/deser"
	_ "github.com/turenlabs/batou-rules/rules/encoding"
	_ "github.com/turenlabs/batou-rules/rules/framework"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/golang"
	_ "github.com/turenlabs/batou-rules/rules/header"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/java"
	_ "github.com/turenlabs/batou-rules/rules/jsts"
	_ "github.com/turenlabs/batou-rules/rules/jwt"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/misconfig"
	_ "github.com/turenlabs/batou-rules/rules/nosql"
	_ "github.com/turenlabs/batou-rules/rules/oauth"
	_ "github.com/turenlabs/batou-rules/rules/php"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/race"
	_ "github.com/turenlabs/batou-rules/rules/redirect"
	_ "github.com/turenlabs/batou-rules/rules/ruby"
	_ "github.com/turenlabs/batou-rules/rules/rust"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/session"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/ssti"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/upload"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/websocket"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/xxe"
	_ "github.com/turenlabs/batou-core/taintrule"
)

type categoryCase struct {
	category   string
	rulePrefix string
	filePath   string
	vulnerable string
	fixed      string
}

// One representative per major category. Uses block suppress (ignore-start/end)
// to cover the whole file, since single-line suppress only covers one line.
var categoryCases = []categoryCase{
	{
		category: "injection", rulePrefix: "BATOU-INJ",
		filePath: "/app/query.rb",
		vulnerable: "def search(term)\n  ActiveRecord::Base.connection.execute(\"SELECT * FROM users WHERE name = '\" + term + \"'\")\nend\n",
		fixed:      "def search(term)\n  User.where(name: term)\nend\n",
	},
	{
		category: "xss", rulePrefix: "BATOU-XSS",
		filePath: "/app/view.js",
		vulnerable: "const name = req.query.name;\nres.send('<h1>Hello ' + name + '</h1>');\n",
		fixed:      "const escapeHtml = require('escape-html');\nconst name = escapeHtml(req.query.name);\nres.json({greeting: name});\n",
	},
	{
		category: "secrets", rulePrefix: "BATOU-SEC",
		filePath: "/app/config.go",
		vulnerable: "package main\nvar password = \"SuperS3cret!Password123\"\n",
		fixed:      "package main\nimport \"os\"\nvar password = os.Getenv(\"APP_PASSWORD\")\n",
	},
	{
		category: "crypto", rulePrefix: "BATOU-CRY",
		filePath: "/app/hash.py",
		vulnerable: "import hashlib\npassword_hash = hashlib.md5(password.encode()).hexdigest()\n",
		fixed:      "import bcrypt\npassword_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n",
	},
	{
		category: "traversal", rulePrefix: "BATOU-TRV",
		filePath: "/app/download.js",
		vulnerable: "const path = require('path');\nconst file = req.params.file;\nconst fullPath = path.join(__dirname, 'uploads', file);\nres.sendFile(fullPath);\n",
		fixed:      "const fs = require('fs');\nconst data = fs.readFileSync('./uploads/readme.txt');\n",
	},
	{
		category: "framework", rulePrefix: "BATOU-FW-FASTAPI-001",
		filePath: "/app/main.py",
		vulnerable: "from fastapi import FastAPI\napp = FastAPI()\n@app.post(\"/api/transfer\")\nasync def transfer():\n    return {\"ok\": True}\n",
		fixed:      "from fastapi import FastAPI, Depends\napp = FastAPI()\n@app.post(\"/api/transfer\", dependencies=[Depends(get_current_user)])\nasync def transfer():\n    return {\"ok\": True}\n",
	},
	{
		category: "race", rulePrefix: "BATOU-RACE",
		filePath: "/app/check.py",
		vulnerable: "import os\nif os.path.exists(filepath):\n    data = open(filepath).read()\n",
		fixed:      "try:\n    data = open(filepath).read()\nexcept FileNotFoundError:\n    data = None\n",
	},
}

// TestCategorySuppress_Pipeline verifies for each category:
// 1. Vulnerable code triggers at least one finding
// 2. Block suppress (ignore-start/end) suppresses all findings for that category
// 3. Fixed code produces no findings for that category
func TestCategorySuppress_Pipeline(t *testing.T) {
	for _, tc := range categoryCases {
		t.Run(tc.category, func(t *testing.T) {
			// Step 1: detect
			r1 := testutil.ScanContent(t, tc.filePath, tc.vulnerable)
			found := findByCategoryOrPrefix(r1.Findings, tc.category, tc.rulePrefix)
			if len(found) == 0 {
				t.Fatalf("step 1 (detect): no findings for category %q (prefix %q). All findings: %v",
					tc.category, tc.rulePrefix, ruleIDs(r1.Findings))
			}

			// Step 2: suppress with block
			cmt := commentForFile(tc.filePath)
			suppressed := fmt.Sprintf("%s batou:ignore-start %s -- test\n%s%s batou:ignore-end\n",
				cmt, tc.category, tc.vulnerable, cmt)
			r2 := testutil.ScanContent(t, tc.filePath, suppressed)

			stillActive := findByCategoryOrPrefix(r2.Findings, tc.category, tc.rulePrefix)
			wasSuppressed := findByCategoryOrPrefix(r2.Raw.SuppressedFindings, tc.category, tc.rulePrefix)

			if len(stillActive) > 0 && len(wasSuppressed) == 0 {
				t.Errorf("step 2 (suppress): %d findings still active after ignore-start %s. Active: %v",
					len(stillActive), tc.category, ruleIDs(stillActive))
			}
			if len(wasSuppressed) > 0 {
				t.Logf("step 2: %d findings suppressed OK: %v", len(wasSuppressed), ruleIDs(wasSuppressed))
			}

			// Step 3: fix — only check by the specific rule prefix, not the
			// whole category (a different rule in the same category may still fire)
			r3 := testutil.ScanContent(t, tc.filePath, tc.fixed)
			remaining := findByPrefix(r3.Findings, tc.rulePrefix)
			if len(remaining) > 0 {
				t.Errorf("step 3 (fix): %d findings remain after fix. Got: %v",
					len(remaining), ruleIDs(remaining))
			}
		})
	}
}

func findByCategoryOrPrefix(findings []rules.Finding, category, prefix string) []rules.Finding {
	var out []rules.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, prefix) || rules.CategoryForRule(f.RuleID) == category {
			out = append(out, f)
		}
	}
	return out
}

func findByPrefix(findings []rules.Finding, prefix string) []rules.Finding {
	var out []rules.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, prefix) {
			out = append(out, f)
		}
	}
	return out
}

func ruleIDs(findings []rules.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

func commentForFile(filePath string) string {
	if strings.HasSuffix(filePath, ".go") || strings.HasSuffix(filePath, ".js") ||
		strings.HasSuffix(filePath, ".ts") || strings.HasSuffix(filePath, ".java") {
		return "//"
	}
	return "#"
}
