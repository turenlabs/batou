package jsts

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-JSTS-001: postMessage without origin check
// ==========================================================================

func TestJSTS001_PostMessage_NoOriginCheck(t *testing.T) {
	content := `
window.addEventListener('message', function(event) {
    const data = event.data;
    document.getElementById('output').innerHTML = data.html;
});
`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-001")
}

func TestJSTS001_PostMessage_WithOriginCheck_Safe(t *testing.T) {
	content := `
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://trusted.com') return;
    const data = event.data;
    document.getElementById('output').textContent = data.text;
});
`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-001")
}

func TestJSTS001_PostMessage_NoDataUsage_Safe(t *testing.T) {
	content := `
window.addEventListener('message', function(event) {
    console.log('message received');
});
`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-001")
}

// ==========================================================================
// GTSS-JSTS-002: DOM clobbering risk
// ==========================================================================

func TestJSTS002_DOMClobber_GetElementById_Href(t *testing.T) {
	content := `
const link = document.getElementById('config').href;
fetch(link).then(r => r.json());
`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-002")
}

func TestJSTS002_DOMClobber_QuerySelector_InnerHTML(t *testing.T) {
	content := `
const el = document.querySelector('#widget').innerHTML;
`
	result := testutil.ScanContent(t, "/app/widget.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-002")
}

func TestJSTS002_DOMClobber_Forms(t *testing.T) {
	content := `
const action = document.forms['login'].action;
`
	result := testutil.ScanContent(t, "/app/form.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-002")
}

// ==========================================================================
// GTSS-JSTS-003: Regex DoS (ReDoS)
// ==========================================================================

func TestJSTS003_NewRegExp_UserInput(t *testing.T) {
	content := `
app.get('/search', (req, res) => {
    const pattern = new RegExp(req.query.search);
    const results = items.filter(i => pattern.test(i.name));
    res.json(results);
});
`
	result := testutil.ScanContent(t, "/app/search.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-003")
}

func TestJSTS003_NewRegExp_TemplateLiteral(t *testing.T) {
	content := `
const regex = new RegExp(` + "`^${userInput}$`" + `);
`
	result := testutil.ScanContent(t, "/app/validator.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-003")
}

func TestJSTS003_NewRegExp_Escaped_Safe(t *testing.T) {
	content := `
const regex = new RegExp(escapeRegExp(userInput));
`
	result := testutil.ScanContent(t, "/app/search.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-003")
}

func TestJSTS003_NewRegExp_StaticString_Safe(t *testing.T) {
	content := `
const regex = new RegExp("^[a-z]+$");
`
	result := testutil.ScanContent(t, "/app/validator.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-003")
}

// ==========================================================================
// GTSS-JSTS-004: child_process.exec shell injection
// ==========================================================================

func TestJSTS004_ExecTemplateLiteral(t *testing.T) {
	content := `
const { exec } = require('child_process');
exec(` + "`ls -la ${userDir}`" + `, (err, stdout) => {
    console.log(stdout);
});
`
	result := testutil.ScanContent(t, "/app/files.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-004")
}

func TestJSTS004_ExecSyncConcat(t *testing.T) {
	content := `
const { execSync } = require('child_process');
const output = execSync('git log ' + branch);
`
	result := testutil.ScanContent(t, "/app/git.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-004")
}

func TestJSTS004_ExecFile_Safe(t *testing.T) {
	content := `
const { execFile } = require('child_process');
execFile('ls', ['-la', userDir], (err, stdout) => {
    console.log(stdout);
});
`
	result := testutil.ScanContent(t, "/app/files.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-004")
}

// ==========================================================================
// GTSS-JSTS-005: eval/Function with template literal
// ==========================================================================

func TestJSTS005_EvalTemplateLiteral(t *testing.T) {
	content := `
const result = eval(` + "`return ${expression}`" + `);
`
	result := testutil.ScanContent(t, "/app/calc.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-005")
}

func TestJSTS005_FunctionCtorTemplateLiteral(t *testing.T) {
	content := `
const fn = new Function(` + "`return ${code}`" + `);
`
	result := testutil.ScanContent(t, "/app/dynamic.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-005")
}

func TestJSTS005_EvalStaticString_Safe(t *testing.T) {
	content := `
const result = eval("2 + 2");
`
	result := testutil.ScanContent(t, "/app/calc.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-005")
}

// ==========================================================================
// GTSS-JSTS-006: JWT verify without algorithms
// ==========================================================================

func TestJSTS006_JWTVerify_NoAlgorithms(t *testing.T) {
	content := `
const jwt = require('jsonwebtoken');
const decoded = jwt.verify(token, publicKey);
`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-006")
}

func TestJSTS006_JWTVerify_WithAlgorithms_Safe(t *testing.T) {
	content := `
const jwt = require('jsonwebtoken');
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-006")
}

// ==========================================================================
// GTSS-JSTS-007: Insecure cookie settings
// ==========================================================================

func TestJSTS007_CookieNoFlags(t *testing.T) {
	content := `
app.get('/login', (req, res) => {
    res.cookie('session', token, { maxAge: 900000 });
    res.send('OK');
});
`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-007")
}

func TestJSTS007_CookieWithFlags_Safe(t *testing.T) {
	content := `
app.get('/login', (req, res) => {
    res.cookie('session', token, {
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
    });
    res.send('OK');
});
`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-007")
}

// ==========================================================================
// GTSS-JSTS-008: Next.js getServerSideProps data exposure
// ==========================================================================

func TestJSTS008_GetSSP_SensitiveData(t *testing.T) {
	content := `
export async function getServerSideProps(context) {
    const user = await getUser(context.params.id);
    return {
        props: {
            password: user.password,
            name: user.name,
        }
    };
}
`
	result := testutil.ScanContent(t, "/app/pages/profile.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-008")
}

func TestJSTS008_GetSSP_SafeData(t *testing.T) {
	content := `
export async function getServerSideProps(context) {
    const user = await getUser(context.params.id);
    return {
        props: {
            name: user.name,
            bio: user.bio,
        }
    };
}
`
	result := testutil.ScanContent(t, "/app/pages/profile.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-008")
}

// ==========================================================================
// GTSS-JSTS-009: React useEffect with unsanitized URL
// ==========================================================================

func TestJSTS009_UseEffect_LocationToInnerHTML(t *testing.T) {
	content := `
function SearchResults() {
    useEffect(() => {
        const query = window.location.search;
        document.getElementById('results').innerHTML = decodeURIComponent(query);
    }, []);
    return <div id="results" />;
}
`
	result := testutil.ScanContent(t, "/app/Search.jsx", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-009")
}

func TestJSTS009_UseEffect_LocationToTextContent_Safe(t *testing.T) {
	content := `
function SearchResults() {
    useEffect(() => {
        const query = window.location.search;
        document.getElementById('results').textContent = query;
    }, []);
    return <div id="results" />;
}
`
	result := testutil.ScanContent(t, "/app/Search.jsx", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-009")
}

// ==========================================================================
// GTSS-JSTS-010: Node.js vm sandbox escape
// ==========================================================================

func TestJSTS010_VMRunInNewContext(t *testing.T) {
	content := `
const vm = require('vm');
const result = vm.runInNewContext(userCode, sandbox);
`
	result := testutil.ScanContent(t, "/app/sandbox.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-010")
}

func TestJSTS010_VM2_NewVM(t *testing.T) {
	content := `
const { VM } = require('vm2');
const vm = new VM({ timeout: 1000 });
const result = vm.run(userCode);
`
	result := testutil.ScanContent(t, "/app/sandbox.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-010")
}

func TestJSTS010_NoVMImport_Safe(t *testing.T) {
	content := `
const result = processCode(userInput);
`
	result := testutil.ScanContent(t, "/app/process.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-010")
}

// ==========================================================================
// GTSS-JSTS-011: path.join doesn't prevent traversal
// ==========================================================================

func TestJSTS011_PathJoin_UserInput(t *testing.T) {
	content := `
const path = require('path');
app.get('/file', (req, res) => {
    const filePath = path.join('/uploads', req.params.filename);
    res.sendFile(filePath);
});
`
	result := testutil.ScanContent(t, "/app/files.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-011")
}

func TestJSTS011_PathJoin_WithCheck_Safe(t *testing.T) {
	content := `
const path = require('path');
app.get('/file', (req, res) => {
    const base = path.resolve('/uploads');
    const filePath = path.join('/uploads', req.params.filename);
    if (!filePath.startsWith(base)) return res.status(403).send('Forbidden');
    res.sendFile(filePath);
});
`
	result := testutil.ScanContent(t, "/app/files.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-011")
}

// ==========================================================================
// GTSS-JSTS-012: Handlebars SafeString XSS
// ==========================================================================

func TestJSTS012_HandlebarsSafeString(t *testing.T) {
	content := `
Handlebars.registerHelper('raw', function(text) {
    return new Handlebars.SafeString(text);
});
`
	result := testutil.ScanContent(t, "/app/helpers.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-012")
}

// ==========================================================================
// GTSS-JSTS-013: Electron insecure config
// ==========================================================================

func TestJSTS013_NodeIntegration(t *testing.T) {
	content := `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,
    }
});
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-013")
}

func TestJSTS013_ContextIsolationFalse(t *testing.T) {
	content := `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({
    webPreferences: {
        contextIsolation: false,
    }
});
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-013")
}

func TestJSTS013_WebSecurityFalse(t *testing.T) {
	content := `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({
    webPreferences: {
        webSecurity: false,
    }
});
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-013")
}

func TestJSTS013_SecureDefaults_Safe(t *testing.T) {
	content := `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({
    webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        preload: path.join(__dirname, 'preload.js')
    }
});
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-013")
}

// ==========================================================================
// GTSS-JSTS-014: Unvalidated redirect via location
// ==========================================================================

func TestJSTS014_LocationHrefUserInput(t *testing.T) {
	content := `
const redirectUrl = new URLSearchParams(window.location.search).get('url');
window.location.href = redirectUrl;
`
	result := testutil.ScanContent(t, "/app/redirect.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-014")
}

func TestJSTS014_LocationReplace(t *testing.T) {
	content := `
window.location.replace(returnUrl);
`
	result := testutil.ScanContent(t, "/app/redirect.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-014")
}

// ==========================================================================
// GTSS-JSTS-015: Server-side template injection
// ==========================================================================

func TestJSTS015_EjsRenderUserInput(t *testing.T) {
	content := `
const ejs = require('ejs');
app.post('/preview', (req, res) => {
    const html = ejs.render(req.body.template, { data: 'test' });
    res.send(html);
});
`
	result := testutil.ScanContent(t, "/app/preview.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-015")
}

func TestJSTS015_PugCompileUserInput(t *testing.T) {
	content := `
const pug = require('pug');
const fn = pug.compile(userInput);
`
	result := testutil.ScanContent(t, "/app/template.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-015")
}

func TestJSTS015_NunjucksRenderString(t *testing.T) {
	content := `
const nunjucks = require('nunjucks');
const html = nunjucks.renderString(req.body.content, { user: 'test' });
`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-015")
}

func TestJSTS015_EjsRenderFile_Safe(t *testing.T) {
	content := `
const ejs = require('ejs');
app.get('/page', (req, res) => {
    res.render('template', { name: req.query.name });
});
`
	result := testutil.ScanContent(t, "/app/page.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-015")
}

// ==========================================================================
// GTSS-JSTS-016: Insecure WebSocket
// ==========================================================================

func TestJSTS016_WSNoVerifyClient(t *testing.T) {
	content := `
const WebSocket = require('ws');
const wss = new WebSocket.Server({
    port: 8080,
    verifyClient: false,
});
`
	result := testutil.ScanContent(t, "/app/ws.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-016")
}

func TestJSTS016_WSWithVerifyClient_Safe(t *testing.T) {
	content := `
const WebSocket = require('ws');
const wss = new WebSocket.Server({
    port: 8080,
    verifyClient: (info) => allowedOrigins.includes(info.origin),
});
`
	result := testutil.ScanContent(t, "/app/ws.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-016")
}

// ==========================================================================
// GTSS-JSTS-017: crypto.createCipher (deprecated)
// ==========================================================================

func TestJSTS017_CreateCipher(t *testing.T) {
	content := `
const crypto = require('crypto');
const cipher = crypto.createCipher('aes-256-cbc', password);
`
	result := testutil.ScanContent(t, "/app/encrypt.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-017")
}

func TestJSTS017_CreateCipheriv_Safe(t *testing.T) {
	content := `
const crypto = require('crypto');
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
`
	result := testutil.ScanContent(t, "/app/encrypt.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-017")
}

// ==========================================================================
// GTSS-JSTS-018: fs.chmod with permissive modes
// ==========================================================================

func TestJSTS018_Chmod777(t *testing.T) {
	content := `
const fs = require('fs');
fs.chmodSync('/tmp/data.json', 0o777);
`
	result := testutil.ScanContent(t, "/app/setup.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-018")
}

func TestJSTS018_WriteFileWorld(t *testing.T) {
	content := `
const fs = require('fs');
fs.writeFileSync('/tmp/config.json', data, { mode: 0o777 });
`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-018")
}

func TestJSTS018_Chmod600_Safe(t *testing.T) {
	content := `
const fs = require('fs');
fs.chmodSync('/tmp/data.json', 0o600);
`
	result := testutil.ScanContent(t, "/app/setup.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-018")
}

// ==========================================================================
// TypeScript-specific tests (.ts file extension)
// ==========================================================================

func TestJSTS001_PostMessage_TypeScript(t *testing.T) {
	content := `
window.addEventListener('message', (event: MessageEvent) => {
    const data = event.data;
    document.getElementById('output')!.innerHTML = data.html;
});
`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-001")
}

func TestJSTS003_ReDoS_TypeScript(t *testing.T) {
	content := `
import { Request, Response } from 'express';

export function search(req: Request, res: Response): void {
    const pattern = new RegExp(req.query.search as string);
    const results = items.filter((i: Item) => pattern.test(i.name));
    res.json(results);
}
`
	result := testutil.ScanContent(t, "/app/search.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-003")
}

func TestJSTS004_ExecSync_TypeScript(t *testing.T) {
	content := `
import { execSync } from 'child_process';

function deploy(branch: string): string {
    const output = execSync('git checkout ' + branch);
    return output.toString();
}
`
	result := testutil.ScanContent(t, "/app/deploy.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-004")
}

func TestJSTS005_EvalTemplate_TypeScript(t *testing.T) {
	content := `
function calculate(expression: string): number {
    const result = eval(` + "`return ${expression}`" + `);
    return result as number;
}
`
	result := testutil.ScanContent(t, "/app/calc.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-005")
}

func TestJSTS006_JWTVerify_TypeScript(t *testing.T) {
	content := `
import jwt from 'jsonwebtoken';

interface UserPayload { id: string; role: string; }

function verifyToken(token: string, key: string): UserPayload {
    const decoded = jwt.verify(token, key);
    return decoded as UserPayload;
}
`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-006")
}

func TestJSTS006_JWTVerify_WithAlgorithms_TypeScript_Safe(t *testing.T) {
	content := `
import jwt from 'jsonwebtoken';

interface UserPayload { id: string; role: string; }

function verifyToken(token: string, key: string): UserPayload {
    const decoded = jwt.verify(token, key, { algorithms: ['RS256'] });
    return decoded as UserPayload;
}
`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-006")
}

func TestJSTS007_Cookie_TypeScript(t *testing.T) {
	content := `
import { Request, Response } from 'express';

export function login(req: Request, res: Response): void {
    const token: string = generateToken(req.body.user);
    res.cookie('session', token, { maxAge: 900000 });
    res.send('OK');
}
`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-007")
}

func TestJSTS010_VMSandbox_TypeScript(t *testing.T) {
	content := `
import vm from 'vm';

function runUserCode(code: string): unknown {
    const sandbox = { console };
    const result = vm.runInNewContext(code, sandbox);
    return result;
}
`
	result := testutil.ScanContent(t, "/app/sandbox.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-010")
}

func TestJSTS011_PathJoin_TypeScript(t *testing.T) {
	content := `
import path from 'path';
import { Request, Response } from 'express';

export function serveFile(req: Request, res: Response): void {
    const filePath: string = path.join('/uploads', req.params.filename);
    res.sendFile(filePath);
}
`
	result := testutil.ScanContent(t, "/app/files.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-011")
}

func TestJSTS013_Electron_TypeScript(t *testing.T) {
	content := `
import { BrowserWindow } from 'electron';

const win: BrowserWindow = new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,
    }
});
`
	result := testutil.ScanContent(t, "/app/main.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-013")
}

func TestJSTS015_SSTI_TypeScript(t *testing.T) {
	content := `
import ejs from 'ejs';
import { Request, Response } from 'express';

export function preview(req: Request, res: Response): void {
    const html: string = ejs.render(req.body.template, { data: 'test' });
    res.send(html);
}
`
	result := testutil.ScanContent(t, "/app/preview.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-015")
}

func TestJSTS017_CreateCipher_TypeScript(t *testing.T) {
	content := `
import crypto from 'crypto';

function encrypt(data: string, password: string): Buffer {
    const cipher = crypto.createCipher('aes-256-cbc', password);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}
`
	result := testutil.ScanContent(t, "/app/encrypt.ts", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-017")
}

func TestJSTS017_CreateCipheriv_TypeScript_Safe(t *testing.T) {
	content := `
import crypto from 'crypto';

function encrypt(data: string, key: Buffer): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}
`
	result := testutil.ScanContent(t, "/app/encrypt.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-JSTS-017")
}

// TSX file extension test
func TestJSTS009_UseEffect_TSX(t *testing.T) {
	content := `
import React, { useEffect } from 'react';

const SearchResults: React.FC = () => {
    useEffect(() => {
        const query = window.location.search;
        document.getElementById('results')!.innerHTML = decodeURIComponent(query);
    }, []);
    return <div id="results" />;
};
`
	result := testutil.ScanContent(t, "/app/Search.tsx", content)
	testutil.MustFindRule(t, result, "GTSS-JSTS-009")
}
