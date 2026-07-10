package tsflow

// Source-category gate for JS/TS prototype pollution (CWE-1321 / SnkPrototype).
//
// Prototype pollution is a KEY-namespace threat: it needs the attacker to
// control object KEYS like __proto__/constructor/prototype. JS database-read
// sources (findOne/find/query/findById/...) are catalogued as SrcDatabase for
// SECOND-ORDER VALUE taint (stored XSS/SQLi). A DB document's key namespace is
// the schema, not attacker-controlled, so `_.merge(target, await
// Model.findOne())` cannot pollute the prototype — that is a conf-1.0
// block-tier FALSE POSITIVE. The gate in addFlow() (taintmap.go) drops
// SrcDatabase -> SnkPrototype flows, with one carve-out: S3 getObject content
// (ObjectType "aws-sdk.S3") can be attacker-uploaded JSON with __proto__ keys,
// so it stays a real flow.
//
// These tests are load-bearing: reverting ONLY taintmap.go makes
// TestJSProtoDBGate_FindOneToMerge_Suppressed FAIL (the suppression vanishes)
// while the genuine user_input / deserialized / S3 cases keep firing.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// protoSourceCategory returns the source category of the first SnkPrototype
// flow, or "" if none. Used to assert which source reached the proto sink.
func firstProtoFlow(flows []taint.TaintFlow) (taint.TaintFlow, bool) {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkPrototype {
			return f, true
		}
	}
	return taint.TaintFlow{}, false
}

// TestJSProtoDBGate_FindOneToMerge_Suppressed is the FALSE-POSITIVE case the
// gate kills: a Mongoose findOne() result merged into a target. A DB document's
// keys are the schema, not attacker-controlled, so no prototype-pollution flow
// must be emitted. THIS is the load-bearing assertion — it FAILS if taintmap.go
// is reverted to HEAD.
func TestJSProtoDBGate_FindOneToMerge_Suppressed(t *testing.T) {
	code := `
const _ = require('lodash');
async function handler(req, res) {
    const doc = await Model.findOne({ id: req.params.id });
    _.merge(target, doc);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if f, ok := firstProtoFlow(flows); ok {
		t.Errorf("DB-sourced prototype pollution must be suppressed, got flow: source=%s (%s) sink=%s line=%d conf=%.2f",
			f.Source.Category, f.Source.ID, f.Sink.Category, f.SinkLine, f.Confidence)
	}
}

// TestJSProtoDBGate_FindByIdToDefaultsDeep_Suppressed covers the ApostropheCMS
// shape (findById doc deep-merged) with a different ORM source and a different
// prototype sink.
func TestJSProtoDBGate_FindByIdToDefaultsDeep_Suppressed(t *testing.T) {
	code := `
const _ = require('lodash');
async function load(req, res) {
    const doc = await Model.findById(req.params.id);
    _.defaultsDeep(target, doc);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/doc-type.js", rules.LangJavaScript)
	if f, ok := firstProtoFlow(flows); ok {
		t.Errorf("findById-sourced prototype pollution must be suppressed, got source=%s (%s)",
			f.Source.Category, f.Source.ID)
	}
}

// TestJSProtoDBGate_ReqBodyToMerge_StillFires is the GENUINE true positive that
// MUST keep blocking: user request body merged into a target. Attacker controls
// the keys (__proto__/constructor), so this is real prototype pollution.
func TestJSProtoDBGate_ReqBodyToMerge_StillFires(t *testing.T) {
	code := `
const _ = require('lodash');
function handler(req, res) {
    const src = req.body;
    _.merge(target, src);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := firstProtoFlow(flows)
	if !ok {
		t.Fatal("user_input -> prototype pollution must still fire (genuine TP), got none")
	}
	if f.Source.Category != taint.SrcUserInput {
		t.Errorf("expected SrcUserInput source, got %s", f.Source.Category)
	}
}

// TestJSProtoDBGate_JSONParseReqBodyToMerge_StillFires covers deserialized
// untrusted input (JSON.parse(req.body)) reaching _.merge. The inner req.body
// keeps the flow user-controlled; it must still fire.
func TestJSProtoDBGate_JSONParseReqBodyToMerge_StillFires(t *testing.T) {
	code := `
const _ = require('lodash');
function handler(req, res) {
    const src = JSON.parse(req.body);
    _.merge(target, src);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if _, ok := firstProtoFlow(flows); !ok {
		t.Fatal("JSON.parse(req.body) -> prototype pollution must still fire (genuine TP), got none")
	}
}

// TestJSProtoDBGate_S3GetObjectToMerge_StillFires verifies the deliberate
// carve-out: S3 object content (ObjectType "aws-sdk.S3") is catalogued
// SrcDatabase but can be attacker-uploaded JSON carrying __proto__ keys, so
// S3 -> proto stays a real flow even though sibling SrcDatabase (ORM/DynamoDB)
// flows are dropped.
func TestJSProtoDBGate_S3GetObjectToMerge_StillFires(t *testing.T) {
	code := `
const _ = require('lodash');
async function handler(req, res) {
    const obj = await s3.getObject({ Bucket: 'b', Key: req.params.key }).promise();
    _.merge(target, obj);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := firstProtoFlow(flows)
	if !ok {
		t.Fatal("S3 getObject content -> prototype pollution must still fire (niche real TP), got none")
	}
	if f.Source.ObjectType != "aws-sdk.S3" {
		t.Errorf("expected aws-sdk.S3 source ObjectType, got %q", f.Source.ObjectType)
	}
}
