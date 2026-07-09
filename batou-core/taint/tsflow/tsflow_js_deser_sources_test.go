package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ---------------------------------------------------------------------------
// SrcDeserialized sources — binary format decode output flows to downstream sinks
// ---------------------------------------------------------------------------

func TestJS_DeserSource_MsgpackDecode_ToSQL(t *testing.T) {
	code := `
const msgpack = require('@msgpack/msgpack');
const db = require('./db');

app.post('/process', (req, res) => {
    const buf = req.body.raw;
    const data = msgpack.decode(buf);
    const query = "SELECT * FROM items WHERE id = '" + data.id + "'";
    db.query(query);
});
`
	flows := Analyze(code, "/app/routes/process.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from req.body -> msgpack.decode() -> db.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSource_MsgpackUnpack_ToCommand(t *testing.T) {
	code := `
const msgpack = require('msgpack-lite');
const { exec } = require('child_process');

app.post('/run', (req, res) => {
    const buf = req.body.payload;
    const msg = msgpack.unpack(buf);
    exec(msg.command);
});
`
	flows := Analyze(code, "/app/routes/run.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from req.body -> msgpack.unpack() -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSource_BSONDeserialize_ToSQL(t *testing.T) {
	code := `
const { BSON } = require('bson');
const db = require('./db');

app.post('/sync', (req, res) => {
    const raw = req.body.bsonData;
    const doc = BSON.deserialize(raw);
    const q = "INSERT INTO logs (msg) VALUES ('" + doc.message + "')";
    db.query(q);
});
`
	flows := Analyze(code, "/app/routes/sync.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from req.body -> BSON.deserialize() -> db.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSource_CborDecode_ToFileWrite(t *testing.T) {
	code := `
const cbor = require('cbor-x');
const fs = require('fs');

app.post('/upload', (req, res) => {
    const buf = req.body.cborPayload;
    const obj = cbor.decode(buf);
    fs.writeFileSync(obj.path, obj.content);
});
`
	flows := Analyze(code, "/app/routes/upload.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow from req.body -> cbor.decode() -> fs.writeFileSync()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSource_CborDecodeMultiple_ToSQL(t *testing.T) {
	code := `
const cbor = require('cbor-x');
const db = require('./db');

app.post('/batch', (req, res) => {
    const buf = req.body.data;
    const result = cbor.decodeMultiple(buf);
    const q = "SELECT * FROM records WHERE tag = '" + result + "'";
    db.query(q);
});
`
	flows := Analyze(code, "/app/routes/batch.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow from req.body -> cbor.decodeMultiple() -> db.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// SnkDeserialize sinks — user input flowing directly to binary deserializers
// ---------------------------------------------------------------------------

func TestJS_DeserSink_MsgpackDecode(t *testing.T) {
	code := `
const msgpack = require('@msgpack/msgpack');

app.post('/decode', (req, res) => {
    const payload = req.body.data;
    const obj = msgpack.decode(payload);
    res.json(obj);
});
`
	flows := Analyze(code, "/app/routes/decode.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink for req.body -> msgpack.decode()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSink_BSONDeserialize(t *testing.T) {
	code := `
const { BSON } = require('bson');

app.post('/parse', (req, res) => {
    const raw = req.body.bsonPayload;
    const doc = BSON.deserialize(raw);
    res.json(doc);
});
`
	flows := Analyze(code, "/app/routes/parse.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink for req.body -> BSON.deserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSink_CborDecode(t *testing.T) {
	code := `
const cbor = require('cbor-x');

app.post('/interpret', (req, res) => {
    const buf = req.body.payload;
    const obj = cbor.decode(buf);
    res.json(obj);
});
`
	flows := Analyze(code, "/app/routes/interpret.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink for req.body -> cbor.decode()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_DeserSink_MsgpackUnpack(t *testing.T) {
	code := `
const msgpack = require('msgpack-lite');

app.post('/unpack', (req, res) => {
    const raw = req.body.msgpackData;
    const result = msgpack.unpack(raw);
    res.json(result);
});
`
	flows := Analyze(code, "/app/routes/unpack.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink for req.body -> msgpack.unpack()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
