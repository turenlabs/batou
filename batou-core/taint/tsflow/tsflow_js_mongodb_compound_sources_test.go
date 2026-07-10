package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// JavaScript/TypeScript — MongoDB / Mongoose compound find-and-modify read-back
// sources for second-order taint (CWE-79 XSS demonstrated end-to-end).
//
// findOneAndUpdate / findOneAndReplace / findOneAndDelete (and the Mongoose
// findByIdAndUpdate / findByIdAndDelete variants) return the document as it
// existed *before* the modification (driver default returnDocument:'before').
// Any attacker-stored field in that returned document is user-controlled data
// read back on a later request; flowing one of its fields into res.send() is
// reflected/stored XSS. Without these sources the downstream HTML sink would
// not fire.
//
// Mirrors js.mongodb.findone (already modeled), php.mongodb.findoneand*
// (PR #1203) and rust MongoDB find_one_and_* (PR #1126).
// ===========================================================================

func TestJS_MongoDB_FindOneAndUpdate_XSS(t *testing.T) {
	code := `
function renderProfile(id) {
    const user = User.findOneAndUpdate({ _id: id }, { $inc: { views: 1 } });
    res.send("<h1>" + user.name + "</h1>");
}
`
	flows := Analyze(code, "/app/routes/profile.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.mongodb.findoneandupdate", taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from MongoDB findOneAndUpdate() pre-update doc -> res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestJS_MongoDB_FindOneAndReplace_XSS(t *testing.T) {
	code := `
function renderProfile(id) {
    const doc = Account.findOneAndReplace({ _id: id }, { active: true });
    res.send("<div>" + doc.bio + "</div>");
}
`
	flows := Analyze(code, "/app/routes/account.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.mongodb.findoneandreplace", taint.SnkHTMLOutput) {
		t.Error("expected flow from MongoDB findOneAndReplace() pre-replacement doc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_MongoDB_FindOneAndDelete_XSS(t *testing.T) {
	code := `
function renderRemoved(id) {
    const removed = Comment.findOneAndDelete({ _id: id });
    res.send("<p>" + removed.body + "</p>");
}
`
	flows := Analyze(code, "/app/routes/comment.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.mongodb.findoneanddelete", taint.SnkHTMLOutput) {
		t.Error("expected flow from MongoDB findOneAndDelete() deleted doc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Mongoose_FindByIdAndUpdate_XSS(t *testing.T) {
	code := `
function renderProfile(postId) {
    const post = Post.findByIdAndUpdate(postId, { $set: { seen: true } });
    res.send("<article>" + post.title + "</article>");
}
`
	flows := Analyze(code, "/app/routes/post.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.mongoose.findbyidandupdate", taint.SnkHTMLOutput) {
		t.Error("expected flow from Mongoose findByIdAndUpdate() pre-update doc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Mongoose_FindByIdAndDelete_XSS(t *testing.T) {
	code := `
function renderRemoved(postId) {
    const post = Post.findByIdAndDelete(postId);
    res.send("<article>" + post.title + "</article>");
}
`
	flows := Analyze(code, "/app/routes/post.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.mongoose.findbyidanddelete", taint.SnkHTMLOutput) {
		t.Error("expected flow from Mongoose findByIdAndDelete() deleted doc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative control: a compound op with no field flowing to a sink, and a
// constant string to res.send(), must not produce an XSS flow.
func TestJS_MongoDB_FindOneAndUpdate_NoFlow(t *testing.T) {
	code := `
function renderStatic(id) {
    const user = User.findOneAndUpdate({ _id: id }, { $inc: { views: 1 } });
    res.send("<h1>static heading</h1>");
}
`
	flows := Analyze(code, "/app/routes/static.js", rules.LangJavaScript)
	if flowFromSourceTo(flows, "js.mongodb.findoneandupdate", taint.SnkHTMLOutput) {
		t.Error("did not expect XSS flow when only a constant string reaches res.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
