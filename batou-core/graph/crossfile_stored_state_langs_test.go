// Cross-file STORED-STATE taint tests for the non-Python languages
// (Java, JavaScript/TypeScript, Ruby, C#).
//
// Each language gets:
//   - a positive case (store external taint in an instance field in file A,
//     read it into a sink in file B; the two methods share a class name across
//     files and have no call edge) — must emit;
//   - param-source negative (field set from a method parameter) — must NOT emit;
//   - sanitized-write negative — must NOT emit;
//   - distinct-class negative (field written in class A, read in class B) —
//     must NOT emit.
//
// The load-bearing assertion is the positive: it fires only because this pass
// exists. The build-and-walk helper below joins purely by enclosing class
// identity, so it does not depend on import resolution (unlike the Python
// module-global channel, which is deferred).

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// storedStateBuildAndWalk writes the files, builds FuncNodes with the given
// per-file builder, resolves cross-file edges, and returns the stored-state
// findings. The builder is chosen by the test per language.
func storedStateBuildAndWalk(t *testing.T, files map[string]string, build func(cg *CallGraph, abs, content string)) []rules.Finding {
	t.Helper()
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	contents := map[string][]byte{}
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		if err := writeFiles(t, root, map[string]string{rel: content}); err != nil {
			t.Fatalf("writeFiles %s: %v", rel, err)
		}
		build(cg, abs, content)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return WalkCrossFileStoredState(cg)
}

func buildJava(cg *CallGraph, abs, content string)   { buildJavaNodes(cg, abs, content, nil) }
func buildCSharp(cg *CallGraph, abs, content string) { buildCSharpNodes(cg, abs, content, nil) }
func buildRubyN(cg *CallGraph, abs, content string)  { buildRubyNodes(cg, abs, content, nil) }
func buildKotlin(cg *CallGraph, abs, content string) { buildKotlinNodes(cg, abs, content, nil) }
func buildSwift(cg *CallGraph, abs, content string)  { buildSwiftNodes(cg, abs, content, nil) }
func buildGroovy(cg *CallGraph, abs, content string) { buildGroovyNodes(cg, abs, content, nil) }
func buildJS(cg *CallGraph, abs, content string) {
	buildJSNodes(cg, abs, content, rules.LangJavaScript, nil)
}
func buildTS(cg *CallGraph, abs, content string) {
	buildJSNodes(cg, abs, content, rules.LangTypeScript, nil)
}

// assertStoredFinding asserts exactly that a stored-state finding for the
// given field needle exists (or doesn't, when want=false), with the two-step
// cross-file taint path and confidence 0.8 on a positive.
func assertStoredFinding(t *testing.T, findings []rules.Finding, fieldNeedle string, want bool) {
	t.Helper()
	got := hasStoredStateFinding(findings, fieldNeedle)
	if got != want {
		t.Fatalf("stored-state finding for %q: got=%v want=%v (%d findings: %+v)", fieldNeedle, got, want, len(findings), findings)
	}
	if !want {
		return
	}
	var found rules.Finding
	for _, f := range findings {
		if strings.Contains(f.Title, fieldNeedle) {
			found = f
			break
		}
	}
	if len(found.TaintPath) < 2 {
		t.Fatalf("expected a two-step taint path, got %+v", found.TaintPath)
	}
	if found.ConfidenceScore != 0.8 {
		t.Errorf("expected confidence 0.8, got %v", found.ConfidenceScore)
	}
}

// ---------------- Java ----------------

func TestStoredState_Java_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.java": `public class UserController {
    public void load(HttpServletRequest request) {
        this.userQuery = request.getParameter("q");
    }
}
`,
		"Use.java": `public class UserController {
    public void run() throws Exception {
        Runtime.getRuntime().exec(this.userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Java_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.java": `public class UserController {
    public void load(String data) {
        this.userQuery = data;
    }
}
`,
		"Use.java": `public class UserController {
    public void run() throws Exception {
        Runtime.getRuntime().exec(this.userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Java_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.java": `public class UserController {
    public void load(HttpServletRequest request) {
        this.userQuery = Encode.forHtml(request.getParameter("q"));
    }
}
`,
		"Use.java": `public class UserController {
    public void run() throws Exception {
        Runtime.getRuntime().exec(this.userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Java_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.java": `public class Writer {
    public void load(HttpServletRequest request) {
        this.userQuery = request.getParameter("q");
    }
}
`,
		"Use.java": `public class Reader {
    public void run() throws Exception {
        Runtime.getRuntime().exec(this.userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", false)
}

// ---------------- JavaScript ----------------

func TestStoredState_JS_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.js": `class UserController {
  load(req) {
    this.userQuery = req.query.q;
  }
}
module.exports = UserController;
`,
		"use.js": `class UserController {
  run() {
    child_process.exec(this.userQuery);
  }
}
module.exports = UserController;
`,
	}, buildJS)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_JS_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.js": `class UserController {
  load(data) {
    this.userQuery = data;
  }
}
module.exports = UserController;
`,
		"use.js": `class UserController {
  run() {
    child_process.exec(this.userQuery);
  }
}
module.exports = UserController;
`,
	}, buildJS)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_JS_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.js": `class UserController {
  load(req) {
    this.userQuery = encodeURIComponent(req.query.q);
  }
}
module.exports = UserController;
`,
		"use.js": `class UserController {
  run() {
    child_process.exec(this.userQuery);
  }
}
module.exports = UserController;
`,
	}, buildJS)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_JS_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.js": `class Writer {
  load(req) {
    this.userQuery = req.query.q;
  }
}
module.exports = Writer;
`,
		"use.js": `class Reader {
  run() {
    child_process.exec(this.userQuery);
  }
}
module.exports = Reader;
`,
	}, buildJS)
	assertStoredFinding(t, f, "userQuery", false)
}

// ---------------- TypeScript ----------------

func TestStoredState_TS_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.ts": `export class UserController {
  load(req): void {
    this.userQuery = req.query.q;
  }
}
`,
		"use.ts": `export class UserController {
  run(): void {
    child_process.exec(this.userQuery);
  }
}
`,
	}, buildTS)
	assertStoredFinding(t, f, "userQuery", true)
}

// ---------------- Ruby ----------------

func TestStoredState_Ruby_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.rb": `class UserController
  def load
    @user_query = params[:q]
  end
end
`,
		"use.rb": `class UserController
  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", true)
}

func TestStoredState_Ruby_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.rb": `class UserController
  def load(data)
    @user_query = data
  end
end
`,
		"use.rb": `class UserController
  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

func TestStoredState_Ruby_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.rb": `class UserController
  def load
    @user_query = Shellwords.escape(params[:q])
  end
end
`,
		"use.rb": `class UserController
  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

func TestStoredState_Ruby_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.rb": `class Writer
  def load
    @user_query = params[:q]
  end
end
`,
		"use.rb": `class Reader
  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// ---------------- C# ----------------

func TestStoredState_CSharp_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.cs": `public class UserController {
  public void Load() {
    this.UserQuery = Request.Query["q"];
  }
}
`,
		"Use.cs": `public class UserController {
  public void Run() {
    Process.Start(this.UserQuery);
  }
}
`,
	}, buildCSharp)
	assertStoredFinding(t, f, "UserQuery", true)
}

func TestStoredState_CSharp_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.cs": `public class UserController {
  public void Load(string data) {
    this.UserQuery = data;
  }
}
`,
		"Use.cs": `public class UserController {
  public void Run() {
    Process.Start(this.UserQuery);
  }
}
`,
	}, buildCSharp)
	assertStoredFinding(t, f, "UserQuery", false)
}

func TestStoredState_CSharp_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.cs": `public class UserController {
  public void Load() {
    this.UserQuery = HttpUtility.UrlEncode(Request.Query["q"]);
  }
}
`,
		"Use.cs": `public class UserController {
  public void Run() {
    Process.Start(this.UserQuery);
  }
}
`,
	}, buildCSharp)
	assertStoredFinding(t, f, "UserQuery", false)
}

func TestStoredState_CSharp_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.cs": `public class Writer {
  public void Load() {
    this.UserQuery = Request.Query["q"];
  }
}
`,
		"Use.cs": `public class Reader {
  public void Run() {
    Process.Start(this.UserQuery);
  }
}
`,
	}, buildCSharp)
	assertStoredFinding(t, f, "UserQuery", false)
}

// ---------------- Java: unqualified (bare) instance-field read ----------------

// A Java method reads its own instance field UNQUALIFIED (`exec(userQuery)`
// instead of `exec(this.userQuery)`) — idiomatic Java. The bare-read path
// must still join to the cross-file producer.
func TestStoredState_Java_BareFieldRead(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.java": `public class C {
    String userQuery;
    void load(HttpServletRequest request) {
        this.userQuery = request.getParameter("q");
    }
}
`,
		"Use.java": `public class C {
    String userQuery;
    void run() throws Exception {
        Runtime.getRuntime().exec(userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", true)
}

// A bare read with NO matching tainted field-write producer must NOT fire (the
// field-write producer is the join gate, not the bare token alone).
func TestStoredState_Java_BareReadNoProducerNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.java": `public class C {
    void load(HttpServletRequest request) {
        this.other = request.getParameter("q");
    }
}
`,
		"Use.java": `public class C {
    void run() throws Exception {
        Runtime.getRuntime().exec(userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", false)
}

// ---------------- same-file behaviour ----------------
//
// The same-file cross-method join is language-gated on
// tsflow.SupportsStoredStateChannel: languages whose intra-file tsflow
// stored-state channel already surfaces the flow (Python / JS / TS / Java /
// C#) must stay EXCLUDED here (finalize-emitted findings are never deduped
// against per-file output, so emitting would double-report), while the
// uncovered languages (Ruby / PHP / Kotlin / Swift / Groovy) must EMIT — for
// them this pass is the only engine that sees the flow.

// Java is tsflow-covered: same-file write+read must NOT emit from this
// channel (tsflow's BATOU-TAINT flow already fires at higher confidence).
func TestStoredState_Java_SameFileNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Single.java": `public class UserController {
    public void load(HttpServletRequest request) {
        this.userQuery = request.getParameter("q");
    }
    public void run() throws Exception {
        Runtime.getRuntime().exec(this.userQuery);
    }
}
`,
	}, buildJava)
	assertStoredFinding(t, f, "userQuery", false)
}

// JS is tsflow-covered: same-file write+read across methods must NOT emit
// from this channel.
func TestStoredState_JS_SameFileNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.js": `class UserController {
  load(req) {
    this.userQuery = req.query.q;
  }
  run() {
    child_process.exec(this.userQuery);
  }
}
module.exports = UserController;
`,
	}, buildJS)
	assertStoredFinding(t, f, "userQuery", false)
}

// Ruby has NO tsflow intra-file stored-state channel, so the same-file
// cross-method flow (the canonical instance-field-across-methods recall hole)
// must emit from this pass — with the sink line pointing at the read, a
// two-step taint path, and the cross-method (not cross-file) labels.
func TestStoredState_Ruby_SameFileCrossMethodEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def load
    @user_query = params[:q]
  end

  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", true)
	var found rules.Finding
	for _, fd := range f {
		if strings.Contains(fd.Title, "user_query") {
			found = fd
			break
		}
	}
	if found.LineNumber != 7 {
		t.Errorf("expected sink line 7 (system(@user_query)), got %d", found.LineNumber)
	}
	if !strings.Contains(found.Title, "Cross-method") {
		t.Errorf("expected a Cross-method title for a same-file pair, got %q", found.Title)
	}
	hasCrossMethodTag := false
	for _, tag := range found.Tags {
		if tag == "cross-method" {
			hasCrossMethodTag = true
		}
		if tag == "cross-file" {
			t.Errorf("same-file finding must not carry the cross-file tag, got %v", found.Tags)
		}
	}
	if !hasCrossMethodTag {
		t.Errorf("expected the cross-method tag, got %v", found.Tags)
	}
}

// A write and read inside ONE method must NOT emit (plain intra-procedural
// flow — joining a method to itself would double-report tsflow's output).
func TestStoredState_Ruby_SameMethodNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def handle
    @user_query = params[:q]
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// An untainted (constant) field write must NOT make the field a stored source
// in the same-file join, exactly as in the cross-file variant.
func TestStoredState_Ruby_SameFileConstWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def load
    @user_query = "ls -la"
  end

  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// A sanitized store must NOT emit in the same-file join (mirrors the
// cross-file sanitized-write semantics).
func TestStoredState_Ruby_SameFileSanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def load
    @user_query = Shellwords.escape(params[:q])
  end

  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// An ORM entity lookup keyed by user input stores a DB OBJECT, not the raw
// external value — `@user = User.find_by(id: params[:id])` then
// `sink(@user...)` is the dominant real-world Rails shape and must NOT emit
// (adjudicated majority-FP on discourse before this gate).
func TestStoredState_Ruby_EntityLookupWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def load
    @user = User.find_by(id: params[:id])
  end

  def run
    system(@user)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user", false)
}

// A chained entity lookup (`Reviewable.viewable_by(x).find_by(id: params)`) is
// still an entity lookup — the unbalanced-paren walk must see through the
// balanced intermediate call.
func TestStoredState_Ruby_ChainedEntityLookupNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"store.rb": `class UserController
  def load
    @user_query = Reviewable.viewable_by(current_user, preload: false).find_by(id: params[:reviewable_id])
  end
end
`,
		"use.rb": `class UserController
  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// A constructor wrapping user input (`TopicView.new(params[:topic_id])`)
// stores the wrapper object, not the raw value — must NOT emit.
func TestStoredState_Ruby_ConstructorWrapNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class TopicsController
  def load
    @topic_view = TopicView.new(params[:topic_id])
  end

  def run
    system(@topic_view)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "topic_view", false)
}

// Integer coercion on the stored value (`params[:month].to_i`) cannot carry a
// payload — must NOT emit.
func TestStoredState_Ruby_CoercedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class CakedayController
  def load
    @month = params[:month].to_i.clamp(1..12)
  end

  def run
    @users.where("EXTRACT(MONTH FROM created_at) = #{@month}")
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "month", false)
}

// A line that WRITES the field is not a READ of it: the reader-side scan must
// not treat `@user_query = Marshal.load(data)` (an overwrite) as the stored
// value flowing into Marshal.load.
func TestStoredState_Ruby_WriteLineNotCountedAsRead(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def load
    @user_query = params[:q]
  end

  def run
    @user_query = Marshal.load(data)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// String interpolation of the raw source keeps its taint — the entity-lookup
// gate must not swallow `"#{params[:q]}"`-shaped writes.
func TestStoredState_Ruby_InterpolatedSourceStillEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class UserController
  def load
    @user_query = "prefix #{params[:q]}"
  end

  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", true)
}

// Same-file but DISTINCT classes must not join, exactly as across files.
func TestStoredState_Ruby_SameFileDistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"single.rb": `class Writer
  def load
    @user_query = params[:q]
  end
end

class Reader
  def run
    system(@user_query)
  end
end
`,
	}, buildRubyN)
	assertStoredFinding(t, f, "user_query", false)
}

// ---------------- Kotlin ----------------
//
// `this.field = <source>` stored in file A, read into a sink in file B; the
// two methods share class UserController across files with no call edge.

func TestStoredState_Kotlin_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.kt": `class UserController {
    fun load(call: ApplicationCall) {
        this.userQuery = call.parameters["q"]
    }
}
`,
		"Use.kt": `class UserController {
    fun run() {
        db.rawQuery(this.userQuery)
    }
}
`,
	}, buildKotlin)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Kotlin_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.kt": `class UserController {
    fun load(data: String) {
        this.userQuery = data
    }
}
`,
		"Use.kt": `class UserController {
    fun run() {
        db.rawQuery(this.userQuery)
    }
}
`,
	}, buildKotlin)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Kotlin_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.kt": `class UserController {
    fun load(call: ApplicationCall) {
        this.userQuery = call.parameters["q"].toInt()
    }
}
`,
		"Use.kt": `class UserController {
    fun run() {
        db.rawQuery(this.userQuery)
    }
}
`,
	}, buildKotlin)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Kotlin_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.kt": `class Writer {
    fun load(call: ApplicationCall) {
        this.userQuery = call.parameters["q"]
    }
}
`,
		"Use.kt": `class Reader {
    fun run() {
        db.rawQuery(this.userQuery)
    }
}
`,
	}, buildKotlin)
	assertStoredFinding(t, f, "userQuery", false)
}

// ---------------- Swift ----------------
//
// `self.field = <source>` stored in file A, read into a sink in file B.

func TestStoredState_Swift_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.swift": `class UserController {
    func load(req: Request) {
        self.userQuery = req.query["q"]
    }
}
`,
		"Use.swift": `class UserController {
    func run() {
        system(self.userQuery)
    }
}
`,
	}, buildSwift)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Swift_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.swift": `class UserController {
    func load(data: String) {
        self.userQuery = data
    }
}
`,
		"Use.swift": `class UserController {
    func run() {
        system(self.userQuery)
    }
}
`,
	}, buildSwift)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Swift_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.swift": `class UserController {
    func load(req: Request) {
        self.userQuery = Int(req.query["q"])
    }
}
`,
		"Use.swift": `class UserController {
    func run() {
        system(self.userQuery)
    }
}
`,
	}, buildSwift)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Swift_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.swift": `class Writer {
    func load(req: Request) {
        self.userQuery = req.query["q"]
    }
}
`,
		"Use.swift": `class Reader {
    func run() {
        system(self.userQuery)
    }
}
`,
	}, buildSwift)
	assertStoredFinding(t, f, "userQuery", false)
}

// ---------------- Groovy ----------------
//
// `this.field = <source>` stored in file A, read into a sink in file B.

func TestStoredState_Groovy_Positive(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.groovy": `class UserController {
    def load(request) {
        this.userQuery = request.getParameter("q")
    }
}
`,
		"Use.groovy": `class UserController {
    def run() {
        Runtime.getRuntime().exec(this.userQuery)
    }
}
`,
	}, buildGroovy)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Groovy_ParamSourceNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.groovy": `class UserController {
    def load(data) {
        this.userQuery = data
    }
}
`,
		"Use.groovy": `class UserController {
    def run() {
        Runtime.getRuntime().exec(this.userQuery)
    }
}
`,
	}, buildGroovy)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Groovy_SanitizedWriteNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.groovy": `class UserController {
    def load(request) {
        this.userQuery = URLEncoder.encode(request.getParameter("q"))
    }
}
`,
		"Use.groovy": `class UserController {
    def run() {
        Runtime.getRuntime().exec(this.userQuery)
    }
}
`,
	}, buildGroovy)
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_Groovy_DistinctClassNotJoined(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Store.groovy": `class Writer {
    def load(request) {
        this.userQuery = request.getParameter("q")
    }
}
`,
		"Use.groovy": `class Reader {
    def run() {
        Runtime.getRuntime().exec(this.userQuery)
    }
}
`,
	}, buildGroovy)
	assertStoredFinding(t, f, "userQuery", false)
}

// ---------------- same-file cross-method: Kotlin / Swift / Groovy ----------------
//
// Like Ruby and PHP, these languages have no tsflow intra-file stored-state
// channel, so the same-file cross-method join must emit for them.

func TestStoredState_Kotlin_SameFileCrossMethodEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Single.kt": `class UserController {
    fun load(call: ApplicationCall) {
        this.userQuery = call.parameters["q"]
    }
    fun run() {
        db.rawQuery(this.userQuery)
    }
}
`,
	}, buildKotlin)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Swift_SameFileCrossMethodEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Single.swift": `class UserController {
    func load(req: Request) {
        self.userQuery = req.query["q"]
    }
    func run() {
        system(self.userQuery)
    }
}
`,
	}, buildSwift)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Groovy_SameFileCrossMethodEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Single.groovy": `class UserController {
    def load(request) {
        this.userQuery = request.getParameter("q")
    }
    def run() {
        Runtime.getRuntime().exec(this.userQuery)
    }
}
`,
	}, buildGroovy)
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_Groovy_SameMethodNotEmitted(t *testing.T) {
	f := storedStateBuildAndWalk(t, map[string]string{
		"Single.groovy": `class UserController {
    def handle(request) {
        this.userQuery = request.getParameter("q")
        Runtime.getRuntime().exec(this.userQuery)
    }
}
`,
	}, buildGroovy)
	assertStoredFinding(t, f, "userQuery", false)
}
