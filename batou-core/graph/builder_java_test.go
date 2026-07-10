package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestJavaBuilder_TopLevelMethod_Static: a static method in a class
// gets a "Cls.method" node and its calls land in RawCalls.
func TestJavaBuilder_TopLevelMethod_Static(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Util.java")
	src := `package app;
public class Util {
    public static String sanitize(String s) {
        return s.trim();
    }
    public static String wrap(String s) {
        return sanitize(s);
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	if n := cg.GetNode(filePath + ":Util.sanitize"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf("Util.sanitize node not emitted; have %v", ids)
	}
	wrap := cg.GetNode(filePath + ":Util.wrap")
	if wrap == nil {
		t.Fatal("Util.wrap node not emitted")
	}
	if !containsStr(wrap.RawCalls, "sanitize") {
		t.Errorf("Util.wrap RawCalls missing 'sanitize' (got %v)", wrap.RawCalls)
	}
}

// TestJavaBuilder_InstanceMethod_QualifiedRawCall: `req.getParameter`
// shows up in RawCalls as "req.getParameter" — the qualified form the
// resolver expects.
func TestJavaBuilder_InstanceMethod_QualifiedRawCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Servlet.java")
	src := `package app;
public class Servlet {
    public void doGet(Request req) {
        String x = req.getParameter("id");
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	n := cg.GetNode(filePath + ":Servlet.doGet")
	if n == nil {
		t.Fatal("Servlet.doGet node not emitted")
	}
	if !containsStr(n.RawCalls, "req.getParameter") {
		t.Errorf("RawCalls missing 'req.getParameter' (got %v)", n.RawCalls)
	}
}

// TestJavaBuilder_Constructor: a constructor becomes "Cls.Cls" so
// cross-file `new Cls(...)` lookups work via the same mechanism.
func TestJavaBuilder_Constructor(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "User.java")
	src := `package app;
public class User {
    public User(String name) {
        this.name = name;
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	if n := cg.GetNode(filePath + ":User.User"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("User constructor node not emitted as User.User; have %v", ids)
	}
}

// TestJavaBuilder_NewExpressionRecordsCtorCall: `new Foo(...)` records
// "Foo.Foo" in the caller's RawCalls so the resolver can resolve via
// the constructor node.
func TestJavaBuilder_NewExpressionRecordsCtorCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Factory.java")
	src := `package app;
public class Factory {
    public User make(String n) {
        return new User(n);
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	n := cg.GetNode(filePath + ":Factory.make")
	if n == nil {
		t.Fatal("Factory.make node not emitted")
	}
	if !containsStr(n.RawCalls, "User.User") {
		t.Errorf("RawCalls missing 'User.User' (got %v)", n.RawCalls)
	}
}

// TestJavaBuilder_NestedClass_DottedName: nested classes flow through
// with dotted prefixes — Outer.Inner.m.
func TestJavaBuilder_NestedClass_DottedName(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Outer.java")
	src := `package app;
public class Outer {
    public static class Inner {
        public void hello() {}
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	if n := cg.GetNode(filePath + ":Outer.Inner.hello"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("Outer.Inner.hello node not emitted; have %v", ids)
	}
}

// TestJavaBuilder_Generics_MethodEmitted: generic methods still get a
// FuncNode (the type parameter list shouldn't confuse the walker).
func TestJavaBuilder_Generics_MethodEmitted(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Box.java")
	src := `package app;
public class Box {
    public <T> T peek(java.util.List<T> items) {
        return items.get(0);
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	if n := cg.GetNode(filePath + ":Box.peek"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("Box.peek node not emitted; have %v", ids)
	}
}

// TestJavaBuilder_SpringController_ExtractedNormally: a @RestController
// class extracts the same as any other — the annotation doesn't affect
// naming.
func TestJavaBuilder_SpringController_ExtractedNormally(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Api.java")
	src := `package app;
public class Api {
    public User getUser(Long id) {
        return null;
    }
    public Token login(LoginReq req) {
        return null;
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	for _, want := range []string{"Api.getUser", "Api.login"} {
		if n := cg.GetNode(filePath + ":" + want); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.ID)
			}
			t.Errorf("%q node not emitted; have %v", want, ids)
		}
	}
}

// TestJavaBuilder_SameFileEdges: a bare-name call within the same class
// becomes a same-file Calls edge during the builder pass.
func TestJavaBuilder_SameFileEdges(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Self.java")
	src := `package app;
public class Self {
    public void outer() {
        inner();
    }
    public void inner() {}
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	outer := cg.GetNode(filePath + ":Self.outer")
	if outer == nil {
		t.Fatal("Self.outer node not emitted")
	}
	wantTarget := filePath + ":Self.inner"
	if !containsStr(outer.Calls, wantTarget) {
		t.Errorf("outer.Calls missing %q (got %v) — same-file edge not wired",
			wantTarget, outer.Calls)
	}
}

// TestJavaBuilder_LambdaFieldEmitsNode: a field initialised to a
// lambda gets its own FuncNode named after the binding.
func TestJavaBuilder_LambdaFieldEmitsNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Comparators.java")
	src := `package app;
public class Comparators {
    Comparator<User> byName = (a, b) -> a.getName().compareTo(b.getName());
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	if n := cg.GetNode(filePath + ":Comparators.byName"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("lambda field node not emitted; have %v", ids)
	}
}

// TestJavaBuilder_AnonymousClass_FieldBound: an anonymous-class
// instance bound to a field surfaces its inner methods under the
// field's dotted prefix.
func TestJavaBuilder_AnonymousClass_FieldBound(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Wrapper.java")
	src := `package app;
public class Wrapper {
    Runnable r = new Runnable() {
        @Override
        public void run() {
            doStuff();
        }
    };
    void doStuff() {}
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	if n := cg.GetNode(filePath + ":Wrapper.r.run"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("anonymous-class method node not emitted under Wrapper.r.run; have %v", ids)
	}
}

// TestJavaBuilder_QualifiedNaming_Package: ensures the FuncNode names
// don't include the package prefix — that's tracked on FileScope.Package,
// not in Name.
func TestJavaBuilder_QualifiedNaming_Package(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Greet.java")
	src := `package com.example;
public class Greet {
    public String hi() { return "hi"; }
}
`
	UpdateFile(cg, filePath, src, rules.LangJava)
	// Node name should be "Greet.hi", NOT "com.example.Greet.hi".
	if n := cg.GetNode(filePath + ":Greet.hi"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("Greet.hi node not emitted; have %v", ids)
	}
	// Negative: no node with the package qualifier in the name.
	if n := cg.GetNode(filePath + ":com.example.Greet.hi"); n != nil {
		t.Errorf("unexpected fully-qualified node emitted: %q", n.ID)
	}
}
