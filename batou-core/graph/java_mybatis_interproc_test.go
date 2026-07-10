package graph

import (
	"os"
	"path/filepath"
	"testing"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// javaProject is a tiny on-disk Maven-layout fixture builder shared by the
// MyBatis/interface-dispatch tests. It writes each file under
// src/main/java, builds the call-graph nodes, runs the cross-file
// resolution pass, then pre-computes every node's taint signature (as a
// prior per-file scan would have done) so the interproc walk has caller
// signatures to consult.
type javaProject struct {
	root     string
	srcRoot  string
	cg       *CallGraph
	contents map[string]string // absolute path → source
}

func newJavaProject(t *testing.T) *javaProject {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	return &javaProject{
		root:     root,
		srcRoot:  filepath.Join(root, "src", "main", "java"),
		cg:       NewCallGraph(root, "test"),
		contents: map[string]string{},
	}
}

// addFile writes a .java file at the given dotted package + class name and
// records its source. pkg is "com.macro.mall.controller"; class is
// "UserController". Returns the absolute file path.
func (p *javaProject) addFile(t *testing.T, pkg, class, src string) string {
	t.Helper()
	dir := filepath.Join(p.srcRoot, filepath.FromSlash(pkgToPath(pkg)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, class+".java")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(path)
	p.contents[abs] = src
	return abs
}

func pkgToPath(pkg string) string {
	out := ""
	for _, c := range pkg {
		if c == '.' {
			out += "/"
		} else {
			out += string(c)
		}
	}
	return out
}

// resolve builds nodes for every added file, runs the cross-file pass, and
// pre-computes every node's signature.
func (p *javaProject) resolve(t *testing.T) ResolveStats {
	t.Helper()
	for abs, src := range p.contents {
		buildJavaNodes(p.cg, abs, src, nil)
	}
	bc := map[string][]byte{}
	for abs, src := range p.contents {
		bc[abs] = []byte(src)
	}
	stats := ResolveCrossFileEdges(p.cg, p.root, bc)
	for _, n := range p.cg.Nodes {
		n.TaintSig = ComputeTaintSigTyped(n, p.contents[n.FilePath], n.Language, nil, nil, nil)
	}
	return stats
}

// propagateFrom resets the named node's signature and runs the interproc
// walk starting from it (simulating that node being the freshly-changed
// function). nodeID is "<absPath>:<Name>".
func (p *javaProject) propagateFrom(nodeID string) []rules.Finding {
	if n := p.cg.GetNode(nodeID); n != nil {
		n.TaintSig = TaintSignature{}
	}
	return PropagateInterprocTyped(p.cg, []string{nodeID}, p.contents, nil, nil, nil)
}

func hasSQLInjectionFinding(findings []rules.Finding) bool {
	for _, f := range findings {
		if f.CWEID == "CWE-89" {
			return true
		}
	}
	return false
}

// --- Source fixtures shared across tests ------------------------------------

const javaCtrlViaServiceSrc = `package com.macro.mall.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestParam;
import com.macro.mall.service.UserService;
public class UserController {
    @Autowired
    private UserService userService;
    public Object list(@RequestParam String sort) {
        return userService.listBySort(sort);
    }
}
`

const javaServiceIfaceSrc = `package com.macro.mall.service;
public interface UserService {
    Object listBySort(String sort);
}
`

const javaServiceImplSrc = `package com.macro.mall.service.impl;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import com.macro.mall.service.UserService;
import com.macro.mall.mapper.UserMapper;
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;
    public Object listBySort(String sort) {
        return userMapper.listBySort(sort);
    }
}
`

// TestJavaMyBatis_ControllerServiceMapper_DollarFlow is the primary
// end-to-end test: a Spring controller's @RequestParam flows through an
// @Autowired service INTERFACE into a @Mapper @Select("... ${sort}")
// mapper method. The full controller → service-interface → mapper chain
// must resolve cross-file and produce a CWE-89 SQL-injection finding.
func TestJavaMyBatis_ControllerServiceMapper_DollarFlow(t *testing.T) {
	p := newJavaProject(t)
	p.addFile(t, "com.macro.mall.controller", "UserController", javaCtrlViaServiceSrc)
	p.addFile(t, "com.macro.mall.service", "UserService", javaServiceIfaceSrc)
	p.addFile(t, "com.macro.mall.service.impl", "UserServiceImpl", javaServiceImplSrc)
	mapperAbs := p.addFile(t, "com.macro.mall.mapper", "UserMapper", `package com.macro.mall.mapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Param;
@Mapper
public interface UserMapper {
    @Select("SELECT * FROM user ORDER BY ${sort}")
    java.util.List<Object> listBySort(@Param("sort") String sort);
}
`)

	stats := p.resolve(t)
	// Both interface-dispatch edges (controller→impl, impl→mapper) must
	// have resolved; nothing left unresolved.
	if stats.CrossFileEdges < 2 {
		t.Errorf("CrossFileEdges = %d, want >= 2 (stats=%+v)", stats.CrossFileEdges, stats)
	}

	mapperID := mapperAbs + ":UserMapper.listBySort"
	mapperNode := p.cg.GetNode(mapperID)
	if mapperNode == nil {
		t.Fatalf("mapper node %q not in graph", mapperID)
	}
	// The mapper method must carry a synthetic CWE-89 SQL sink.
	if len(mapperNode.TaintSig.SinkCalls) == 0 {
		t.Fatalf("mapper node has no sink calls; want a MyBatis ${} SQL sink")
	}
	foundSink := false
	for _, s := range mapperNode.TaintSig.SinkCalls {
		if s.SinkCategory == taint.SnkSQLQuery && s.MethodName == javaMyBatisSinkMethod {
			foundSink = true
			if s.ArgFromParam != 0 {
				t.Errorf("mapper sink ArgFromParam = %d, want 0 (${sort} → param sort at index 0)", s.ArgFromParam)
			}
		}
	}
	if !foundSink {
		t.Errorf("mapper node missing the MyBatis ${} SQL sink (sinks=%+v)", mapperNode.TaintSig.SinkCalls)
	}

	findings := p.propagateFrom(mapperID)
	if !hasSQLInjectionFinding(findings) {
		t.Fatalf("expected a CWE-89 interprocedural SQL-injection finding; got %d findings: %+v", len(findings), findings)
	}
}

// TestJavaMyBatis_ParameterizedHash_NoFinding is the negative test: the
// SAME chain but with `#{sort}` (prepared-statement parameter binding)
// instead of `${sort}` must NOT flag — #{...} is safe.
func TestJavaMyBatis_ParameterizedHash_NoFinding(t *testing.T) {
	p := newJavaProject(t)
	p.addFile(t, "com.macro.mall.controller", "UserController", javaCtrlViaServiceSrc)
	p.addFile(t, "com.macro.mall.service", "UserService", javaServiceIfaceSrc)
	p.addFile(t, "com.macro.mall.service.impl", "UserServiceImpl", javaServiceImplSrc)
	mapperAbs := p.addFile(t, "com.macro.mall.mapper", "UserMapper", `package com.macro.mall.mapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Param;
@Mapper
public interface UserMapper {
    @Select("SELECT * FROM user WHERE sort = #{sort}")
    java.util.List<Object> listBySort(@Param("sort") String sort);
}
`)

	p.resolve(t)
	mapperID := mapperAbs + ":UserMapper.listBySort"
	mapperNode := p.cg.GetNode(mapperID)
	if mapperNode == nil {
		t.Fatalf("mapper node %q not in graph", mapperID)
	}
	// No MyBatis ${} sink should be synthesised for a #{}-only mapper.
	for _, s := range mapperNode.TaintSig.SinkCalls {
		if s.MethodName == javaMyBatisSinkMethod {
			t.Fatalf("#{} parameterised mapper must NOT get a MyBatis ${} sink (sinks=%+v)", mapperNode.TaintSig.SinkCalls)
		}
	}

	findings := p.propagateFrom(mapperID)
	if hasSQLInjectionFinding(findings) {
		t.Fatalf("#{} parameterised mapper must NOT produce a CWE-89 finding; got %+v", findings)
	}
}

// TestJavaMyBatis_ControllerDirectMapper_DollarFlow covers the simpler
// shape where the controller @Autowires the @Mapper interface directly
// (no service layer). controller.@RequestParam → mapper @Select ${} must
// still flag.
func TestJavaMyBatis_ControllerDirectMapper_DollarFlow(t *testing.T) {
	p := newJavaProject(t)
	p.addFile(t, "com.macro.mall.controller", "OrderController", `package com.macro.mall.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestParam;
import com.macro.mall.mapper.OrderMapper;
public class OrderController {
    @Autowired
    private OrderMapper orderMapper;
    public Object list(@RequestParam String column) {
        return orderMapper.listByColumn(column);
    }
}
`)
	mapperAbs := p.addFile(t, "com.macro.mall.mapper", "OrderMapper", `package com.macro.mall.mapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Param;
@Mapper
public interface OrderMapper {
    @Select("SELECT * FROM orders ORDER BY ${column}")
    java.util.List<Object> listByColumn(@Param("column") String column);
}
`)

	stats := p.resolve(t)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	mapperID := mapperAbs + ":OrderMapper.listByColumn"
	findings := p.propagateFrom(mapperID)
	if !hasSQLInjectionFinding(findings) {
		t.Fatalf("controller→mapper direct ${} chain: expected CWE-89 finding; got %+v", findings)
	}
}

// --- Unit tests for the new helpers ----------------------------------------

func TestJavaBodyHasMyBatisDollarSink(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"select dollar", `@Select("SELECT * FROM t ORDER BY ${col}") List q();`, true},
		{"update dollar", `@Update("UPDATE t SET x=1 WHERE y=${id}") void u();`, true},
		{"select hash safe", `@Select("SELECT * FROM t WHERE id=#{id}") T q();`, false},
		{"no annotation but dollar", `String s = "${notSql}";`, false},
		{"annotation no dollar", `@Select("SELECT 1") int q();`, false},
		{"provider dollar", `@SelectProvider(type=X.class) List q(); // ${x}`, true},
		{"mixed hash and dollar", `@Select("SELECT * FROM t WHERE id=#{id} ORDER BY ${col}") T q();`, true},
	}
	for _, c := range cases {
		if got := javaBodyHasMyBatisDollarSink(c.body); got != c.want {
			t.Errorf("%s: javaBodyHasMyBatisDollarSink(%q) = %v, want %v", c.name, c.body, got, c.want)
		}
	}
}

func TestMyBatisDollarParamNames(t *testing.T) {
	names := mybatisDollarParamNames(`@Select("... ORDER BY ${sort} , ${order.column}")`)
	want := map[string]bool{"sort": true, "order": true}
	if len(names) != 2 {
		t.Fatalf("got %v, want two names", names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected dollar param name %q", n)
		}
	}
}

func TestCollectJavaClassMetadata_Fields(t *testing.T) {
	src := `package com.x;
import a.b.UserService;
public class C {
    @Autowired
    private UserService userService;
    @Resource
    private OrderMapper orderMapper;
    private String notInjected;
}
`
	tree := tsast.Parse([]byte(src), rules.LangJava)
	if tree == nil {
		t.Fatal("parse failed")
	}
	aux := map[string]string{}
	collectJavaClassMetadata(tree.Root(), aux)
	if aux[javaAuxFieldPrefix+"userService"] != "UserService" {
		t.Errorf("userService field type = %q, want UserService", aux[javaAuxFieldPrefix+"userService"])
	}
	if aux[javaAuxFieldPrefix+"orderMapper"] != "OrderMapper" {
		t.Errorf("orderMapper field type = %q, want OrderMapper", aux[javaAuxFieldPrefix+"orderMapper"])
	}
	// Non-injected field must NOT be recorded (it isn't a DI receiver).
	if _, ok := aux[javaAuxFieldPrefix+"notInjected"]; ok {
		t.Errorf("notInjected should not be captured (no DI annotation)")
	}
}

func TestCollectJavaClassMetadata_ImplementsAndAnnotations(t *testing.T) {
	src := `package com.x;
@Service
public class UserServiceImpl implements UserService, Auditable {
    public void m() {}
}
`
	tree := tsast.Parse([]byte(src), rules.LangJava)
	if tree == nil {
		t.Fatal("parse failed")
	}
	aux := map[string]string{}
	collectJavaClassMetadata(tree.Root(), aux)
	if aux[javaAuxImplementsPrefix+"UserServiceImpl"] != "UserService,Auditable" {
		t.Errorf("implements = %q, want UserService,Auditable", aux[javaAuxImplementsPrefix+"UserServiceImpl"])
	}
	if aux[javaAuxBeanPrefix+"UserServiceImpl"] != "1" {
		t.Errorf("@Service class should be flagged as a bean")
	}
}

func TestCollectJavaClassMetadata_MapperAnnotation(t *testing.T) {
	src := `package com.x;
@Mapper
public interface UserMapper {
    Object q();
}
`
	tree := tsast.Parse([]byte(src), rules.LangJava)
	if tree == nil {
		t.Fatal("parse failed")
	}
	aux := map[string]string{}
	collectJavaClassMetadata(tree.Root(), aux)
	if aux[javaAuxMapperPrefix+"UserMapper"] != "1" {
		t.Errorf("@Mapper interface should be flagged; aux=%v", aux)
	}
	if aux[javaAuxBeanPrefix+"UserMapper"] != "1" {
		t.Errorf("@Mapper should also count as a bean stereotype")
	}
}

func TestImplIndex_SingleImplOnly(t *testing.T) {
	idx := newImplIndex()
	idx.add("FooServiceImpl", "/a/FooServiceImpl.java", true, []string{"FooService"})
	if rec, ok := idx.lookup("FooService"); !ok || rec.className != "FooServiceImpl" {
		t.Errorf("single impl lookup failed: %+v ok=%v", rec, ok)
	}
	// Two non-bean impls → ambiguous → not resolved.
	idx.add("BarA", "/a/BarA.java", false, []string{"Bar"})
	idx.add("BarB", "/a/BarB.java", false, []string{"Bar"})
	if _, ok := idx.lookup("Bar"); ok {
		t.Errorf("two impls should be ambiguous (no unique bean)")
	}
	// Two impls but one is a bean → resolves to the bean.
	idx.add("BazReal", "/a/BazReal.java", true, []string{"Baz"})
	idx.add("BazTest", "/a/BazTest.java", false, []string{"Baz"})
	if rec, ok := idx.lookup("Baz"); !ok || rec.className != "BazReal" {
		t.Errorf("bean-annotated impl should win among candidates: %+v ok=%v", rec, ok)
	}
}

// TestUpdateFileWithAST_JavaUnchangedRescanKeepsTreeSitterNodes guards the
// warm-rescan regression that produced 0 findings in the real `bin/batou
// scan` pipeline: on the SECOND scan of an unchanged file, every Java node
// is reused via the content-hash short-circuit, so buildJavaNodes appended
// nothing to updatedIDs. Before the fix it returned a nil slice, which made
// UpdateFileWithAST fall back to buildGenericNodes — that builder re-named
// the mapper method to a bare, unqualified node and dropped the MyBatis
// @Select ${} sink signature, so the cross-file walk found callee-sink=0.
//
// The fix makes buildJavaNodes return a non-nil (possibly empty) slice on a
// successful parse, reserving nil for genuine parse failure. This test
// drives the real UpdateFile dispatcher twice and asserts the
// class-qualified node survives both times — i.e. the tree-sitter builder
// (not the generic one) keeps ownership of an unchanged file.
func TestUpdateFileWithAST_JavaUnchangedRescanKeepsTreeSitterNodes(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	mapperPath := filepath.Join(root, "UserMapper.java")
	src := `package com.acme.shop;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
@Mapper
public interface UserMapper {
    @Select("SELECT * FROM users ORDER BY ${sort}")
    java.util.List<Object> listBySort(String sort);
}
`
	// First scan: cold build. The node must be class-qualified.
	UpdateFile(cg, mapperPath, src, rules.LangJava)
	qualifiedID := FuncID(mapperPath, "UserMapper.listBySort")
	if cg.GetNode(qualifiedID) == nil {
		t.Fatalf("cold build: class-qualified node %q missing", qualifiedID)
	}
	if cg.GetNode(FuncID(mapperPath, "listBySort")) != nil {
		t.Fatalf("cold build: bare (generic-builder) node should NOT exist")
	}

	// Second scan: unchanged content => content-hash reuse => buildJavaNodes
	// appends nothing to updatedIDs. The dispatcher must NOT fall back to the
	// generic builder.
	UpdateFile(cg, mapperPath, src, rules.LangJava)
	if cg.GetNode(qualifiedID) == nil {
		t.Fatalf("warm rescan: class-qualified node %q was clobbered "+
			"(generic-builder fallback regression)", qualifiedID)
	}
	if cg.GetNode(FuncID(mapperPath, "listBySort")) != nil {
		t.Fatalf("warm rescan: bare unqualified node appeared — UpdateFileWithAST " +
			"fell back to buildGenericNodes on unchanged content")
	}

	// And the MyBatis ${} sink must still be derivable from the surviving
	// node (computeTaintSigTyped reaches maybeAppendMyBatisSink).
	n := cg.GetNode(qualifiedID)
	n.TaintSig = ComputeTaintSigTyped(n, src, n.Language, nil, nil, nil)
	foundSink := false
	for _, s := range n.TaintSig.SinkCalls {
		if s.SinkCategory == taint.SnkSQLQuery && s.MethodName == javaMyBatisSinkMethod {
			foundSink = true
		}
	}
	if !foundSink {
		t.Fatalf("warm rescan: MyBatis @Select ${} sink missing on surviving node: %+v",
			n.TaintSig.SinkCalls)
	}
}
