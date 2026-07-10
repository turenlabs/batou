package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// First non-Go extractor — proves the cross-language abstraction. Test
// shape mirrors extractor_golang_realworld_test.go so per-language PRs
// for the remaining 13 languages can copy this structure.

// -----------------------------------------------------------------------
// Servlet API — the primary source surface for Java web apps.
// -----------------------------------------------------------------------

func TestJavaExtractor_Servlet_HttpServletRequest_Javax(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "servlet_http_request_source",
			FilePath: "/app/src/main/java/BenchmarkTest00001.java",
			Content: `package org.owasp.benchmark.testcode;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest00001 {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("foo");
    }
}
`,
			Func: "BenchmarkTest00001.doPost",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "request",
					CanonicalType:  "javax.servlet.http.HttpServletRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
				{
					// HttpServletResponse is a servlet OUTPUT object, never user
					// input — it is in javaDIParamTypeAllowlist and must NOT be
					// tagged as a taint source (#1288 fixed the block-FP where a
					// seeded response tripped header/XSS sinks on its own calls).
					Index:         1,
					Name:          "response",
					CanonicalType: "javax.servlet.http.HttpServletResponse",
					IsSourceType:  false,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_Servlet_HttpServletRequest_Jakarta(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "jakarta_servlet_http_request_source",
			FilePath: "/app/JakartaHandler.java",
			Content: `package app;

import jakarta.servlet.http.HttpServletRequest;

public class JakartaHandler {
    public String handle(HttpServletRequest req) {
        return req.getParameter("q");
    }
}
`,
			Func: "JakartaHandler.handle",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "req",
					CanonicalType:  "jakarta.servlet.http.HttpServletRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
			WantReturns: []ReturnTaint{
				{Type: "String", CanonicalType: "String"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// Spring — MultipartFile (upload) + ServerHttpRequest (reactive).
// -----------------------------------------------------------------------

func TestJavaExtractor_Spring_MultipartFile(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "spring_multipart_file_source",
			FilePath: "/app/UploadController.java",
			Content: `package app;

import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    public void upload(MultipartFile file, String name) {
    }
}
`,
			Func: "UploadController.upload",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "file",
					CanonicalType:  "org.springframework.web.multipart.MultipartFile",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
				{
					Index:         1,
					Name:          "name",
					CanonicalType: "String",
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// JDBC — ResultSet (source) + PreparedStatement (sink).
// -----------------------------------------------------------------------

func TestJavaExtractor_JDBC_ResultSetAndPreparedStatement(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "resultset_source_param",
			FilePath: "/app/UserDAO.java",
			Content: `package app;

import java.sql.ResultSet;

public class UserDAO {
    public String readName(ResultSet rs) throws Exception {
        return rs.getString("name");
    }
}
`,
			Func: "UserDAO.readName",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "rs",
					CanonicalType:  "java.sql.ResultSet",
					IsSourceType:   true,
					SourceCategory: taint.SrcDatabase,
				},
			},
		},
		{
			Name:     "prepared_statement_sink_param",
			FilePath: "/app/QueryBuilder.java",
			Content: `package app;

import java.sql.PreparedStatement;

public class QueryBuilder {
    public void bind(PreparedStatement stmt, String value) throws Exception {
        stmt.setString(1, value);
    }
}
`,
			Func: "QueryBuilder.bind",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "stmt",
					CanonicalType: "java.sql.PreparedStatement",
					IsSinkType:    true,
					SinkCategory:  taint.SnkSQLQuery,
				},
				{
					Index:         1,
					Name:          "value",
					CanonicalType: "String",
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// I/O — InputStream and Reader as network sources.
// -----------------------------------------------------------------------

func TestJavaExtractor_IO_InputStream(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "input_stream_network_source",
			FilePath: "/app/StreamReader.java",
			Content: `package app;

import java.io.InputStream;

public class StreamReader {
    public byte[] slurp(InputStream in) throws Exception {
        return in.readAllBytes();
    }
}
`,
			Func: "StreamReader.slurp",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "in",
					CanonicalType:  "java.io.InputStream",
					IsSourceType:   true,
					SourceCategory: taint.SrcNetwork,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// Parameter shapes — multiple params, generics, arrays, varargs.
// -----------------------------------------------------------------------

func TestJavaExtractor_ParamShape_Varargs(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "varargs_preserved_in_raw_type",
			FilePath: "/app/Logger.java",
			Content: `package app;

public class Logger {
    public void log(String level, String... parts) {
    }
}
`,
			Func: "Logger.log",
			WantParams: []ParamTaint{
				{Index: 0, Name: "level", CanonicalType: "String"},
				{Index: 1, Name: "parts"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_ParamShape_Generics(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "generic_list_param",
			FilePath: "/app/Sorter.java",
			Content: `package app;

import java.util.List;

public class Sorter {
    public void sort(List<String> items) {
    }
}
`,
			Func: "Sorter.sort",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "items",
					CanonicalType: "java.util.List<String>",
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// Type hierarchy — nested class, constructor, inheritance.
// -----------------------------------------------------------------------

func TestJavaExtractor_NestedClass_Naming(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "nested_class_method_uses_dotted_name",
			FilePath: "/app/Outer.java",
			Content: `package app;

public class Outer {
    public static class Inner {
        public String hello(String name) {
            return "hi " + name;
        }
    }
}
`,
			Func: "Outer.Inner.hello",
			WantParams: []ParamTaint{
				{Index: 0, Name: "name", CanonicalType: "String"},
			},
			WantReturns: []ReturnTaint{
				{Type: "String", CanonicalType: "String"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_Constructor(t *testing.T) {
	// Constructors have no return type; the extractor should emit a
	// FuncSignature with no Returns and correctly-named params.
	cases := []HarnessCase{
		{
			Name:     "constructor_with_request_param",
			FilePath: "/app/Handler.java",
			Content: `package app;

import javax.servlet.http.HttpServletRequest;

public class Handler {
    public Handler(HttpServletRequest request) {
    }
}
`,
			Func: "Handler.Handler",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "request",
					CanonicalType:  "javax.servlet.http.HttpServletRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// Return types — source-typed return flagged via SourceReturn catalog.
// -----------------------------------------------------------------------

func TestJavaExtractor_Returns_SourceTyped(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "method_returning_request_is_source_return",
			FilePath: "/app/Factory.java",
			Content: `package app;

import javax.servlet.http.HttpServletRequest;

public class Factory {
    public HttpServletRequest build() {
        return null;
    }
}
`,
			Func: "Factory.build",
			WantReturns: []ReturnTaint{
				{
					CanonicalType:  "javax.servlet.http.HttpServletRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// Negative cases — plain types not over-flagged.
// -----------------------------------------------------------------------

func TestJavaExtractor_NegativeCases(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "plain_types_not_flagged",
			FilePath: "/app/Arith.java",
			Content: `package app;

public class Arith {
    public int add(int a, int b) {
        return a + b;
    }
}
`,
			Func: "Arith.add",
			WantParams: []ParamTaint{
				{Index: 0, Name: "a", CanonicalType: "int"},
				{Index: 1, Name: "b", CanonicalType: "int"},
			},
			WantReturns: []ReturnTaint{
				{Type: "int", CanonicalType: "int"},
			},
		},
		{
			Name:     "custom_unrelated_type_not_matched",
			FilePath: "/app/UseLogger.java",
			Content: `package app;

public class UseLogger {
    public void configure(Logger logger) {
    }
}
`,
			Func: "UseLogger.configure",
			WantParams: []ParamTaint{
				{Index: 0, Name: "logger", CanonicalType: "Logger"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// Wire-up end-to-end — via ComputeTaintSigTyped so we verify the
// registry path produces a TaintSignature with Java-derived Params.
// -----------------------------------------------------------------------

func TestJavaExtractor_WireUp_ViaComputeTaintSig(t *testing.T) {
	content := `package app;

import javax.servlet.http.HttpServletRequest;

public class Servlet {
    public void doPost(HttpServletRequest request) {
    }
}
`
	node := &FuncNode{
		Name:     "Servlet.doPost",
		FilePath: "/app/Servlet.java",
		Language: rules.LangJava,
	}
	sig := ComputeTaintSigTyped(node, content, rules.LangJava, nil, nil, nil)

	if len(sig.Params) != 1 {
		t.Fatalf("expected 1 Param, got %d", len(sig.Params))
	}
	p := sig.Params[0]
	if p.CanonicalType != "javax.servlet.http.HttpServletRequest" {
		t.Errorf("Params[0].CanonicalType = %q", p.CanonicalType)
	}
	if !p.IsSourceType {
		t.Error("Params[0].IsSourceType = false, want true")
	}
	if cat, ok := sig.SourceParams[0]; !ok || cat != taint.SrcUserInput {
		t.Errorf("SourceParams[0] = %q (ok=%v), want %q", cat, ok, taint.SrcUserInput)
	}
	if sig.TypesVersion != TypesSchemaVersion {
		t.Errorf("TypesVersion = %d, want %d", sig.TypesVersion, TypesSchemaVersion)
	}
}

// -----------------------------------------------------------------------
// PR-BBjava: framework parameter annotations — Spring MVC, JAX-RS,
// Micronaut, Quarkus. Each handler-style annotation on a formal
// parameter should mark the parameter as a SrcUserInput source.
// -----------------------------------------------------------------------

func TestJavaExtractor_FrameworkAnnotations_Spring(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "spring_request_param_marks_param",
			FilePath: "/app/UserController.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class UserController {
    @GetMapping("/users")
    public String getUser(@RequestParam String id) {
        return id;
    }
}
`,
			Func: "UserController.getUser",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "id",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			Name:     "spring_request_body_marks_param",
			FilePath: "/app/LoginController.java",
			Content: `package app;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public class LoginController {
    @PostMapping("/login")
    public String login(@RequestBody LoginReq req) {
        return req.toString();
    }
}
`,
			Func: "LoginController.login",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "req",
					Type:           "LoginReq",
					CanonicalType:  "LoginReq",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			// PR-CATjava (Fix 3): numeric / UUID @PathVariable types
			// are no longer auto-tagged. Jackson rejects malformed
			// input before the handler body runs, so a Long path
			// variable cannot carry SQL/command/path payloads.
			Name:     "spring_path_variable_numeric_not_source",
			FilePath: "/app/PathController.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public class PathController {
    @GetMapping("/users/{id}")
    public String h(@PathVariable("id") Long id) {
        return id.toString();
    }
}
`,
			Func: "PathController.h",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "id",
					Type:          "Long",
					CanonicalType: "Long",
				},
			},
		},
		{
			// String @PathVariable IS still a source — only numeric /
			// UUID types are suppressed by Fix 3.
			Name:     "spring_path_variable_string_still_source",
			FilePath: "/app/PathStr.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public class PathStr {
    @GetMapping("/u/{name}")
    public String h(@PathVariable("name") String name) {
        return name;
    }
}
`,
			Func: "PathStr.h",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "name",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			Name:     "spring_request_header_marks_param",
			FilePath: "/app/HeaderController.java",
			Content: `package app;

import org.springframework.web.bind.annotation.RequestHeader;

public class HeaderController {
    public String h(@RequestHeader("X-User") String user) {
        return user;
    }
}
`,
			Func: "HeaderController.h",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "user",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_FrameworkAnnotations_JAXRS(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "jaxrs_query_param_marks_param",
			FilePath: "/app/UserResource.java",
			Content: `package app;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;

public class UserResource {
    @GET
    public String find(@QueryParam("q") String q) {
        return q;
    }
}
`,
			Func: "UserResource.find",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "q",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			Name:     "jaxrs_multiple_annotations_all_tagged",
			FilePath: "/app/MultiResource.java",
			Content: `package app;

import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.HeaderParam;

public class MultiResource {
    public String h(@PathParam("id") String id,
                    @QueryParam("q") String q,
                    @HeaderParam("X-User") String user) {
        return id + q + user;
    }
}
`,
			Func: "MultiResource.h",
			WantParams: []ParamTaint{
				{Index: 0, Name: "id", Type: "String", CanonicalType: "String", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "q", Type: "String", CanonicalType: "String", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 2, Name: "user", Type: "String", CanonicalType: "String", IsSourceType: true, SourceCategory: taint.SrcUserInput},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_FrameworkAnnotations_Micronaut(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "micronaut_query_value_marks_param",
			FilePath: "/app/MicroController.java",
			Content: `package app;

import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.QueryValue;

public class MicroController {
    @Get("/u")
    String getU(@QueryValue("q") String q) {
        return q;
    }
}
`,
			Func: "MicroController.getU",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "q",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			Name:     "micronaut_body_marks_param",
			FilePath: "/app/MicroBody.java",
			Content: `package app;

import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Post;

public class MicroBody {
    @Post("/login")
    String login(@Body LoginReq body) {
        return body.toString();
    }
}
`,
			Func: "MicroBody.login",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "body",
					Type:           "LoginReq",
					CanonicalType:  "LoginReq",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_FrameworkAnnotations_Quarkus(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "quarkus_restquery_marks_param",
			FilePath: "/app/QuarkusResource.java",
			Content: `package app;

import org.jboss.resteasy.reactive.RestQuery;
import org.jboss.resteasy.reactive.RestPath;

public class QuarkusResource {
    public String getU(@RestPath String id, @RestQuery String q) {
        return id + q;
    }
}
`,
			Func: "QuarkusResource.getU",
			WantParams: []ParamTaint{
				{Index: 0, Name: "id", Type: "String", CanonicalType: "String", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "q", Type: "String", CanonicalType: "String", IsSourceType: true, SourceCategory: taint.SrcUserInput},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// Negative: a plain parameter with no framework annotation must NOT be
// tagged. Guards against a regression where the annotation walk would
// over-trigger on any modifiers block.
func TestJavaExtractor_FrameworkAnnotations_Negative(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "plain_string_param_not_source",
			FilePath: "/app/Plain.java",
			Content: `package app;

public class Plain {
    public String echo(String foo) {
        return foo;
    }
}
`,
			Func: "Plain.echo",
			WantParams: []ParamTaint{
				{Index: 0, Name: "foo", Type: "String", CanonicalType: "String"},
			},
		},
		{
			Name:     "non_handler_annotation_not_source",
			FilePath: "/app/AnnotatedButNotHandler.java",
			Content: `package app;

import javax.annotation.Nullable;

public class AnnotatedButNotHandler {
    public String h(@Nullable String foo) {
        return foo;
    }
}
`,
			Func: "AnnotatedButNotHandler.h",
			WantParams: []ParamTaint{
				{Index: 0, Name: "foo", Type: "String", CanonicalType: "String"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// PR-BBjava: framework-typed params — ServerRequest (Spring WebFlux
// functional), WebRequest (Spring MVC), JoinPoint (Spring AOP) should
// be tagged as user-input sources via the type catalog (no annotation
// needed). Mirrors the existing HttpServletRequest test above.
func TestJavaExtractor_FrameworkTypes_PRBBjava(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "spring_webflux_serverrequest_param",
			FilePath: "/app/RouterHandler.java",
			Content: `package app;

import org.springframework.web.reactive.function.server.ServerRequest;
import reactor.core.publisher.Mono;

public class RouterHandler {
    public Mono<String> handle(ServerRequest request) {
        return Mono.just("ok");
    }
}
`,
			Func: "RouterHandler.handle",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "request",
					Type:           "ServerRequest",
					CanonicalType:  "org.springframework.web.reactive.function.server.ServerRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			Name:     "spring_mvc_webrequest_param",
			FilePath: "/app/Advice.java",
			Content: `package app;

import org.springframework.web.context.request.WebRequest;

public class Advice {
    public String h(WebRequest req) {
        return req.getDescription(false);
    }
}
`,
			Func: "Advice.h",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "req",
					Type:           "WebRequest",
					CanonicalType:  "org.springframework.web.context.request.WebRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
		{
			Name:     "spring_aop_joinpoint_param",
			FilePath: "/app/Aspect.java",
			Content: `package app;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Before;

public class Aspect {
    @Before("execution(* *(..))")
    public void log(JoinPoint jp) {
    }
}
`,
			Func: "Aspect.log",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "jp",
					Type:           "JoinPoint",
					CanonicalType:  "org.aspectj.lang.JoinPoint",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// PR-CATjava (Fix 2): Spring DI parameter type allowlist.
// RedirectAttributes, Model, Authentication, Principal, BindingResult,
// SessionStatus, HttpSession are server-managed parameters that
// must NOT be auto-tagged as user-input sources even on handler methods.
// -----------------------------------------------------------------------

func TestJavaExtractor_DIAllowlist_RedirectAttributes(t *testing.T) {
	cases := []HarnessCase{
		{
			// Petclinic FP shape: @PostMapping with a tainted @RequestParam
			// and a RedirectAttributes injected by Spring. Only the
			// @RequestParam should be tagged as a source.
			Name:     "redirectattributes_param_not_source",
			FilePath: "/app/PetController.java",
			Content: `package app;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

public class PetController {
    @PostMapping("/save")
    public String save(@RequestParam String name, RedirectAttributes ra) {
        ra.addFlashAttribute("message", "Saved " + name);
        return "redirect:/";
    }
}
`,
			Func: "PetController.save",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "name",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
				{
					Index:         1,
					Name:          "ra",
					Type:          "RedirectAttributes",
					CanonicalType: "org.springframework.web.servlet.mvc.support.RedirectAttributes",
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_DIAllowlist_AuthenticationAndPrincipal(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "authentication_param_not_source",
			FilePath: "/app/AuthController.java",
			Content: `package app;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

public class AuthController {
    @GetMapping("/me")
    public String me(Authentication auth) {
        return auth.getName();
    }
}
`,
			Func: "AuthController.me",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "auth",
					Type:          "Authentication",
					CanonicalType: "org.springframework.security.core.Authentication",
				},
			},
		},
		{
			Name:     "principal_param_not_source",
			FilePath: "/app/PrincipalController.java",
			Content: `package app;

import java.security.Principal;
import org.springframework.web.bind.annotation.GetMapping;

public class PrincipalController {
    @GetMapping("/who")
    public String who(Principal principal) {
        return principal.getName();
    }
}
`,
			Func: "PrincipalController.who",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "principal",
					Type:          "Principal",
					CanonicalType: "java.security.Principal",
				},
			},
		},
		{
			Name:     "bindingresult_param_not_source",
			FilePath: "/app/FormController.java",
			Content: `package app;

import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public class FormController {
    @PostMapping("/form")
    public String submit(@RequestBody Form form, BindingResult result) {
        if (result.hasErrors()) return "error";
        return "ok";
    }
}
`,
			Func: "FormController.submit",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "form",
					Type:           "Form",
					CanonicalType:  "Form",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
				{
					Index:         1,
					Name:          "result",
					Type:          "BindingResult",
					CanonicalType: "org.springframework.validation.BindingResult",
				},
			},
		},
		{
			Name:     "model_param_not_source",
			FilePath: "/app/ViewController.java",
			Content: `package app;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

public class ViewController {
    @GetMapping("/view")
    public String view(Model model) {
        model.addAttribute("title", "Home");
        return "home";
    }
}
`,
			Func: "ViewController.view",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "model",
					Type:          "Model",
					CanonicalType: "org.springframework.ui.Model",
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// PR-CATjava (Fix 3): numeric / UUID @PathVariable / @RequestParam types
// are no longer auto-tagged. Jackson rejects malformed input before the
// handler body runs, so they cannot carry SQL / command / path payloads.
// -----------------------------------------------------------------------

func TestJavaExtractor_NumericPathVariable_NotSource(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "pathvariable_long_not_source",
			FilePath: "/app/L.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public class L {
    @GetMapping("/o/{id}")
    public String o(@PathVariable Long id) { return id.toString(); }
}
`,
			Func: "L.o",
			WantParams: []ParamTaint{
				{Index: 0, Name: "id", Type: "Long", CanonicalType: "Long"},
			},
		},
		{
			Name:     "pathvariable_uuid_not_source",
			FilePath: "/app/U.java",
			Content: `package app;

import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public class U {
    @GetMapping("/u/{id}")
    public String u(@PathVariable UUID id) { return id.toString(); }
}
`,
			Func: "U.u",
			WantParams: []ParamTaint{
				{Index: 0, Name: "id", Type: "UUID", CanonicalType: "java.util.UUID"},
			},
		},
		{
			Name:     "pathvariable_int_primitive_not_source",
			FilePath: "/app/Iprim.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public class Iprim {
    @GetMapping("/o/{id}")
    public String o(@PathVariable int id) { return Integer.toString(id); }
}
`,
			Func: "Iprim.o",
			WantParams: []ParamTaint{
				{Index: 0, Name: "id", Type: "int", CanonicalType: "int"},
			},
		},
		{
			// Sanity: a String @RequestParam is still tagged. Only
			// numeric / UUID / boolean types are suppressed by Fix 3.
			Name:     "requestparam_string_still_source",
			FilePath: "/app/Q.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class Q {
    @GetMapping("/q")
    public String q(@RequestParam String q) { return q; }
}
`,
			Func: "Q.q",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "q",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// -----------------------------------------------------------------------
// PR-CATjava-1-deferred (Fix 1): handler-annotation-gated source tagging.
//
// Internal helpers like sentry-java's `processFile(File file, Hint hint)`
// used to be auto-tagged as web handlers because their body happened to
// mention `file.getAbsolutePath()` — the substring `Path(` was in the
// `isWebHandlerFunc` allowlist. The new `javaMethodIsHandler` helper
// walks the method's (and enclosing class's) AST annotations instead, so
// only real `@GetMapping` / `@KafkaListener` / etc. methods qualify, and
// the extractor only adds the unannotated-fallback source tag on those
// real handlers. Per-param annotations (@RequestParam, @PathVariable, …)
// and framework-typed parameters (HttpServletRequest, …) keep tagging
// independently — only the catch-all auto-tag is gated.
// -----------------------------------------------------------------------

func TestJavaExtractor_HandlerWithMapping_AutoTagsParams(t *testing.T) {
	cases := []HarnessCase{
		{
			// `@GetMapping` is a recognised handler annotation, so the
			// otherwise-unmarked `String s` parameter is tagged as a
			// source by the new handler-gate path.
			Name:     "spring_getmapping_string_param",
			FilePath: "/app/H.java",
			Content: `package app;

import org.springframework.web.bind.annotation.GetMapping;

public class H {
    @GetMapping("/h")
    public String h(String s) {
        return s;
    }
}
`,
			Func: "H.h",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "s",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_HandlerWithJaxRsPath_AutoTagsParams(t *testing.T) {
	cases := []HarnessCase{
		{
			// JAX-RS class-level `@Path` is enough — every method in the
			// class is treated as a handler, so unannotated `String s` is
			// tagged.
			Name:     "jaxrs_class_path_method_param",
			FilePath: "/app/UR.java",
			Content: `package app;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/u")
public class UR {
    @GET
    public String h(String s) {
        return s;
    }
}
`,
			Func: "UR.h",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "s",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_HandlerWithKafkaListener_AutoTagsParams(t *testing.T) {
	cases := []HarnessCase{
		{
			// `@KafkaListener` is an async listener; its single
			// `ConsumerRecord` parameter carries the broker payload and
			// should be tagged. Listener annotations qualify a method as
			// a handler in the new helper.
			Name:     "kafka_listener_consumerrecord_param",
			FilePath: "/app/KL.java",
			Content: `package app;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;

public class KL {
    @KafkaListener(topics = "orders")
    public void onMessage(ConsumerRecord<String, String> record) {
        record.toString();
    }
}
`,
			Func: "KL.onMessage",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "record",
					Type:           "ConsumerRecord<String, String>",
					CanonicalType:  "org.apache.kafka.clients.consumer.ConsumerRecord<String, String>",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_NonHandlerMethod_NoAutoTag(t *testing.T) {
	cases := []HarnessCase{
		{
			// `processFile` shape from sentry-java's EnvelopeSender. No
			// handler annotation on the method (or its class), so the
			// auto-tag is suppressed. Without this gate, the legacy
			// `isWebHandlerFunc` substring match (which the prior PR
			// would have kept) would have tagged both parameters
			// because the body contains `Path(` via `getAbsolutePath()`.
			Name:     "private_helper_no_annotation_no_tag",
			FilePath: "/app/EnvelopeSender.java",
			Content: `package app;

import java.io.File;
import java.io.FileInputStream;

public class EnvelopeSender {
    protected void processFile(final File file, final Hint hint) {
        if (!file.isFile()) {
            return;
        }
        try (FileInputStream is = new FileInputStream(file.getAbsolutePath())) {
            is.read();
        } catch (Exception ignored) {
        }
    }
}
`,
			Func: "EnvelopeSender.processFile",
			WantParams: []ParamTaint{
				{Index: 0, Name: "file", Type: "File", CanonicalType: "java.io.File"},
				{Index: 1, Name: "hint", Type: "Hint", CanonicalType: "Hint"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_NonHandlerMethod_PerParamAnnotationStillTags(t *testing.T) {
	cases := []HarnessCase{
		{
			// Even on a non-handler method, an explicit @RequestParam
			// on a parameter still tags it. The handler gate only
			// controls the catch-all auto-tag for unannotated params —
			// per-param annotations are intentionally independent of
			// the enclosing method's annotation status.
			Name:     "per_param_annotation_on_non_handler",
			FilePath: "/app/U.java",
			Content: `package app;

import org.springframework.web.bind.annotation.RequestParam;

public class U {
    private void log(@RequestParam String s) {
        System.out.println(s);
    }
}
`,
			Func: "U.log",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "s",
					Type:           "String",
					CanonicalType:  "String",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_NonHandlerMethod_FrameworkTypedStillTags(t *testing.T) {
	cases := []HarnessCase{
		{
			// Even on a non-handler method, a framework-typed parameter
			// (HttpServletRequest is in `javaTypeCatalog.SourceParam`)
			// still tags. The type-catalog path is independent of the
			// handler gate — handing a request object to an arbitrary
			// helper is unusual but it really is user input.
			Name:     "framework_typed_on_non_handler",
			FilePath: "/app/U.java",
			Content: `package app;

import javax.servlet.http.HttpServletRequest;

public class U {
    private void handle(HttpServletRequest req) {
        req.getParameter("x");
    }
}
`,
			Func: "U.handle",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "req",
					Type:           "HttpServletRequest",
					CanonicalType:  "javax.servlet.http.HttpServletRequest",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

func TestJavaExtractor_PrivateHelperWithStringFile_NotSource(t *testing.T) {
	cases := []HarnessCase{
		{
			// sentry-java's EnvelopeCache.writeEnvelopeToDisk has the
			// exact shape that produced the dominant false-positive
			// class in the RESCAN-java sentry-java triage: a private
			// helper taking a `File` + a non-framework type, whose
			// body invokes `file.getAbsolutePath()` (substring `Path(`)
			// and `new FileOutputStream(...)`. With the handler-gate,
			// neither parameter is tagged.
			Name:     "private_writeenvelope_helper",
			FilePath: "/app/EnvelopeCache.java",
			Content: `package app;

import java.io.File;
import java.io.FileOutputStream;

public class EnvelopeCache {
    private boolean writeEnvelopeToDisk(final File file, final SentryEnvelope envelope) {
        if (file.exists()) {
            file.delete();
        }
        try (FileOutputStream out = new FileOutputStream(file.getAbsolutePath())) {
            out.write(envelope.toString().getBytes());
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
`,
			Func: "EnvelopeCache.writeEnvelopeToDisk",
			WantParams: []ParamTaint{
				{Index: 0, Name: "file", Type: "File", CanonicalType: "java.io.File"},
				{Index: 1, Name: "envelope", Type: "SentryEnvelope", CanonicalType: "SentryEnvelope"},
			},
		},
	}
	RunHarness(t, rules.LangJava, cases)
}

// TestJavaExtractor_RegisteredInRegistry confirms the init() registration
// fires and the extractor is reachable via GetExtractor.
func TestJavaExtractor_RegisteredInRegistry(t *testing.T) {
	if !IsExtractorSupported(rules.LangJava) {
		t.Fatal("Java extractor not registered")
	}
	ex := GetExtractor(rules.LangJava)
	if ex == nil {
		t.Fatal("GetExtractor returned nil for Java")
	}
	if ex.Language() != rules.LangJava {
		t.Errorf("Language() = %q, want Java", ex.Language())
	}
}
