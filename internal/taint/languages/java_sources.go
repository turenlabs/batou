package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (javaCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// Servlet request sources
		{ID: "java.servlet.getparameter", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getParameter\s*\(`, ObjectType: "HttpServletRequest", MethodName: "getParameter", Description: "HTTP request parameter", Assigns: "return"},
		{ID: "java.servlet.getheader", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getHeader\s*\(`, ObjectType: "HttpServletRequest", MethodName: "getHeader", Description: "HTTP request header", Assigns: "return"},
		{ID: "java.servlet.getcookies", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getCookies\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getCookies", Description: "HTTP request cookies", Assigns: "return"},
		{ID: "java.servlet.getinputstream", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getInputStream\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getInputStream", Description: "HTTP request input stream", Assigns: "return"},
		{ID: "java.servlet.getreader", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getReader\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getReader", Description: "HTTP request reader", Assigns: "return"},
		{ID: "java.servlet.getpathinfo", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getPathInfo\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getPathInfo", Description: "HTTP request path info", Assigns: "return"},
		{ID: "java.servlet.getquerystring", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getQueryString\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getQueryString", Description: "HTTP request query string", Assigns: "return"},
		{ID: "java.servlet.getrequesturi", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getRequestURI\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getRequestURI", Description: "HTTP request URI", Assigns: "return"},

		// Spring annotations
		{ID: "java.spring.requestparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestParam`, ObjectType: "Spring", MethodName: "@RequestParam", Description: "Spring request parameter annotation", Assigns: "return"},
		{ID: "java.spring.pathvariable", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@PathVariable`, ObjectType: "Spring", MethodName: "@PathVariable", Description: "Spring path variable annotation", Assigns: "return"},
		{ID: "java.spring.requestbody", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestBody`, ObjectType: "Spring", MethodName: "@RequestBody", Description: "Spring request body annotation", Assigns: "return"},

		// Environment/CLI
		{ID: "java.system.getenv", Category: taint.SrcEnvVar, Language: rules.LangJava, Pattern: `System\.getenv\s*\(`, ObjectType: "System", MethodName: "getenv", Description: "System environment variable", Assigns: "return"},
		{ID: "java.main.args", Category: taint.SrcCLIArg, Language: rules.LangJava, Pattern: `\bargs\s*\[`, ObjectType: "", MethodName: "args", Description: "Main method arguments", Assigns: "return"},
		{ID: "java.scanner.stdin", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `new\s+Scanner\s*\(\s*System\.in\s*\)`, ObjectType: "Scanner", MethodName: "Scanner", Description: "Scanner reading from stdin", Assigns: "return"},

		// Database
		{ID: "java.resultset.getstring", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:ResultSet|rs)\.getString\s*\(`, ObjectType: "ResultSet", MethodName: "getString", Description: "Database result set value", Assigns: "return"},

		// IO
		{ID: "java.bufferedreader.readline", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `(?:BufferedReader|reader|br)\.readLine\s*\(`, ObjectType: "BufferedReader", MethodName: "readLine", Description: "BufferedReader input (network/file)", Assigns: "return"},

		// Spring MVC additional annotations
		{ID: "java.spring.requestheader", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestHeader`, ObjectType: "Spring", MethodName: "@RequestHeader", Description: "Spring request header annotation", Assigns: "return"},
		{ID: "java.spring.cookievalue", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@CookieValue`, ObjectType: "Spring", MethodName: "@CookieValue", Description: "Spring cookie value annotation", Assigns: "return"},
		{ID: "java.spring.matrixvariable", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@MatrixVariable`, ObjectType: "Spring", MethodName: "@MatrixVariable", Description: "Spring matrix variable annotation", Assigns: "return"},

		// Spring Security
		{ID: "java.spring.securitycontext.getauthentication", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `SecurityContextHolder\.getContext\s*\(\s*\)\s*\.getAuthentication\s*\(`, ObjectType: "SecurityContext", MethodName: "getAuthentication", Description: "Spring Security authentication context (potentially spoofable)", Assigns: "return"},

		// Struts ActionForm
		{ID: "java.struts.actionform", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:ActionForm|form)\.get\w+\s*\(`, ObjectType: "ActionForm", MethodName: "get*", Description: "Struts ActionForm getter (user-controlled form data)", Assigns: "return"},

		// MyBatis SqlSession results
		{ID: "java.mybatis.sqlsession.selectone", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:SqlSession|sqlSession|session)\.selectOne\s*\(`, ObjectType: "SqlSession", MethodName: "selectOne", Description: "MyBatis SqlSession.selectOne result", Assigns: "return"},
		{ID: "java.mybatis.sqlsession.selectlist", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:SqlSession|sqlSession|session)\.selectList\s*\(`, ObjectType: "SqlSession", MethodName: "selectList", Description: "MyBatis SqlSession.selectList result", Assigns: "return"},

		// Apache Commons IO
		{ID: "java.commons.ioutils.tostring", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `IOUtils\.toString\s*\(`, ObjectType: "IOUtils", MethodName: "toString", Description: "Apache Commons IOUtils.toString (reads from input stream)", Assigns: "return"},
		{ID: "java.commons.fileutils.readfiletostring", Category: taint.SrcFileRead, Language: rules.LangJava, Pattern: `FileUtils\.readFileToString\s*\(`, ObjectType: "FileUtils", MethodName: "readFileToString", Description: "Apache Commons FileUtils.readFileToString", Assigns: "return"},

		// Deserialized data
		{ID: "java.jackson.readvalue", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:ObjectMapper|objectMapper|mapper)\.readValue\s*\(`, ObjectType: "ObjectMapper", MethodName: "readValue", Description: "Jackson deserialized JSON data", Assigns: "return"},

		// AWS Lambda event source
		{ID: "java.aws.lambda.event", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `implements\s+RequestHandler`, ObjectType: "com.amazonaws.services.lambda", MethodName: "handleRequest", Description: "AWS Lambda handler event data from external trigger", Assigns: "return"},
		// AWS SQS message source
		{ID: "java.aws.sqs.receive", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.receiveMessage\s*\(`, ObjectType: "SqsClient", MethodName: "receiveMessage", Description: "AWS SQS message data from queue", Assigns: "return"},
		// AWS S3 object source
		{ID: "java.aws.s3.getobject", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.getObject\s*\(`, ObjectType: "S3Client", MethodName: "getObject", Description: "AWS S3 object data from potentially untrusted bucket", Assigns: "return"},
		// GCP Cloud Functions event source
		{ID: "java.gcp.cloudfunctions.event", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `implements\s+(?:HttpFunction|BackgroundFunction|CloudEventsFunction)`, ObjectType: "com.google.cloud.functions", MethodName: "service", Description: "GCP Cloud Functions event data from external trigger", Assigns: "return"},
		// GCP Pub/Sub pull
		{ID: "java.gcp.pubsub.pull", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `subscriber\.pull\s*\(|\.pullMessages\s*\(`, ObjectType: "SubscriptionAdminClient", MethodName: "pull", Description: "GCP Pub/Sub message data", Assigns: "return"},

		// JAX-RS annotations
		{ID: "java.jaxrs.queryparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@QueryParam`, ObjectType: "JAX-RS", MethodName: "@QueryParam", Description: "JAX-RS query parameter annotation", Assigns: "return"},
		{ID: "java.jaxrs.pathparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@PathParam`, ObjectType: "JAX-RS", MethodName: "@PathParam", Description: "JAX-RS path parameter annotation", Assigns: "return"},
		{ID: "java.jaxrs.formparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@FormParam`, ObjectType: "JAX-RS", MethodName: "@FormParam", Description: "JAX-RS form parameter annotation", Assigns: "return"},
		{ID: "java.jaxrs.headerparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@HeaderParam`, ObjectType: "JAX-RS", MethodName: "@HeaderParam", Description: "JAX-RS header parameter annotation", Assigns: "return"},

		// Spring WebFlux
		{ID: "java.spring.webflux.serverrequest", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `ServerRequest.*\.queryParam\s*\(|ServerRequest.*\.bodyToMono\s*\(`, ObjectType: "ServerRequest", MethodName: "queryParam/bodyToMono", Description: "Spring WebFlux reactive request input", Assigns: "return"},

		// JAXB deserialization
		{ID: "java.jaxb.unmarshal", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:Unmarshaller|unmarshaller)\.unmarshal\s*\(`, ObjectType: "Unmarshaller", MethodName: "unmarshal", Description: "JAXB XML deserialized data", Assigns: "return"},

		// Servlet additional parameter sources
		{ID: "java.servlet.getparametervalues", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getParameterValues\s*\(`, ObjectType: "HttpServletRequest", MethodName: "getParameterValues", Description: "HTTP request parameter values array", Assigns: "return"},
		{ID: "java.servlet.getparametermap", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getParameterMap\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getParameterMap", Description: "HTTP request all parameters map", Assigns: "return"},

		// Servlet additional sources
		{ID: "java.servlet.getservletpath", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getServletPath\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getServletPath", Description: "HTTP request servlet path", Assigns: "return"},
		{ID: "java.servlet.getrequesturl", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getRequestURL\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getRequestURL", Description: "HTTP full request URL", Assigns: "return"},
		{ID: "java.servlet.getremoteaddr", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getRemoteAddr\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getRemoteAddr", Description: "Client IP address (spoofable via proxy headers)", Assigns: "return"},

		// NIO file read
		{ID: "java.nio.files.readallbytes", Category: taint.SrcFileRead, Language: rules.LangJava, Pattern: `Files\.readAllBytes\s*\(|Files\.readString\s*\(|Files\.readAllLines\s*\(`, ObjectType: "Files", MethodName: "readAllBytes/readString", Description: "NIO Files read methods", Assigns: "return"},

		// Spring multipart
		{ID: "java.spring.multipart", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestPart|MultipartFile`, ObjectType: "Spring", MethodName: "@RequestPart/MultipartFile", Description: "Spring multipart file upload data", Assigns: "return"},
	}
}
