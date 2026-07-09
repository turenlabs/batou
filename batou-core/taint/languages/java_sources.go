package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
		// AWS S3 v2 high-level object reads + v1 stream read (bucket contents may be attacker-controlled: uploads, public buckets)
		{ID: "java.aws.s3.client.getobjectasbytes", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\b(?:s3|s3Client)\.getObjectAsBytes\s*\(`, ObjectType: "S3Client", MethodName: "getObjectAsBytes", Description: "AWS S3 v2 getObjectAsBytes() — object body bytes from a potentially untrusted bucket (second-order injection)", Assigns: "return"},
		{ID: "java.aws.s3.s3object.objectcontent", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\bs3Object\.getObjectContent\s*\(`, ObjectType: "S3Object", MethodName: "getObjectContent", Description: "AWS S3 v1 S3Object.getObjectContent() — InputStream of object body from a potentially untrusted bucket (second-order injection)", Assigns: "return"},
		// AWS SQS per-message body read (v2 Message.body() — payload from external producers)
		{ID: "java.aws.sqs.message.body", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\bmessage\.body\s*\(\s*\)`, ObjectType: "Message", MethodName: "body", Description: "AWS SQS v2 Message.body() — queue message payload from external producers (second-order injection)", Assigns: "return"},
		// AWS Kinesis stream record payload (v2 Record.data() — bytes from external producers)
		{ID: "java.aws.kinesis.record.data", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\brecord\.data\s*\(\s*\)`, ObjectType: "Record", MethodName: "data", Description: "AWS Kinesis Record.data() — stream record payload from external producers (second-order injection)", Assigns: "return"},
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
		{ID: "java.servlet.getheadernames", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getHeaderNames\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getHeaderNames", Description: "HTTP request header names enumeration", Assigns: "return"},
		{ID: "java.servlet.getheaders", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getHeaders\s*\(`, ObjectType: "HttpServletRequest", MethodName: "getHeaders", Description: "HTTP request headers for a given name", Assigns: "return"},
		{ID: "java.servlet.getparameternames", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getParameterNames\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getParameterNames", Description: "HTTP request parameter names enumeration", Assigns: "return"},
		{ID: "java.servlet.getservletpath", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getServletPath\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getServletPath", Description: "HTTP request servlet path", Assigns: "return"},
		{ID: "java.servlet.getrequesturl", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getRequestURL\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getRequestURL", Description: "HTTP full request URL", Assigns: "return"},
		{ID: "java.servlet.getremoteaddr", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getRemoteAddr\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getRemoteAddr", Description: "Client IP address (spoofable via proxy headers)", Assigns: "return"},

		// NIO file read
		{ID: "java.nio.files.readallbytes", Category: taint.SrcFileRead, Language: rules.LangJava, Pattern: `Files\.readAllBytes\s*\(|Files\.readString\s*\(|Files\.readAllLines\s*\(`, ObjectType: "Files", MethodName: "readAllBytes/readString", Description: "NIO Files read methods", Assigns: "return"},

		// Spring multipart
		{ID: "java.spring.multipart", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestPart|MultipartFile`, ObjectType: "Spring", MethodName: "@RequestPart/MultipartFile", Description: "Spring multipart file upload data", Assigns: "return"},

		// Enumeration iteration (user input from getHeaders/getParameterNames)
		{ID: "java.enumeration.nextelement", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.nextElement\s*\(`, ObjectType: "Enumeration", MethodName: "nextElement", Description: "Enumeration.nextElement() iterating over request headers/parameters", Assigns: "return"},

		// Servlet 3.0 multipart file upload
		{ID: "java.servlet.getpart", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getPart\s*\(`, ObjectType: "HttpServletRequest", MethodName: "getPart", Description: "Servlet 3.0 file upload part (user-controlled filename and content)", Assigns: "return"},
		{ID: "java.servlet.getparts", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `request\.getParts\s*\(\s*\)`, ObjectType: "HttpServletRequest", MethodName: "getParts", Description: "Servlet 3.0 all uploaded parts collection", Assigns: "return"},

		// System properties (attacker-controlled via -D flags or JNDI)
		{ID: "java.system.getproperty", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `System\.getProperty\s*\(`, ObjectType: "System", MethodName: "getProperty", Description: "System property (controllable via -D JVM flags or JNDI)", Assigns: "return"},

		// ResultSet additional getters (second-order injection from DB)
		{ID: "java.resultset.getobject", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:ResultSet|rs)\.getObject\s*\(`, ObjectType: "ResultSet", MethodName: "getObject", Description: "Database result set object value (second-order injection)", Assigns: "return"},
		{ID: "java.resultset.getbytes", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:ResultSet|rs)\.getBytes\s*\(`, ObjectType: "ResultSet", MethodName: "getBytes", Description: "Database result set byte data (second-order injection)", Assigns: "return"},

		// Scanner stdin read methods
		{ID: "java.scanner.nextline", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:Scanner|scanner)\.nextLine\s*\(\s*\)`, ObjectType: "Scanner", MethodName: "nextLine", Description: "Scanner.nextLine() reading user input", Assigns: "return"},
		{ID: "java.scanner.next", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:Scanner|scanner)\.next\s*\(\s*\)`, ObjectType: "Scanner", MethodName: "next", Description: "Scanner.next() reading user input token", Assigns: "return"},

		// Properties from external config files
		{ID: "java.properties.getproperty", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Properties|props|properties|config)\.getProperty\s*\(`, ObjectType: "Properties", MethodName: "getProperty", Description: "Properties.getProperty() from potentially untrusted config", Assigns: "return"},

		// --- JMS (javax.jms / jakarta.jms) messaging sources ---
		{ID: "java.jms.textmessage.gettext", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:TextMessage|textMessage|textMsg)\.getText\s*\(\s*\)`, ObjectType: "TextMessage", MethodName: "getText", Description: "JMS TextMessage.getText() — message payload from queue", Assigns: "return"},
		{ID: "java.jms.objectmessage.getobject", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:ObjectMessage|objectMessage|objectMsg)\.getObject\s*\(\s*\)`, ObjectType: "ObjectMessage", MethodName: "getObject", Description: "JMS ObjectMessage.getObject() — deserialized object from queue (CWE-502 risk)", Assigns: "return"},
		{ID: "java.jms.mapmessage.getstring", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:MapMessage|mapMessage|mapMsg)\.getString\s*\(`, ObjectType: "MapMessage", MethodName: "getString", Description: "JMS MapMessage.getString() — named value from map message", Assigns: "return"},
		{ID: "java.jms.bytesmessage.readutf", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:BytesMessage|bytesMessage)\.readUTF\s*\(\s*\)`, ObjectType: "BytesMessage", MethodName: "readUTF", Description: "JMS BytesMessage.readUTF() — text from binary message", Assigns: "return"},
		{ID: "java.jms.message.getstringproperty", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.getStringProperty\s*\(`, ObjectType: "Message", MethodName: "getStringProperty", Description: "JMS Message.getStringProperty() — message header/property from queue", Assigns: "return"},
		{ID: "java.jms.message.getbody", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message|msg)\.getBody\s*\(`, ObjectType: "Message", MethodName: "getBody", Description: "JMS 2.0 Message.getBody() — typed message payload", Assigns: "return"},

		// --- Apache Kafka consumer sources ---
		{ID: "java.kafka.consumerrecord.value", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:ConsumerRecord|consumerRecord|record)\.value\s*\(\s*\)`, ObjectType: "ConsumerRecord", MethodName: "value", Description: "Kafka ConsumerRecord.value() — message payload from topic", Assigns: "return"},
		{ID: "java.kafka.consumerrecord.key", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:ConsumerRecord|consumerRecord|record)\.key\s*\(\s*\)`, ObjectType: "ConsumerRecord", MethodName: "key", Description: "Kafka ConsumerRecord.key() — message key from topic", Assigns: "return"},

		// --- RabbitMQ (AMQP) consumer sources ---
		{ID: "java.rabbitmq.delivery.getbody", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Delivery|delivery)\.getBody\s*\(\s*\)`, ObjectType: "Delivery", MethodName: "getBody", Description: "RabbitMQ Delivery.getBody() — message body bytes from queue", Assigns: "return"},

		// --- Apache Pulsar consumer sources (org.apache.pulsar.client.api.Message) ---
		// Pulsar message contents are attacker-controlled — multi-tenant clusters, IoT
		// device pipelines, and cross-team topics all carry untrusted payloads from
		// upstream producers. Mirrors Kafka ConsumerRecord / RabbitMQ Delivery coverage.
		{ID: "java.pulsar.message.getvalue", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message|msg)\.getValue\s*\(\s*\)`, ObjectType: "Message", MethodName: "getValue", Description: "Apache Pulsar Message.getValue() — deserialized typed payload from topic", Assigns: "return"},
		{ID: "java.pulsar.message.getdata", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message|msg)\.getData\s*\(\s*\)`, ObjectType: "Message", MethodName: "getData", Description: "Apache Pulsar Message.getData() — raw byte payload from topic", Assigns: "return"},
		{ID: "java.pulsar.message.getkey", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message|msg)\.getKey\s*\(\s*\)`, ObjectType: "Message", MethodName: "getKey", Description: "Apache Pulsar Message.getKey() — producer-supplied message key", Assigns: "return"},
		{ID: "java.pulsar.message.getproperty", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message|msg)\.getProperty\s*\(`, ObjectType: "Message", MethodName: "getProperty", Description: "Apache Pulsar Message.getProperty(name) — single producer-supplied property", Assigns: "return"},
		{ID: "java.pulsar.message.getproperties", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message|msg)\.getProperties\s*\(\s*\)`, ObjectType: "Message", MethodName: "getProperties", Description: "Apache Pulsar Message.getProperties() — full producer-supplied properties map", Assigns: "return"},

		// --- Spring messaging listener annotations ---
		{ID: "java.spring.kafkalistener", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `@KafkaListener`, ObjectType: "Spring", MethodName: "@KafkaListener", Description: "Spring Kafka listener — method receives untrusted message data", Assigns: "return"},
		{ID: "java.spring.jmslistener", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `@JmsListener`, ObjectType: "Spring", MethodName: "@JmsListener", Description: "Spring JMS listener — method receives untrusted message data", Assigns: "return"},
		{ID: "java.spring.rabbitlistener", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `@RabbitListener`, ObjectType: "Spring", MethodName: "@RabbitListener", Description: "Spring RabbitMQ listener — method receives untrusted message data", Assigns: "return"},
		{ID: "java.spring.pulsarlistener", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `@PulsarListener`, ObjectType: "Spring", MethodName: "@PulsarListener", Description: "Spring for Apache Pulsar listener — method receives untrusted message data", Assigns: "return"},

		// --- Additional JAX-RS annotations ---
		{ID: "java.jaxrs.cookieparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@CookieParam`, ObjectType: "JAX-RS", MethodName: "@CookieParam", Description: "JAX-RS cookie parameter annotation", Assigns: "return"},
		{ID: "java.jaxrs.beanparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@BeanParam`, ObjectType: "JAX-RS", MethodName: "@BeanParam", Description: "JAX-RS composite bean parameter annotation (aggregates query/form/header params)", Assigns: "return"},

		// --- Vert.x Web framework sources ---
		{ID: "java.vertx.routingcontext.pathparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.pathParam\s*\(`, ObjectType: "RoutingContext", MethodName: "pathParam", Description: "Vert.x RoutingContext path parameter", Assigns: "return"},
		{ID: "java.vertx.routingcontext.queryparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.queryParam\s*\(`, ObjectType: "RoutingContext", MethodName: "queryParam", Description: "Vert.x RoutingContext query parameter", Assigns: "return"},
		{ID: "java.vertx.request.getparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.request\s*\(\s*\)\s*\.getParam\s*\(`, ObjectType: "HttpServerRequest", MethodName: "getParam", Description: "Vert.x HttpServerRequest parameter", Assigns: "return"},
		{ID: "java.vertx.request.getheader", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.request\s*\(\s*\)\s*\.getHeader\s*\(`, ObjectType: "HttpServerRequest", MethodName: "getHeader", Description: "Vert.x HttpServerRequest header value", Assigns: "return"},
		{ID: "java.vertx.request.getformattribute", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.request\s*\(\s*\)\s*\.getFormAttribute\s*\(`, ObjectType: "HttpServerRequest", MethodName: "getFormAttribute", Description: "Vert.x HttpServerRequest form field", Assigns: "return"},
		{ID: "java.vertx.body.asstring", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.body\s*\(\s*\)\s*\.asString\s*\(`, ObjectType: "RequestBody", MethodName: "asString", Description: "Vert.x request body as string", Assigns: "return"},
		{ID: "java.vertx.body.asjsonobject", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.body\s*\(\s*\)\s*\.asJsonObject\s*\(`, ObjectType: "RequestBody", MethodName: "asJsonObject", Description: "Vert.x request body as JSON object", Assigns: "return"},
		{ID: "java.vertx.fileuploads", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.fileUploads\s*\(\s*\)`, ObjectType: "RoutingContext", MethodName: "fileUploads", Description: "Vert.x file uploads from multipart request", Assigns: "return"},

		// --- Javalin web framework sources (io.javalin.http.Context, conventionally `ctx`) ---
		// Javalin (https://javalin.io) is a popular lightweight JVM web framework.
		// The single Context object (`ctx`) is the entry point for all request
		// input. ObjectType "Context" binds the `ctx`/`context` receiver via the
		// matchesCatalogEntry "context" alias and the abbreviation heuristic.
		{ID: "java.javalin.queryparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.queryParam\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "queryParam", Description: "Javalin Context.queryParam() — user-controlled query string parameter", Assigns: "return"},
		{ID: "java.javalin.pathparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.pathParam\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "pathParam", Description: "Javalin Context.pathParam() — user-controlled URL path parameter", Assigns: "return"},
		{ID: "java.javalin.formparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.formParam\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "formParam", Description: "Javalin Context.formParam() — user-controlled form field", Assigns: "return"},
		{ID: "java.javalin.header", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.header\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "header", Description: "Javalin Context.header(name) — user-controlled request header", Assigns: "return"},
		{ID: "java.javalin.cookie", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.cookie\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "cookie", Description: "Javalin Context.cookie(name) — user-controlled request cookie", Assigns: "return"},
		{ID: "java.javalin.body", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.body\s*\(\s*\)`, ObjectType: "io.javalin.http.Context", MethodName: "body", Description: "Javalin Context.body() — raw user-controlled request body", Assigns: "return"},
		{ID: "java.javalin.bodyasclass", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.bodyAsClass\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "bodyAsClass", Description: "Javalin Context.bodyAsClass() — deserialized user-controlled request body", Assigns: "return"},
		{ID: "java.javalin.bodyasbytes", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.bodyAsBytes\s*\(\s*\)`, ObjectType: "io.javalin.http.Context", MethodName: "bodyAsBytes", Description: "Javalin Context.bodyAsBytes() — raw user-controlled request body bytes", Assigns: "return"},
		{ID: "java.javalin.querystring", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.queryString\s*\(\s*\)`, ObjectType: "io.javalin.http.Context", MethodName: "queryString", Description: "Javalin Context.queryString() — raw user-controlled query string", Assigns: "return"},

		// --- HTTP client response sources (SrcNetwork) ---

		// Java 11+ HttpClient — response body from remote server
		{ID: "java.httpclient.send", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `(?:HttpClient|httpClient)\.send(?:Async)?\s*\(`, ObjectType: "HttpClient", MethodName: "send", Description: "Java 11+ HttpClient.send() — response from remote server (SSRF chain vector)", Assigns: "return"},

		// Apache HttpClient 4.x/5.x — execute returns response with potentially attacker-controlled body
		{ID: "java.apache.httpclient.execute", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `(?:CloseableHttpClient|HttpClient|httpclient|httpClient)\.execute\s*\(`, ObjectType: "CloseableHttpClient", MethodName: "execute", Description: "Apache HttpClient.execute() — response from remote server", Assigns: "return"},

		// Apache HttpClient response body extraction
		{ID: "java.apache.entityutils.tostring", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `EntityUtils\.toString\s*\(`, ObjectType: "EntityUtils", MethodName: "toString", Description: "Apache HttpClient EntityUtils.toString() — response body as string", Assigns: "return"},

		// OkHttp3 — newCall initiates HTTP request; taint propagates through .execute().body().string()
		{ID: "java.okhttp.newcall", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `\.newCall\s*\(`, ObjectType: "", MethodName: "newCall", Description: "OkHttp Client.newCall() — initiates HTTP request to remote server", Assigns: "return"},

		// Spring RestTemplate — HTTP client responses from remote services
		{ID: "java.spring.resttemplate.get", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `(?:RestTemplate|restTemplate)\.(?:getForObject|getForEntity)\s*\(`, ObjectType: "RestTemplate", MethodName: "getForObject/getForEntity", Description: "Spring RestTemplate GET — response data from remote service", Assigns: "return"},
		{ID: "java.spring.resttemplate.exchange", Category: taint.SrcNetwork, Language: rules.LangJava, Pattern: `(?:RestTemplate|restTemplate)\.(?:exchange|postForObject|postForEntity)\s*\(`, ObjectType: "RestTemplate", MethodName: "exchange/postFor*", Description: "Spring RestTemplate exchange/POST — response data from remote service", Assigns: "return"},

		// --- Database/ORM query result sources (SrcDatabase) ---

		// Spring JdbcTemplate — query results from database
		{ID: "java.spring.jdbctemplate.queryforobject", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:JdbcTemplate|jdbcTemplate)\.queryForObject\s*\(`, ObjectType: "JdbcTemplate", MethodName: "queryForObject", Description: "Spring JdbcTemplate.queryForObject() — single value from DB (second-order injection)", Assigns: "return"},
		{ID: "java.spring.jdbctemplate.queryforlist", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:JdbcTemplate|jdbcTemplate)\.queryForList\s*\(`, ObjectType: "JdbcTemplate", MethodName: "queryForList", Description: "Spring JdbcTemplate.queryForList() — result list from DB (second-order injection)", Assigns: "return"},
		{ID: "java.spring.jdbctemplate.query", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:JdbcTemplate|jdbcTemplate)\.query\s*\(`, ObjectType: "JdbcTemplate", MethodName: "query", Description: "Spring JdbcTemplate.query() — query results from DB", Assigns: "return"},

		// JPA EntityManager — entity/query results from database
		{ID: "java.jpa.entitymanager.find", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:EntityManager|em|entityManager)\.find\s*\(`, ObjectType: "EntityManager", MethodName: "find", Description: "JPA EntityManager.find() — entity loaded from DB (second-order injection)", Assigns: "return"},
		{ID: "java.jpa.entitymanager.createquery", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:EntityManager|em|entityManager)\.create(?:Query|NativeQuery)\s*\(`, ObjectType: "EntityManager", MethodName: "createQuery/createNativeQuery", Description: "JPA EntityManager query creation — results from DB", Assigns: "return"},

		// --- Quarkus RESTEasy Reactive annotations ---
		{ID: "java.quarkus.rest.annotation", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestQuery|@RestPath|@RestHeader|@RestCookie|@RestForm|@RestMatrix`, ObjectType: "Quarkus", MethodName: "@RestQuery/@RestPath/@RestHeader/@RestCookie/@RestForm/@RestMatrix", Description: "Quarkus RESTEasy Reactive parameter binding annotations", Assigns: "return"},

		// --- Micronaut HTTP annotations ---
		{ID: "java.micronaut.queryvalue", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@QueryValue`, ObjectType: "Micronaut", MethodName: "@QueryValue", Description: "Micronaut @QueryValue query parameter binding", Assigns: "return"},

		// --- Missing Servlet cookie/multipart patterns ---
		{ID: "java.cookie.getvalue", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:Cookie|cookie)\.getValue\s*\(\s*\)`, ObjectType: "Cookie", MethodName: "getValue", Description: "javax.servlet.http.Cookie value (user-controlled cookie data)", Assigns: "return"},
		{ID: "java.servlet.part.getinputstream", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:Part|part|filePart)\.getInputStream\s*\(\s*\)`, ObjectType: "Part", MethodName: "getInputStream", Description: "Servlet 3.0 Part.getInputStream() — uploaded file content stream", Assigns: "return"},
		{ID: "java.servlet.part.getsubmittedfilename", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:Part|part|filePart)\.getSubmittedFileName\s*\(\s*\)`, ObjectType: "Part", MethodName: "getSubmittedFileName", Description: "Servlet 3.0 Part.getSubmittedFileName() — user-controlled upload filename", Assigns: "return"},

		// --- JNDI lookup result (SrcExternal — object from directory service) ---
		{ID: "java.jndi.lookup.result", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:InitialContext|DirContext|ctx)\.lookup\s*\(`, ObjectType: "InitialContext", MethodName: "lookup", Description: "JNDI lookup result — object from potentially attacker-controlled directory (Log4Shell vector)", Assigns: "return"},

		// --- Spring WebFlux additional request sources ---
		{ID: "java.spring.webflux.pathvariable", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `ServerRequest.*\.pathVariable\s*\(`, ObjectType: "ServerRequest", MethodName: "pathVariable", Description: "Spring WebFlux ServerRequest.pathVariable() — URL path segment", Assigns: "return"},
		{ID: "java.spring.webflux.bodytoflux", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `ServerRequest.*\.bodyToFlux\s*\(`, ObjectType: "ServerRequest", MethodName: "bodyToFlux", Description: "Spring WebFlux ServerRequest.bodyToFlux() — reactive request body stream", Assigns: "return"},

		// --- Deserialization library sources ---
		{ID: "java.gson.fromjson", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:Gson|gson)\.fromJson\s*\(`, ObjectType: "Gson", MethodName: "fromJson", Description: "Gson JSON deserialization — untrusted data yields arbitrary typed objects", Assigns: "return"},
		{ID: "java.snakeyaml.deserialized", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:Yaml|yaml)\.load\s*\(`, ObjectType: "Yaml", MethodName: "load", Description: "SnakeYAML deserialized data — untrusted YAML yields arbitrary objects (CVE-2022-1471)", Assigns: "return"},

		// --- Archive entry sources (Zip Slip / Tar Slip, CWE-22) ---
		// The returned entry carries an attacker-controlled name from the archive header.
		// Calling entry.getName() on a tainted entry propagates the taint via
		// receiver-taint propagation in the tsflow walker, so the tainted
		// filename flows into File/FileOutputStream/Files.write sinks.
		// References: Snyk "Zip Slip" (2018), CVE-2018-1000544, CVE-2018-11771.
		{ID: "java.zip.zipinputstream.getnextentry", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.getNextEntry\s*\(\s*\)`, ObjectType: "", MethodName: "getNextEntry", Description: "ZipInputStream.getNextEntry() / ArchiveInputStream.getNextEntry() — returns entry whose name is attacker-controlled (Zip Slip source)", Assigns: "return"},
		{ID: "java.jar.jarinputstream.getnextjarentry", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.getNextJarEntry\s*\(\s*\)`, ObjectType: "", MethodName: "getNextJarEntry", Description: "JarInputStream.getNextJarEntry() — JAR entry with attacker-controlled name (Zip Slip source)", Assigns: "return"},
		{ID: "java.compress.ziparchiveinputstream.getnextzipentry", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.getNextZipEntry\s*\(\s*\)`, ObjectType: "", MethodName: "getNextZipEntry", Description: "ZipArchiveInputStream.getNextZipEntry() (Apache Commons Compress) — entry with attacker-controlled name (Zip Slip source)", Assigns: "return"},
		{ID: "java.compress.tararchiveinputstream.getnexttarentry", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `\.getNextTarEntry\s*\(\s*\)`, ObjectType: "", MethodName: "getNextTarEntry", Description: "TarArchiveInputStream.getNextTarEntry() (Apache Commons Compress) — entry with attacker-controlled name (Tar Slip source)", Assigns: "return"},
		// COVERAGE ADD (cov/java): ZipEntry/ArchiveEntry.getName() as a Zip-Slip
		// SOURCE (CWE-22). The dominant extraction idiom enumerates entries
		// (`for (ZipEntry e : Collections.list(zipFile.entries()))`) where the
		// entry is NOT obtained via getNextEntry(), so its name is not yet
		// tainted. Reading `e.getName()` returns the attacker-controlled archive
		// path; wired here it flows into the existing File/FileOutputStream/
		// Files.copy FileWrite sinks — no new sink needed. ObjectType is
		// FQN-anchored to the archive-entry types (receiver `entry`/`e`/`ze`/
		// `zipEntry`) so it never fires on the many unrelated `.getName()`
		// callers (Class, Field, Thread, File). Note: `.getName()` here OVERRIDES
		// the bare-name nothing — it is a member call on a typed entry. The
		// existing servlet/upload `.getName()` sources use the same FQN-anchoring
		// discipline (Part/Cookie/MultipartFile).
		{ID: "java.zip.zipentry.getname", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:entry|zipEntry|ze|e)\.getName\s*\(\s*\)`, ObjectType: "java.util.zip.ZipEntry", MethodName: "getName", Description: "java.util.zip.ZipEntry.getName() — attacker-controlled archive entry path (Zip Slip source, CWE-22)", Assigns: "return"},
		{ID: "java.compress.archiveentry.getname", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:entry|archiveEntry|ae|e)\.getName\s*\(\s*\)`, ObjectType: "org.apache.commons.compress.archivers.ArchiveEntry", MethodName: "getName", Description: "org.apache.commons.compress.archivers.ArchiveEntry.getName() — attacker-controlled archive entry path (Zip/Tar Slip source, CWE-22)", Assigns: "return"},

		// --- GraphQL sources (graphql-java DataFetchingEnvironment, Netflix DGS, Spring Boot GraphQL) ---
		// The DataFetchingEnvironment (typically bound to `env`, `dfe`, or `environment`
		// in Java resolvers) exposes caller-controlled GraphQL request data — query
		// arguments, operation variables, and the parent resolver value. All three are
		// attacker-reachable when the schema is publicly served.
		{ID: "java.graphql.dfe.getargument", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.getArgument\s*[<(]`, ObjectType: "DataFetchingEnvironment", MethodName: "getArgument", Description: "GraphQL DataFetchingEnvironment.getArgument — resolver argument from query", Assigns: "return"},
		{ID: "java.graphql.dfe.getarguments", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.getArguments\s*\(\s*\)`, ObjectType: "DataFetchingEnvironment", MethodName: "getArguments", Description: "GraphQL DataFetchingEnvironment.getArguments — full argument map from query", Assigns: "return"},
		{ID: "java.graphql.dfe.getvariables", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.getVariables\s*\(\s*\)`, ObjectType: "DataFetchingEnvironment", MethodName: "getVariables", Description: "GraphQL DataFetchingEnvironment.getVariables — operation variables from request", Assigns: "return"},
		{ID: "java.graphql.dfe.getsource", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `\.getSource\s*\(\s*\)`, ObjectType: "DataFetchingEnvironment", MethodName: "getSource", Description: "GraphQL DataFetchingEnvironment.getSource — parent resolver value (may carry prior query input)", Assigns: "return"},

		// --- Apache Camel integration framework sources ---
		// Camel routes typically receive untrusted data from external endpoints
		// (HTTP, JMS, Kafka, file://, etc.). The Exchange / Message / ConsumerTemplate
		// API surfaces are the standard taint boundaries inside Camel processors,
		// route DSL beans, and @Consume-annotated handlers. The Java catalog already
		// covers Spring/JMS/Kafka/RabbitMQ listeners, but Camel is the most common
		// EIP framework on the JVM and was missing entirely (Groovy already has the
		// equivalent groovy.camel.exchange.body entry — see PR #271).
		{ID: "java.camel.exchange.getin", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:exchange|ex|exch)\.getIn\s*\(\s*\)`, ObjectType: "Exchange", MethodName: "getIn", Description: "Apache Camel Exchange.getIn() — inbound Message from upstream endpoint", Assigns: "return"},
		{ID: "java.camel.exchange.getmessage", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:exchange|ex|exch)\.getMessage\s*\(\s*\)`, ObjectType: "Exchange", MethodName: "getMessage", Description: "Apache Camel Exchange.getMessage() — current Message (preferred over getIn() since Camel 3.0)", Assigns: "return"},
		{ID: "java.camel.exchange.getout", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:exchange|ex|exch)\.getOut\s*\(\s*\)`, ObjectType: "Exchange", MethodName: "getOut", Description: "Apache Camel Exchange.getOut() — outbound Message slot (deprecated but still in use)", Assigns: "return"},
		{ID: "java.camel.exchange.getproperty", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:exchange|ex|exch)\.getProperty\s*\(`, ObjectType: "Exchange", MethodName: "getProperty", Description: "Apache Camel Exchange.getProperty(name) — exchange-level property carrying upstream data", Assigns: "return"},
		{ID: "java.camel.exchange.getproperties", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:exchange|ex|exch)\.getProperties\s*\(\s*\)`, ObjectType: "Exchange", MethodName: "getProperties", Description: "Apache Camel Exchange.getProperties() — full property map from upstream route", Assigns: "return"},
		{ID: "java.camel.message.getheader", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message)\.getHeader\s*\(`, ObjectType: "Message", MethodName: "getHeader", Description: "Apache Camel Message.getHeader(name) — header value from inbound message (HTTP, JMS, Kafka headers, etc.)", Assigns: "return"},
		{ID: "java.camel.message.getheaders", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message)\.getHeaders\s*\(\s*\)`, ObjectType: "Message", MethodName: "getHeaders", Description: "Apache Camel Message.getHeaders() — full header map from inbound message", Assigns: "return"},
		{ID: "java.camel.message.getmandatorybody", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message)\.getMandatoryBody\s*\(`, ObjectType: "Message", MethodName: "getMandatoryBody", Description: "Apache Camel Message.getMandatoryBody() — message body (throws if null), upstream payload", Assigns: "return"},
		{ID: "java.camel.consumertemplate.receivebody", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:consumerTemplate|consumer|ct)\.receiveBody\s*\(`, ObjectType: "ConsumerTemplate", MethodName: "receiveBody", Description: "Apache Camel ConsumerTemplate.receiveBody(endpoint) — pulls untrusted body from a Camel endpoint", Assigns: "return"},
		{ID: "java.camel.consumertemplate.receivebodynowait", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:consumerTemplate|consumer|ct)\.receiveBodyNoWait\s*\(`, ObjectType: "ConsumerTemplate", MethodName: "receiveBodyNoWait", Description: "Apache Camel ConsumerTemplate.receiveBodyNoWait(endpoint) — non-blocking pull of untrusted body", Assigns: "return"},
		{ID: "java.camel.consumertemplate.receive", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:consumerTemplate|consumer|ct)\.receive\s*\(`, ObjectType: "ConsumerTemplate", MethodName: "receive", Description: "Apache Camel ConsumerTemplate.receive(endpoint) — pulls full Exchange from a Camel endpoint", Assigns: "return"},
		{ID: "java.camel.pollingconsumer.receive", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:pollingConsumer|consumer)\.receive\s*\(`, ObjectType: "PollingConsumer", MethodName: "receive", Description: "Apache Camel PollingConsumer.receive() — Exchange polled from endpoint, carries untrusted message", Assigns: "return"},

		// --- Spring Messaging WebSocket / STOMP / Spring Cloud Stream sources ---
		// Spring's reactive messaging surface — used by @MessageMapping, @SubscribeMapping
		// STOMP handlers, Spring Cloud Stream Function<Message<I>, Message<O>> beans,
		// Spring Integration channel interceptors, and the WebSocket sub-protocol
		// pipeline — passes attacker-controlled bytes through Message<T>.getPayload().
		// The Java catalog already covers the @KafkaListener / @JmsListener /
		// @RabbitListener / @PulsarListener annotation surfaces, but the lower-level
		// org.springframework.messaging.Message<T> interface that all of them resolve
		// to inside Function-style handlers and channel interceptors was missing.
		{ID: "java.spring.message.getpayload", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:Message|message)\.getPayload\s*\(\s*\)`, ObjectType: "Message", MethodName: "getPayload", Description: "Spring Messaging Message<?>.getPayload() — payload from a STOMP frame, Spring Cloud Stream binding, or Spring Integration channel", Assigns: "return"},

		// --- Spring WebFlux ServerHttpRequest sources ---
		// Reactive controllers, WebFilter implementations, and HandlerFunction
		// route definitions frequently work with the lower-level
		// org.springframework.http.server.reactive.ServerHttpRequest interface
		// (rather than @RequestParam-bound parameters). The catalog already covers
		// ServerRequest (functional routes) and the @-annotation surface, but the
		// reactive ServerHttpRequest used in WebFilter / HandlerFunction /
		// HandshakeWebSocketService code was missing.
		{ID: "java.spring.serverhttprequest.getqueryparams", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:ServerHttpRequest|request|req)\.getQueryParams\s*\(\s*\)`, ObjectType: "ServerHttpRequest", MethodName: "getQueryParams", Description: "Spring WebFlux ServerHttpRequest.getQueryParams() — multimap of query string parameters from the reactive request", Assigns: "return"},
		{ID: "java.spring.serverhttprequest.getpath", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:ServerHttpRequest|request|req)\.getPath\s*\(\s*\)`, ObjectType: "ServerHttpRequest", MethodName: "getPath", Description: "Spring WebFlux ServerHttpRequest.getPath() — RequestPath wrapper around the URL-decoded request path", Assigns: "return"},
		{ID: "java.spring.serverhttprequest.geturi", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:ServerHttpRequest|request|req)\.getURI\s*\(\s*\)`, ObjectType: "ServerHttpRequest", MethodName: "getURI", Description: "Spring WebFlux ServerHttpRequest.getURI() — full request URI from the client", Assigns: "return"},

		// --- JSR-356 jakarta.websocket / javax.websocket Session sources ---
		// The JSR-356 standard WebSocket API is implemented by Tyrus, Tomcat,
		// Jetty, Undertow, and most other Java web servers. @ServerEndpoint
		// methods receive a Session whose getRequestParameterMap /
		// getQueryString / getPathParameters surface attacker-controlled data
		// from the upgrade request, while getUserProperties exposes a Map that
		// handshake handlers (HandshakeRequest interceptors, Configurator
		// subclasses) populate from client-supplied request data — every entry
		// crosses the WebSocket trust boundary. Historical CVEs include
		// CVE-2017-7674 (Tomcat WebSocket CORS bypass via origin properties).
		{ID: "java.websocket.session.getrequestparametermap", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:session|sess)\.getRequestParameterMap\s*\(\s*\)`, ObjectType: "Session", MethodName: "getRequestParameterMap", Description: "JSR-356 jakarta.websocket.Session.getRequestParameterMap() — query parameters from the WebSocket upgrade request", Assigns: "return"},
		{ID: "java.websocket.session.getquerystring", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:session|sess)\.getQueryString\s*\(\s*\)`, ObjectType: "Session", MethodName: "getQueryString", Description: "JSR-356 jakarta.websocket.Session.getQueryString() — raw query string from the WebSocket upgrade request", Assigns: "return"},
		{ID: "java.websocket.session.getpathparameters", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:session|sess)\.getPathParameters\s*\(\s*\)`, ObjectType: "Session", MethodName: "getPathParameters", Description: "JSR-356 jakarta.websocket.Session.getPathParameters() — path template variables from the matched @ServerEndpoint URI", Assigns: "return"},
		{ID: "java.websocket.session.getuserproperties", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:session|sess)\.getUserProperties\s*\(\s*\)`, ObjectType: "Session", MethodName: "getUserProperties", Description: "JSR-356 jakarta.websocket.Session.getUserProperties() — modifiable property map populated by handshake handlers (may carry attacker-controlled values from the WebSocket upgrade)", Assigns: "return"},

		// --- Netty inbound channel sources ---
		// Netty is the NIO server engine behind Reactor Netty, gRPC-java,
		// Vert.x, Hadoop, Cassandra, and Elasticsearch. Custom
		// ChannelInboundHandlerAdapter / SimpleChannelInboundHandler subclasses
		// receive a FullHttpRequest object whose uri() / headers() / content()
		// are wholly attacker-controlled before any framework parsing has
		// happened. The Java catalog already has Netty SINKS
		// (netty.response.headers, reactor.netty.baseurl) but no Netty SOURCES,
		// so taint never originated inside a raw Netty handler.
		{ID: "java.netty.fullhttprequest.uri", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:FullHttpRequest|request|req)\.uri\s*\(\s*\)`, ObjectType: "FullHttpRequest", MethodName: "uri", Description: "Netty FullHttpRequest.uri() — request-line URI from the client (path + raw query string)", Assigns: "return"},
		{ID: "java.netty.fullhttprequest.headers", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:FullHttpRequest|request|req)\.headers\s*\(\s*\)`, ObjectType: "FullHttpRequest", MethodName: "headers", Description: "Netty FullHttpRequest.headers() — HttpHeaders from the client (case-insensitive multimap)", Assigns: "return"},
		{ID: "java.netty.fullhttprequest.content", Category: taint.SrcExternal, Language: rules.LangJava, Pattern: `(?:FullHttpRequest|request|req)\.content\s*\(\s*\)`, ObjectType: "FullHttpRequest", MethodName: "content", Description: "Netty FullHttpRequest.content() — request body as ByteBuf from the client", Assigns: "return"},

		// --- Jedis (Redis) read sources for second-order taint (CWE-89, CWE-78, CWE-79, CWE-502) ---
		// Jedis is the most widely deployed Redis Java client. Java's existing
		// catalog has Jedis SINKS (java.jedis.eval, java.lettuce.dispatch) but
		// no Jedis SOURCES, so user-controlled data written to Redis on one
		// request and read back on a later request would not propagate taint
		// into downstream sinks (Statement.executeQuery, Runtime.exec, response
		// writers, ObjectInputStream, etc.). Redis-backed caches, session
		// stores, and queues all routinely persist attacker-controlled bytes;
		// reading them back without sanitization is a real second-order
		// injection path. Mirrors PR #505 (lua.resty.redis read sources) and
		// the existing JDBC/JPA second-order sources in this catalog.
		{ID: "java.jedis.get", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.get\s*\(`, ObjectType: "Jedis", MethodName: "get", Description: "Jedis.get(key) — Redis GET, returns string value attacker may have placed in cache (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.mget", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.mget\s*\(`, ObjectType: "Jedis", MethodName: "mget", Description: "Jedis.mget(keys) — Redis MGET, returns list of attacker-controlled cached values (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.hget", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.hget\s*\(`, ObjectType: "Jedis", MethodName: "hget", Description: "Jedis.hget(key, field) — Redis HGET, returns hash field value (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.hgetall", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.hgetAll\s*\(`, ObjectType: "Jedis", MethodName: "hgetAll", Description: "Jedis.hgetAll(key) — Redis HGETALL, returns map of attacker-controlled hash fields (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.hmget", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.hmget\s*\(`, ObjectType: "Jedis", MethodName: "hmget", Description: "Jedis.hmget(key, fields) — Redis HMGET, returns list of hash field values (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.hkeys", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.hkeys\s*\(`, ObjectType: "Jedis", MethodName: "hkeys", Description: "Jedis.hkeys(key) — Redis HKEYS, returns set of hash field names (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.hvals", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.hvals\s*\(`, ObjectType: "Jedis", MethodName: "hvals", Description: "Jedis.hvals(key) — Redis HVALS, returns list of hash field values (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.lrange", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.lrange\s*\(`, ObjectType: "Jedis", MethodName: "lrange", Description: "Jedis.lrange(key, start, stop) — Redis LRANGE, returns list of attacker-controlled list elements (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.lindex", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.lindex\s*\(`, ObjectType: "Jedis", MethodName: "lindex", Description: "Jedis.lindex(key, index) — Redis LINDEX, returns list element at index (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.lpop", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.lpop\s*\(`, ObjectType: "Jedis", MethodName: "lpop", Description: "Jedis.lpop(key) — Redis LPOP, returns popped list head value (second-order injection / queue payload)", Assigns: "return"},
		{ID: "java.jedis.smembers", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.smembers\s*\(`, ObjectType: "Jedis", MethodName: "smembers", Description: "Jedis.smembers(key) — Redis SMEMBERS, returns set members (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.zrange", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.zrange\s*\(`, ObjectType: "Jedis", MethodName: "zrange", Description: "Jedis.zrange(key, start, stop) — Redis ZRANGE, returns sorted-set members (second-order injection)", Assigns: "return"},
		{ID: "java.jedis.zrangebyscore", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.zrangeByScore\s*\(`, ObjectType: "Jedis", MethodName: "zrangeByScore", Description: "Jedis.zrangeByScore(key, min, max) — Redis ZRANGEBYSCORE, returns sorted-set members in score range (second-order injection)", Assigns: "return"},

		// --- In-memory cache read sources for second-order taint (CWE-89, CWE-78, CWE-79, CWE-502, CWE-918) ---
		// Guava Cache/LoadingCache, Caffeine Cache/LoadingCache, JCache (javax.cache.Cache)
		// and Ehcache 3 are the dominant JVM caching libraries (Caffeine is the default
		// Spring Boot cache provider). Their value getters return whatever was previously
		// stored — which is frequently attacker-influenced data (a profile name, a
		// serialized blob, a redirect target). Reading it back and feeding it into a SQL
		// statement / Runtime.exec / response writer / ObjectInputStream without
		// re-sanitizing is a real second-order injection path, identical in shape to the
		// Jedis (Redis) read sources above — the catalog had no cache SOURCES.
		//
		// getIfPresent / getAllPresent / getUnchecked are unique to Guava+Caffeine caches
		// (java.util.Map has none of them), so they are FP-safe even with ObjectType ""
		// (any receiver). getUnchecked and getAll are scoped to ObjectType "Cache" to
		// avoid matching unrelated value-unwrap getters (e.g. Futures.getUnchecked,
		// HttpHeaders.getAll); the matcher anchors ObjectType "Cache" to receivers
		// cache/c via its prefix heuristic.
		{ID: "java.cache.getifpresent", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `\.getIfPresent\s*\(`, ObjectType: "", MethodName: "getIfPresent", Description: "Guava/Caffeine Cache.getIfPresent(key) — returns a previously cached value the attacker may have placed in the cache (second-order injection)", Assigns: "return"},
		{ID: "java.cache.getallpresent", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `\.getAllPresent\s*\(`, ObjectType: "", MethodName: "getAllPresent", Description: "Guava/Caffeine Cache.getAllPresent(keys) — returns map of cached values for the present keys (second-order injection)", Assigns: "return"},
		{ID: "java.cache.getunchecked", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:cache|Cache)\w*\.getUnchecked\s*\(`, ObjectType: "Cache", MethodName: "getUnchecked", Description: "Guava LoadingCache.getUnchecked(key) — returns the loaded/cached value (second-order injection)", Assigns: "return"},
		{ID: "java.cache.getall", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:cache|Cache)\w*\.getAll\s*\(`, ObjectType: "Cache", MethodName: "getAll", Description: "JCache/Ehcache3/Guava LoadingCache Cache.getAll(keys) — returns map of cached values (second-order injection)", Assigns: "return"},

		// --- MongoDB BSON Document read sources for second-order taint (CWE-89, CWE-78, CWE-79, CWE-502, CWE-22) ---
		// MongoDB is the most widely deployed NoSQL store in the JVM ecosystem,
		// and `org.bson.Document` is the value type returned by every read path
		// (MongoCollection.find(...).first()/.into(...)/iteration, .aggregate()).
		// The Java catalog already has MongoDB SINKS (java.mongodb.collection.find,
		// .aggregate, .updateOne, ..., java.mongodb.document.parse) but no MongoDB
		// SOURCES, so attacker-controlled bytes written to a collection on one
		// request and read back on a later request did not propagate taint into
		// downstream sinks (Statement.executeQuery, Runtime.exec, response
		// writers, ObjectInputStream, path operations, etc.). Mirrors the Jedis
		// read sources above and the JDBC/JPA/MyBatis second-order sources in
		// this catalog. ObjectType "Document" anchors to receivers doc/document
		// via the matcher's prefix-abbreviation heuristic — the same convention
		// the existing java.mongodb.document.parse sink already uses.
		{ID: "java.mongodb.document.getstring", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:doc|document)\.getString\s*\(`, ObjectType: "Document", MethodName: "getString", Description: "org.bson.Document.getString(key) — value read from a MongoDB document (second-order injection)", Assigns: "return"},
		{ID: "java.mongodb.document.getlist", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:doc|document)\.getList\s*\(`, ObjectType: "Document", MethodName: "getList", Description: "org.bson.Document.getList(key, clazz) — list of values read from a MongoDB document (second-order injection)", Assigns: "return"},
		{ID: "java.mongodb.document.getembedded", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:doc|document)\.getEmbedded\s*\(`, ObjectType: "Document", MethodName: "getEmbedded", Description: "org.bson.Document.getEmbedded(keys, clazz) — nested value read from a MongoDB document (second-order injection)", Assigns: "return"},
		{ID: "java.mongodb.document.tojson", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:doc|document)\.toJson\s*\(`, ObjectType: "Document", MethodName: "toJson", Description: "org.bson.Document.toJson() — full MongoDB document serialized to a JSON string (second-order injection)", Assigns: "return"},

		// --- DataStax Cassandra driver Row read sources for second-order taint (CWE-943, CWE-89, CWE-78) ---
		// Java already has Cassandra SINKS (java.cassandra.cqlsession.execute,
		// .executeAsync, java.cassandra.simplestatement.newinstance/.builder,
		// java.spring.cassandratemplate.select) but had no Cassandra SOURCES, so
		// attacker-controlled bytes written to a table on one request and read
		// back via `row.getString(...)` on a later request did not propagate
		// taint. A Row comes from `ResultSet rs = session.execute(...)` then
		// `Row row = rs.one()` / `for (Row row : rs)`; the getters read column
		// values. Covers the 3.x (com.datastax.driver.core.Row) and 4.x
		// (com.datastax.oss.driver.api.core.cql.Row) drivers plus Spring Data
		// Cassandra, which all expose the same Row getter API. The canonical
		// receiver name `row` anchors to ObjectType "Row" via the matcher's
		// prefix-abbreviation heuristic; `rs`/`session` (the ResultSet/CqlSession)
		// stay scoped to their own entries so there is no overlap.
		{ID: "java.cassandra.row.getstring", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:Row|row)\.getString\s*\(`, ObjectType: "Row", MethodName: "getString", Description: "DataStax Cassandra Row.getString(name/index) — column value read from a Cassandra table (second-order CQL/SQL injection)", Assigns: "return"},
		{ID: "java.cassandra.row.getobject", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:Row|row)\.getObject\s*\(`, ObjectType: "Row", MethodName: "getObject", Description: "DataStax Cassandra Row.getObject(name/index) — column value read from a Cassandra table (second-order injection)", Assigns: "return"},
		{ID: "java.cassandra.row.getlist", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:Row|row)\.getList\s*\(`, ObjectType: "Row", MethodName: "getList", Description: "DataStax Cassandra Row.getList(name, clazz) — collection column read from a Cassandra table (second-order injection)", Assigns: "return"},
		{ID: "java.cassandra.row.getset", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:Row|row)\.getSet\s*\(`, ObjectType: "Row", MethodName: "getSet", Description: "DataStax Cassandra Row.getSet(name, clazz) — set column read from a Cassandra table (second-order injection)", Assigns: "return"},
		{ID: "java.cassandra.row.getmap", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:Row|row)\.getMap\s*\(`, ObjectType: "Row", MethodName: "getMap", Description: "DataStax Cassandra Row.getMap(name, keyClass, valClass) — map column read from a Cassandra table (second-order injection)", Assigns: "return"},

		// --- org.json (JSON-Java) read sources for parsed-input / second-order taint (CWE-89, CWE-78, CWE-79) ---
		// org.json (JSONObject/JSONArray) is one of the most widely used JSON
		// libraries in Java — it ships in the Android platform and is pulled in
		// transitively by countless server projects. It is routinely populated
		// straight from request bodies, webhook payloads, and upstream API
		// responses via `new JSONObject(body)` / `new JSONArray(body)`. The
		// catalog already models Gson/Jackson/JAXB/SnakeYAML deserialization
		// sources but had no org.json coverage, so strings pulled out with
		// .getString()/.optString() were untracked. ObjectType "JSONObject"/
		// "JSONArray" anchors to receivers json/jsonObject/jsonArr/jsonArray/ja
		// via the matcher's prefix-abbreviation heuristic.
		{ID: "java.orgjson.jsonobject.getstring", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:json|jsonObj\w*)\.getString\s*\(`, ObjectType: "JSONObject", MethodName: "getString", Description: "org.json.JSONObject.getString(key) — value parsed from untrusted JSON", Assigns: "return"},
		{ID: "java.orgjson.jsonobject.optstring", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:json|jsonObj\w*)\.optString\s*\(`, ObjectType: "JSONObject", MethodName: "optString", Description: "org.json.JSONObject.optString(key) — value parsed from untrusted JSON", Assigns: "return"},
		{ID: "java.orgjson.jsonarray.getstring", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:jsonArr\w*|jsonArray|json)\.getString\s*\(`, ObjectType: "JSONArray", MethodName: "getString", Description: "org.json.JSONArray.getString(index) — element parsed from untrusted JSON", Assigns: "return"},
		{ID: "java.orgjson.jsonarray.optstring", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `(?:jsonArr\w*|jsonArray|json)\.optString\s*\(`, ObjectType: "JSONArray", MethodName: "optString", Description: "org.json.JSONArray.optString(index) — element parsed from untrusted JSON", Assigns: "return"},

		// --- AWS DynamoDB read sources for second-order taint (CWE-943, CWE-89, CWE-79, CWE-502) ---
		// DynamoDB is the most widely deployed managed NoSQL store in the AWS
		// ecosystem. Items written from one request (attacker-controlled
		// attributes) and read back on a later request via getItem/query/scan
		// carry untrusted values. Reading them without sanitization is a real
		// second-order injection path into downstream sinks (PartiQL/SQL,
		// Runtime.exec, response writers, ObjectInputStream, path ops, etc.).
		// Scoped to dynamoDb*/ddb* receivers so generic .query()/.scan() on
		// JDBC/cache objects are not mis-attributed. Mirrors the Jedis / MongoDB
		// second-order read sources already in this catalog.
		{ID: "java.dynamodb.client.getitem", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:dynamoDb\w*|ddb\w*)\.getItem\s*\(`, ObjectType: "DynamoDbClient", MethodName: "getItem", Description: "AWS DynamoDB getItem() — single item read from a table (attacker may have placed the attribute values; second-order injection)", Assigns: "return"},
		{ID: "java.dynamodb.client.queryscan", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:dynamoDb\w*|ddb\w*)\.(?:query|scan)\s*\(`, ObjectType: "DynamoDbClient", MethodName: "query/scan", Description: "AWS DynamoDB query()/scan() — items read from a table (attacker-controlled attribute values; second-order injection)", Assigns: "return"},
		{ID: "java.dynamodb.client.batchgetitem", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:dynamoDb\w*|ddb\w*)\.batchGetItem\s*\(`, ObjectType: "DynamoDbClient", MethodName: "batchGetItem", Description: "AWS DynamoDB batchGetItem() — multi-table item read (attacker may have placed the attribute values; second-order injection)", Assigns: "return"},
		{ID: "java.dynamodb.client.transactgetitems", Category: taint.SrcDatabase, Language: rules.LangJava, Pattern: `(?:dynamoDb\w*|ddb\w*)\.transactGetItems\s*\(`, ObjectType: "DynamoDbClient", MethodName: "transactGetItems", Description: "AWS DynamoDB transactGetItems() — transactional multi-item read (attacker-controlled attribute values; second-order injection)", Assigns: "return"},

		// =================================================================
		// Mined from public MIT-licensed security-model data.
		// 195 remote/database sources.
		// =================================================================

		{ID: "java.content.context.getexternalcachedir", Category: taint.SrcExternal, Pattern: `\.getExternalCacheDir\s*\(`, ObjectType: "android.content.Context", MethodName: "getExternalCacheDir", Description: "android.content.Context.getExternalCacheDir — android external storage dir source", Assigns: "return"},
		{ID: "java.content.context.getexternalcachedirs", Category: taint.SrcExternal, Pattern: `\.getExternalCacheDirs\s*\(`, ObjectType: "android.content.Context", MethodName: "getExternalCacheDirs", Description: "android.content.Context.getExternalCacheDirs — android external storage dir source", Assigns: "return"},
		{ID: "java.content.context.getexternalfilesdir", Category: taint.SrcExternal, Pattern: `\.getExternalFilesDir\s*\(`, ObjectType: "android.content.Context", MethodName: "getExternalFilesDir", Description: "android.content.Context.getExternalFilesDir — android external storage dir source", Assigns: "return"},
		{ID: "java.content.context.getexternalfilesdirs", Category: taint.SrcExternal, Pattern: `\.getExternalFilesDirs\s*\(`, ObjectType: "android.content.Context", MethodName: "getExternalFilesDirs", Description: "android.content.Context.getExternalFilesDirs — android external storage dir source", Assigns: "return"},
		{ID: "java.os.environment.getexternalstoragedirectory", Category: taint.SrcExternal, Pattern: `\.getExternalStorageDirectory\s*\(`, ObjectType: "android.os.Environment", MethodName: "getExternalStorageDirectory", Description: "android.os.Environment.getExternalStorageDirectory — android external storage dir source", Assigns: "return"},
		{ID: "java.os.environment.getexternalstoragepublicdirectory", Category: taint.SrcExternal, Pattern: `\.getExternalStoragePublicDirectory\s*\(`, ObjectType: "android.os.Environment", MethodName: "getExternalStoragePublicDirectory", Description: "android.os.Environment.getExternalStoragePublicDirectory — android external storage dir source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributebooleanvalue", Category: taint.SrcExternal, Pattern: `\.getAttributeBooleanValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeBooleanValue", Description: "android.util.AttributeSet.getAttributeBooleanValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributecount", Category: taint.SrcExternal, Pattern: `\.getAttributeCount\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeCount", Description: "android.util.AttributeSet.getAttributeCount — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributefloatvalue", Category: taint.SrcExternal, Pattern: `\.getAttributeFloatValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeFloatValue", Description: "android.util.AttributeSet.getAttributeFloatValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributeintvalue", Category: taint.SrcExternal, Pattern: `\.getAttributeIntValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeIntValue", Description: "android.util.AttributeSet.getAttributeIntValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributelistvalue", Category: taint.SrcExternal, Pattern: `\.getAttributeListValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeListValue", Description: "android.util.AttributeSet.getAttributeListValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributename", Category: taint.SrcExternal, Pattern: `\.getAttributeName\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeName", Description: "android.util.AttributeSet.getAttributeName — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributenameresource", Category: taint.SrcExternal, Pattern: `\.getAttributeNameResource\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeNameResource", Description: "android.util.AttributeSet.getAttributeNameResource — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributenamespace", Category: taint.SrcExternal, Pattern: `\.getAttributeNamespace\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeNamespace", Description: "android.util.AttributeSet.getAttributeNamespace — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributeresourcevalue", Category: taint.SrcExternal, Pattern: `\.getAttributeResourceValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeResourceValue", Description: "android.util.AttributeSet.getAttributeResourceValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributeunsignedintvalue", Category: taint.SrcExternal, Pattern: `\.getAttributeUnsignedIntValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeUnsignedIntValue", Description: "android.util.AttributeSet.getAttributeUnsignedIntValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getattributevalue", Category: taint.SrcExternal, Pattern: `\.getAttributeValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getAttributeValue", Description: "android.util.AttributeSet.getAttributeValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getclassattribute", Category: taint.SrcExternal, Pattern: `\.getClassAttribute\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getClassAttribute", Description: "android.util.AttributeSet.getClassAttribute — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getidattribute", Category: taint.SrcExternal, Pattern: `\.getIdAttribute\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getIdAttribute", Description: "android.util.AttributeSet.getIdAttribute — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getidattributeresourcevalue", Category: taint.SrcExternal, Pattern: `\.getIdAttributeResourceValue\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getIdAttributeResourceValue", Description: "android.util.AttributeSet.getIdAttributeResourceValue — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getpositiondescription", Category: taint.SrcExternal, Pattern: `\.getPositionDescription\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getPositionDescription", Description: "android.util.AttributeSet.getPositionDescription — remote source", Assigns: "return"},
		{ID: "java.util.attributeset.getstyleattribute", Category: taint.SrcExternal, Pattern: `\.getStyleAttribute\s*\(`, ObjectType: "android.util.AttributeSet", MethodName: "getStyleAttribute", Description: "android.util.AttributeSet.getStyleAttribute — remote source", Assigns: "return"},
		{ID: "java.webkit.webview.getoriginalurl", Category: taint.SrcExternal, Pattern: `\.getOriginalUrl\s*\(`, ObjectType: "android.webkit.WebView", MethodName: "getOriginalUrl", Description: "android.webkit.WebView.getOriginalUrl — remote source", Assigns: "return"},
		{ID: "java.webkit.webview.geturl", Category: taint.SrcExternal, Pattern: `\.getUrl\s*\(`, ObjectType: "android.webkit.WebView", MethodName: "getUrl", Description: "android.webkit.WebView.getUrl — remote source", Assigns: "return"},
		{ID: "java.impl.framehandler.readframe", Category: taint.SrcExternal, Pattern: `\.readFrame\s*\(`, ObjectType: "com.rabbitmq.client.impl.FrameHandler", MethodName: "readFrame", Description: "com.rabbitmq.client.impl.FrameHandler.readFrame — remote source", Assigns: "return"},
		{ID: "java.client.command.getcontentbody", Category: taint.SrcExternal, Pattern: `\.getContentBody\s*\(`, ObjectType: "com.rabbitmq.client.Command", MethodName: "getContentBody", Description: "com.rabbitmq.client.Command.getContentBody — remote source", Assigns: "return"},
		{ID: "java.client.command.getcontentheader", Category: taint.SrcExternal, Pattern: `\.getContentHeader\s*\(`, ObjectType: "com.rabbitmq.client.Command", MethodName: "getContentHeader", Description: "com.rabbitmq.client.Command.getContentHeader — remote source", Assigns: "return"},
		{ID: "java.client.consumer.handledelivery", Category: taint.SrcExternal, Pattern: `\.handleDelivery\s*\(`, ObjectType: "com.rabbitmq.client.Consumer", MethodName: "handleDelivery", Description: "com.rabbitmq.client.Consumer.handleDelivery — remote source", Assigns: "return"},
		{ID: "java.client.queueingconsumer.nextdelivery", Category: taint.SrcExternal, Pattern: `\.nextDelivery\s*\(`, ObjectType: "com.rabbitmq.client.QueueingConsumer", MethodName: "nextDelivery", Description: "com.rabbitmq.client.QueueingConsumer.nextDelivery — remote source", Assigns: "return"},
		{ID: "java.client.rpcclient.docall", Category: taint.SrcExternal, Pattern: `\.doCall\s*\(`, ObjectType: "com.rabbitmq.client.RpcClient", MethodName: "doCall", Description: "com.rabbitmq.client.RpcClient.doCall — remote source", Assigns: "return"},
		{ID: "java.client.rpcclient.mapcall", Category: taint.SrcExternal, Pattern: `\.mapCall\s*\(`, ObjectType: "com.rabbitmq.client.RpcClient", MethodName: "mapCall", Description: "com.rabbitmq.client.RpcClient.mapCall — remote source", Assigns: "return"},
		{ID: "java.client.rpcclient.primitivecall", Category: taint.SrcExternal, Pattern: `\.primitiveCall\s*\(`, ObjectType: "com.rabbitmq.client.RpcClient", MethodName: "primitiveCall", Description: "com.rabbitmq.client.RpcClient.primitiveCall — remote source", Assigns: "return"},
		{ID: "java.client.rpcclient.responsecall", Category: taint.SrcExternal, Pattern: `\.responseCall\s*\(`, ObjectType: "com.rabbitmq.client.RpcClient", MethodName: "responseCall", Description: "com.rabbitmq.client.RpcClient.responseCall — remote source", Assigns: "return"},
		{ID: "java.client.rpcclient.stringcall", Category: taint.SrcExternal, Pattern: `\.stringCall\s*\(`, ObjectType: "com.rabbitmq.client.RpcClient", MethodName: "stringCall", Description: "com.rabbitmq.client.RpcClient.stringCall — remote source", Assigns: "return"},
		{ID: "java.client.rpcserver.handlecall", Category: taint.SrcExternal, Pattern: `\.handleCall\s*\(`, ObjectType: "com.rabbitmq.client.RpcServer", MethodName: "handleCall", Description: "com.rabbitmq.client.RpcServer.handleCall — remote source", Assigns: "return"},
		{ID: "java.client.rpcserver.handlecast", Category: taint.SrcExternal, Pattern: `\.handleCast\s*\(`, ObjectType: "com.rabbitmq.client.RpcServer", MethodName: "handleCast", Description: "com.rabbitmq.client.RpcServer.handleCast — remote source", Assigns: "return"},
		{ID: "java.client.rpcserver.postprocessreplyproperties", Category: taint.SrcExternal, Pattern: `\.postprocessReplyProperties\s*\(`, ObjectType: "com.rabbitmq.client.RpcServer", MethodName: "postprocessReplyProperties", Description: "com.rabbitmq.client.RpcServer.postprocessReplyProperties — remote source", Assigns: "return"},
		{ID: "java.client.rpcserver.preprocessreplyproperties", Category: taint.SrcExternal, Pattern: `\.preprocessReplyProperties\s*\(`, ObjectType: "com.rabbitmq.client.RpcServer", MethodName: "preprocessReplyProperties", Description: "com.rabbitmq.client.RpcServer.preprocessReplyProperties — remote source", Assigns: "return"},
		{ID: "java.client.stringrpcserver.handlestringcall", Category: taint.SrcExternal, Pattern: `\.handleStringCall\s*\(`, ObjectType: "com.rabbitmq.client.StringRpcServer", MethodName: "handleStringCall", Description: "com.rabbitmq.client.StringRpcServer.handleStringCall — remote source", Assigns: "return"},
		{ID: "java.model.descriptor.configure", Category: taint.SrcExternal, Pattern: `\.configure\s*\(`, ObjectType: "hudson.model.Descriptor", MethodName: "configure", Description: "hudson.model.Descriptor.configure — remote source", Assigns: "return"},
		{ID: "java.model.descriptor.newinstance", Category: taint.SrcExternal, Pattern: `\.newInstance\s*\(`, ObjectType: "hudson.model.Descriptor", MethodName: "newInstance", Description: "hudson.model.Descriptor.newInstance — remote source", Assigns: "return"},
		{ID: "java.hudson.plugin.configure", Category: taint.SrcExternal, Pattern: `\.configure\s*\(`, ObjectType: "hudson.Plugin", MethodName: "configure", Description: "hudson.Plugin.configure — remote source", Assigns: "return"},
		{ID: "java.hudson.plugin.newinstance", Category: taint.SrcExternal, Pattern: `\.newInstance\s*\(`, ObjectType: "hudson.Plugin", MethodName: "newInstance", Description: "hudson.Plugin.newInstance — remote source", Assigns: "return"},
		{ID: "java.jsonwebtoken.signingkeyresolver.resolvesigningkey", Category: taint.SrcExternal, Pattern: `\.resolveSigningKey\s*\(`, ObjectType: "io.jsonwebtoken.SigningKeyResolver", MethodName: "resolveSigningKey", Description: "io.jsonwebtoken.SigningKeyResolver.resolveSigningKey — remote source", Assigns: "return"},
		{ID: "java.jsonwebtoken.signingkeyresolveradapter.resolvesigningkeybytes", Category: taint.SrcExternal, Pattern: `\.resolveSigningKeyBytes\s*\(`, ObjectType: "io.jsonwebtoken.SigningKeyResolverAdapter", MethodName: "resolveSigningKeyBytes", Description: "io.jsonwebtoken.SigningKeyResolverAdapter.resolveSigningKeyBytes — remote source", Assigns: "return"},
		{ID: "java.channel.channelinboundhandler.channelread", Category: taint.SrcExternal, Pattern: `\.channelRead\s*\(`, ObjectType: "io.netty.channel.ChannelInboundHandler", MethodName: "channelRead", Description: "io.netty.channel.ChannelInboundHandler.channelRead — remote source", Assigns: "return"},
		{ID: "java.channel.simplechannelinboundhandler.channelread0", Category: taint.SrcExternal, Pattern: `\.channelRead0\s*\(`, ObjectType: "io.netty.channel.SimpleChannelInboundHandler", MethodName: "channelRead0", Description: "io.netty.channel.SimpleChannelInboundHandler.channelRead0 — remote source", Assigns: "return"},
		{ID: "java.http2.http2framelistener.ondataread", Category: taint.SrcExternal, Pattern: `\.onDataRead\s*\(`, ObjectType: "io.netty.handler.codec.http2.Http2FrameListener", MethodName: "onDataRead", Description: "io.netty.handler.codec.http2.Http2FrameListener.onDataRead — remote source", Assigns: "return"},
		{ID: "java.http2.http2framelistener.onheadersread", Category: taint.SrcExternal, Pattern: `\.onHeadersRead\s*\(`, ObjectType: "io.netty.handler.codec.http2.Http2FrameListener", MethodName: "onHeadersRead", Description: "io.netty.handler.codec.http2.Http2FrameListener.onHeadersRead — remote source", Assigns: "return"},
		{ID: "java.http2.http2framelistener.onpushpromiseread", Category: taint.SrcExternal, Pattern: `\.onPushPromiseRead\s*\(`, ObjectType: "io.netty.handler.codec.http2.Http2FrameListener", MethodName: "onPushPromiseRead", Description: "io.netty.handler.codec.http2.Http2FrameListener.onPushPromiseRead — remote source", Assigns: "return"},
		{ID: "java.http2.http2framelistener.onunknownframe", Category: taint.SrcExternal, Pattern: `\.onUnknownFrame\s*\(`, ObjectType: "io.netty.handler.codec.http2.Http2FrameListener", MethodName: "onUnknownFrame", Description: "io.netty.handler.codec.http2.Http2FrameListener.onUnknownFrame — remote source", Assigns: "return"},
		{ID: "java.codec.bytetomessagedecoder.calldecode", Category: taint.SrcExternal, Pattern: `\.callDecode\s*\(`, ObjectType: "io.netty.handler.codec.ByteToMessageDecoder", MethodName: "callDecode", Description: "io.netty.handler.codec.ByteToMessageDecoder.callDecode — remote source", Assigns: "return"},
		{ID: "java.codec.bytetomessagedecoder.decode", Category: taint.SrcExternal, Pattern: `\.decode\s*\(`, ObjectType: "io.netty.handler.codec.ByteToMessageDecoder", MethodName: "decode", Description: "io.netty.handler.codec.ByteToMessageDecoder.decode — remote source", Assigns: "return"},
		{ID: "java.codec.bytetomessagedecoder.decodelast", Category: taint.SrcExternal, Pattern: `\.decodeLast\s*\(`, ObjectType: "io.netty.handler.codec.ByteToMessageDecoder", MethodName: "decodeLast", Description: "io.netty.handler.codec.ByteToMessageDecoder.decodeLast — remote source", Assigns: "return"},
		{ID: "java.codec.bytetomessagecodec.decode", Category: taint.SrcExternal, Pattern: `\.decode\s*\(`, ObjectType: "io.netty.handler.codec.ByteToMessageCodec", MethodName: "decode", Description: "io.netty.handler.codec.ByteToMessageCodec.decode — remote source", Assigns: "return"},
		{ID: "java.codec.bytetomessagecodec.decodelast", Category: taint.SrcExternal, Pattern: `\.decodeLast\s*\(`, ObjectType: "io.netty.handler.codec.ByteToMessageCodec", MethodName: "decodeLast", Description: "io.netty.handler.codec.ByteToMessageCodec.decodeLast — remote source", Assigns: "return"},
		{ID: "java.codec.messagetomessagedecoder.acceptinboundmessage", Category: taint.SrcExternal, Pattern: `\.acceptInboundMessage\s*\(`, ObjectType: "io.netty.handler.codec.MessageToMessageDecoder", MethodName: "acceptInboundMessage", Description: "io.netty.handler.codec.MessageToMessageDecoder.acceptInboundMessage — remote source", Assigns: "return"},
		{ID: "java.codec.messagetomessagedecoder.decode", Category: taint.SrcExternal, Pattern: `\.decode\s*\(`, ObjectType: "io.netty.handler.codec.MessageToMessageDecoder", MethodName: "decode", Description: "io.netty.handler.codec.MessageToMessageDecoder.decode — remote source", Assigns: "return"},
		{ID: "java.codec.messagetomessagecodec.acceptinboundmessage", Category: taint.SrcExternal, Pattern: `\.acceptInboundMessage\s*\(`, ObjectType: "io.netty.handler.codec.MessageToMessageCodec", MethodName: "acceptInboundMessage", Description: "io.netty.handler.codec.MessageToMessageCodec.acceptInboundMessage — remote source", Assigns: "return"},
		{ID: "java.codec.messagetomessagecodec.decode", Category: taint.SrcExternal, Pattern: `\.decode\s*\(`, ObjectType: "io.netty.handler.codec.MessageToMessageCodec", MethodName: "decode", Description: "io.netty.handler.codec.MessageToMessageCodec.decode — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestcookiemap", Category: taint.SrcExternal, Pattern: `\.getRequestCookieMap\s*\(`, ObjectType: "jakarta.faces.context.ExternalContext", MethodName: "getRequestCookieMap", Description: "jakarta.faces.context.ExternalContext.getRequestCookieMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestheadermap", Category: taint.SrcExternal, Pattern: `\.getRequestHeaderMap\s*\(`, ObjectType: "jakarta.faces.context.ExternalContext", MethodName: "getRequestHeaderMap", Description: "jakarta.faces.context.ExternalContext.getRequestHeaderMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestheadervaluesmap", Category: taint.SrcExternal, Pattern: `\.getRequestHeaderValuesMap\s*\(`, ObjectType: "jakarta.faces.context.ExternalContext", MethodName: "getRequestHeaderValuesMap", Description: "jakarta.faces.context.ExternalContext.getRequestHeaderValuesMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestparameternames", Category: taint.SrcExternal, Pattern: `\.getRequestParameterNames\s*\(`, ObjectType: "jakarta.faces.context.ExternalContext", MethodName: "getRequestParameterNames", Description: "jakarta.faces.context.ExternalContext.getRequestParameterNames — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestparametervaluesmap", Category: taint.SrcExternal, Pattern: `\.getRequestParameterValuesMap\s*\(`, ObjectType: "jakarta.faces.context.ExternalContext", MethodName: "getRequestParameterValuesMap", Description: "jakarta.faces.context.ExternalContext.getRequestParameterValuesMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestpathinfo", Category: taint.SrcExternal, Pattern: `\.getRequestPathInfo\s*\(`, ObjectType: "jakarta.faces.context.ExternalContext", MethodName: "getRequestPathInfo", Description: "jakarta.faces.context.ExternalContext.getRequestPathInfo — remote source", Assigns: "return"},
		{ID: "java.http.part.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "jakarta.servlet.http.Part", MethodName: "getName", Description: "jakarta.servlet.http.Part.getName — remote source", Assigns: "return"},
		{ID: "java.http.part.getcontenttype", Category: taint.SrcExternal, Pattern: `\.getContentType\s*\(`, ObjectType: "jakarta.servlet.http.Part", MethodName: "getContentType", Description: "jakarta.servlet.http.Part.getContentType — remote source", Assigns: "return"},
		{ID: "java.http.httpservletrequest.getremoteuser", Category: taint.SrcExternal, Pattern: `\.getRemoteUser\s*\(`, ObjectType: "jakarta.servlet.http.HttpServletRequest", MethodName: "getRemoteUser", Description: "jakarta.servlet.http.HttpServletRequest.getRemoteUser — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getacceptablelanguages", Category: taint.SrcExternal, Pattern: `\.getAcceptableLanguages\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getAcceptableLanguages", Description: "jakarta.ws.rs.container.ContainerRequestContext.getAcceptableLanguages — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getacceptablemediatypes", Category: taint.SrcExternal, Pattern: `\.getAcceptableMediaTypes\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getAcceptableMediaTypes", Description: "jakarta.ws.rs.container.ContainerRequestContext.getAcceptableMediaTypes — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getentitystream", Category: taint.SrcExternal, Pattern: `\.getEntityStream\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getEntityStream", Description: "jakarta.ws.rs.container.ContainerRequestContext.getEntityStream — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getheaderstring", Category: taint.SrcExternal, Pattern: `\.getHeaderString\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getHeaderString", Description: "jakarta.ws.rs.container.ContainerRequestContext.getHeaderString — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getlanguage", Category: taint.SrcExternal, Pattern: `\.getLanguage\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getLanguage", Description: "jakarta.ws.rs.container.ContainerRequestContext.getLanguage — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getmediatype", Category: taint.SrcExternal, Pattern: `\.getMediaType\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getMediaType", Description: "jakarta.ws.rs.container.ContainerRequestContext.getMediaType — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.geturiinfo", Category: taint.SrcExternal, Pattern: `\.getUriInfo\s*\(`, ObjectType: "jakarta.ws.rs.container.ContainerRequestContext", MethodName: "getUriInfo", Description: "jakarta.ws.rs.container.ContainerRequestContext.getUriInfo — remote source", Assigns: "return"},
		{ID: "java.attachment.attachmentunmarshaller.getattachmentasdatahandler", Category: taint.SrcExternal, Pattern: `\.getAttachmentAsDataHandler\s*\(`, ObjectType: "jakarta.xml.bind.attachment.AttachmentUnmarshaller", MethodName: "getAttachmentAsDataHandler", Description: "jakarta.xml.bind.attachment.AttachmentUnmarshaller.getAttachmentAsDataHandler — remote source", Assigns: "return"},
		{ID: "java.attachment.attachmentunmarshaller.getattachmentasbytearray", Category: taint.SrcExternal, Pattern: `\.getAttachmentAsByteArray\s*\(`, ObjectType: "jakarta.xml.bind.attachment.AttachmentUnmarshaller", MethodName: "getAttachmentAsByteArray", Description: "jakarta.xml.bind.attachment.AttachmentUnmarshaller.getAttachmentAsByteArray — remote source", Assigns: "return"},
		{ID: "java.http.websocketlistener.ontext", Category: taint.SrcExternal, Pattern: `\.onText\s*\(`, ObjectType: "java.net.http.WebSocket$Listener", MethodName: "onText", Description: "java.net.http.WebSocket$Listener.onText — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestcookiemap", Category: taint.SrcExternal, Pattern: `\.getRequestCookieMap\s*\(`, ObjectType: "javax.faces.context.ExternalContext", MethodName: "getRequestCookieMap", Description: "javax.faces.context.ExternalContext.getRequestCookieMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestheadermap", Category: taint.SrcExternal, Pattern: `\.getRequestHeaderMap\s*\(`, ObjectType: "javax.faces.context.ExternalContext", MethodName: "getRequestHeaderMap", Description: "javax.faces.context.ExternalContext.getRequestHeaderMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestheadervaluesmap", Category: taint.SrcExternal, Pattern: `\.getRequestHeaderValuesMap\s*\(`, ObjectType: "javax.faces.context.ExternalContext", MethodName: "getRequestHeaderValuesMap", Description: "javax.faces.context.ExternalContext.getRequestHeaderValuesMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestparameternames", Category: taint.SrcExternal, Pattern: `\.getRequestParameterNames\s*\(`, ObjectType: "javax.faces.context.ExternalContext", MethodName: "getRequestParameterNames", Description: "javax.faces.context.ExternalContext.getRequestParameterNames — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestparametervaluesmap", Category: taint.SrcExternal, Pattern: `\.getRequestParameterValuesMap\s*\(`, ObjectType: "javax.faces.context.ExternalContext", MethodName: "getRequestParameterValuesMap", Description: "javax.faces.context.ExternalContext.getRequestParameterValuesMap — remote source", Assigns: "return"},
		{ID: "java.context.externalcontext.getrequestpathinfo", Category: taint.SrcExternal, Pattern: `\.getRequestPathInfo\s*\(`, ObjectType: "javax.faces.context.ExternalContext", MethodName: "getRequestPathInfo", Description: "javax.faces.context.ExternalContext.getRequestPathInfo — remote source", Assigns: "return"},
		{ID: "java.jms.jmsconsumer.receivenowait", Category: taint.SrcExternal, Pattern: `\.receiveNoWait\s*\(`, ObjectType: "javax.jms.JMSConsumer", MethodName: "receiveNoWait", Description: "javax.jms.JMSConsumer.receiveNoWait — remote source", Assigns: "return"},
		{ID: "java.jms.messageconsumer.receivenowait", Category: taint.SrcExternal, Pattern: `\.receiveNoWait\s*\(`, ObjectType: "javax.jms.MessageConsumer", MethodName: "receiveNoWait", Description: "javax.jms.MessageConsumer.receiveNoWait — remote source", Assigns: "return"},
		{ID: "java.jms.messagelistener.onmessage", Category: taint.SrcExternal, Pattern: `\.onMessage\s*\(`, ObjectType: "javax.jms.MessageListener", MethodName: "onMessage", Description: "javax.jms.MessageListener.onMessage — remote source", Assigns: "return"},
		{ID: "java.jms.queuerequestor.request", Category: taint.SrcExternal, Pattern: `\.request\s*\(`, ObjectType: "javax.jms.QueueRequestor", MethodName: "request", Description: "javax.jms.QueueRequestor.request — remote source", Assigns: "return"},
		{ID: "java.jms.topicrequestor.request", Category: taint.SrcExternal, Pattern: `\.request\s*\(`, ObjectType: "javax.jms.TopicRequestor", MethodName: "request", Description: "javax.jms.TopicRequestor.request — remote source", Assigns: "return"},
		{ID: "java.http.cookie.getcomment", Category: taint.SrcExternal, Pattern: `\.getComment\s*\(`, ObjectType: "javax.servlet.http.Cookie", MethodName: "getComment", Description: "javax.servlet.http.Cookie.getComment — remote source", Assigns: "return"},
		{ID: "java.http.cookie.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "javax.servlet.http.Cookie", MethodName: "getName", Description: "javax.servlet.http.Cookie.getName — remote source", Assigns: "return"},
		{ID: "java.http.httpservletrequest.getremoteuser", Category: taint.SrcExternal, Pattern: `\.getRemoteUser\s*\(`, ObjectType: "javax.servlet.http.HttpServletRequest", MethodName: "getRemoteUser", Description: "javax.servlet.http.HttpServletRequest.getRemoteUser — remote source", Assigns: "return"},
		{ID: "java.http.part.getcontenttype", Category: taint.SrcExternal, Pattern: `\.getContentType\s*\(`, ObjectType: "javax.servlet.http.Part", MethodName: "getContentType", Description: "javax.servlet.http.Part.getContentType — remote source", Assigns: "return"},
		{ID: "java.http.part.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "javax.servlet.http.Part", MethodName: "getName", Description: "javax.servlet.http.Part.getName — remote source", Assigns: "return"},
		{ID: "java.validation.constraintvalidator.isvalid", Category: taint.SrcExternal, Pattern: `\.isValid\s*\(`, ObjectType: "javax.validation.ConstraintValidator", MethodName: "isValid", Description: "javax.validation.ConstraintValidator.isValid — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getacceptablelanguages", Category: taint.SrcExternal, Pattern: `\.getAcceptableLanguages\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getAcceptableLanguages", Description: "javax.ws.rs.container.ContainerRequestContext.getAcceptableLanguages — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getacceptablemediatypes", Category: taint.SrcExternal, Pattern: `\.getAcceptableMediaTypes\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getAcceptableMediaTypes", Description: "javax.ws.rs.container.ContainerRequestContext.getAcceptableMediaTypes — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getentitystream", Category: taint.SrcExternal, Pattern: `\.getEntityStream\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getEntityStream", Description: "javax.ws.rs.container.ContainerRequestContext.getEntityStream — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getheaderstring", Category: taint.SrcExternal, Pattern: `\.getHeaderString\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getHeaderString", Description: "javax.ws.rs.container.ContainerRequestContext.getHeaderString — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getlanguage", Category: taint.SrcExternal, Pattern: `\.getLanguage\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getLanguage", Description: "javax.ws.rs.container.ContainerRequestContext.getLanguage — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.getmediatype", Category: taint.SrcExternal, Pattern: `\.getMediaType\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getMediaType", Description: "javax.ws.rs.container.ContainerRequestContext.getMediaType — remote source", Assigns: "return"},
		{ID: "java.container.containerrequestcontext.geturiinfo", Category: taint.SrcExternal, Pattern: `\.getUriInfo\s*\(`, ObjectType: "javax.ws.rs.container.ContainerRequestContext", MethodName: "getUriInfo", Description: "javax.ws.rs.container.ContainerRequestContext.getUriInfo — remote source", Assigns: "return"},
		{ID: "java.attachment.attachmentunmarshaller.getattachmentasdatahandler", Category: taint.SrcExternal, Pattern: `\.getAttachmentAsDataHandler\s*\(`, ObjectType: "javax.xml.bind.attachment.AttachmentUnmarshaller", MethodName: "getAttachmentAsDataHandler", Description: "javax.xml.bind.attachment.AttachmentUnmarshaller.getAttachmentAsDataHandler — remote source", Assigns: "return"},
		{ID: "java.attachment.attachmentunmarshaller.getattachmentasbytearray", Category: taint.SrcExternal, Pattern: `\.getAttachmentAsByteArray\s*\(`, ObjectType: "javax.xml.bind.attachment.AttachmentUnmarshaller", MethodName: "getAttachmentAsByteArray", Description: "javax.xml.bind.attachment.AttachmentUnmarshaller.getAttachmentAsByteArray — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitem.getcontenttype", Category: taint.SrcExternal, Pattern: `\.getContentType\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItem", MethodName: "getContentType", Description: "org.apache.commons.fileupload.FileItem.getContentType — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitem.getfieldname", Category: taint.SrcExternal, Pattern: `\.getFieldName\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItem", MethodName: "getFieldName", Description: "org.apache.commons.fileupload.FileItem.getFieldName — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitem.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItem", MethodName: "getName", Description: "org.apache.commons.fileupload.FileItem.getName — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitemstream.getcontenttype", Category: taint.SrcExternal, Pattern: `\.getContentType\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItemStream", MethodName: "getContentType", Description: "org.apache.commons.fileupload.FileItemStream.getContentType — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitemstream.getfieldname", Category: taint.SrcExternal, Pattern: `\.getFieldName\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItemStream", MethodName: "getFieldName", Description: "org.apache.commons.fileupload.FileItemStream.getFieldName — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitemstream.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItemStream", MethodName: "getName", Description: "org.apache.commons.fileupload.FileItemStream.getName — remote source", Assigns: "return"},
		{ID: "java.fileupload.fileitemstream.openstream", Category: taint.SrcExternal, Pattern: `\.openStream\s*\(`, ObjectType: "org.apache.commons.fileupload.FileItemStream", MethodName: "openStream", Description: "org.apache.commons.fileupload.FileItemStream.openStream — remote source", Assigns: "return"},
		{ID: "java.ftp.ftpclient.listdirectories", Category: taint.SrcExternal, Pattern: `\.listDirectories\s*\(`, ObjectType: "org.apache.commons.net.ftp.FTPClient", MethodName: "listDirectories", Description: "org.apache.commons.net.ftp.FTPClient.listDirectories — remote source", Assigns: "return"},
		{ID: "java.ftp.ftpclient.listfiles", Category: taint.SrcExternal, Pattern: `\.listFiles\s*\(`, ObjectType: "org.apache.commons.net.ftp.FTPClient", MethodName: "listFiles", Description: "org.apache.commons.net.ftp.FTPClient.listFiles — remote source", Assigns: "return"},
		{ID: "java.ftp.ftpclient.listnames", Category: taint.SrcExternal, Pattern: `\.listNames\s*\(`, ObjectType: "org.apache.commons.net.ftp.FTPClient", MethodName: "listNames", Description: "org.apache.commons.net.ftp.FTPClient.listNames — remote source", Assigns: "return"},
		{ID: "java.ftp.ftpclient.mlistdir", Category: taint.SrcExternal, Pattern: `\.mlistDir\s*\(`, ObjectType: "org.apache.commons.net.ftp.FTPClient", MethodName: "mlistDir", Description: "org.apache.commons.net.ftp.FTPClient.mlistDir — remote source", Assigns: "return"},
		{ID: "java.ftp.ftpclient.retrievefile", Category: taint.SrcExternal, Pattern: `\.retrieveFile\s*\(`, ObjectType: "org.apache.commons.net.ftp.FTPClient", MethodName: "retrieveFile", Description: "org.apache.commons.net.ftp.FTPClient.retrieveFile — remote source", Assigns: "return"},
		{ID: "java.ftp.ftpclient.retrievefilestream", Category: taint.SrcExternal, Pattern: `\.retrieveFileStream\s*\(`, ObjectType: "org.apache.commons.net.ftp.FTPClient", MethodName: "retrieveFileStream", Description: "org.apache.commons.net.ftp.FTPClient.retrieveFileStream — remote source", Assigns: "return"},
		{ID: "java.io.httprequesthandler.handle", Category: taint.SrcExternal, Pattern: `\.handle\s*\(`, ObjectType: "org.apache.hc.core5.http.io.HttpRequestHandler", MethodName: "handle", Description: "org.apache.hc.core5.http.io.HttpRequestHandler.handle — remote source", Assigns: "return"},
		{ID: "java.io.httpserverrequesthandler.handle", Category: taint.SrcExternal, Pattern: `\.handle\s*\(`, ObjectType: "org.apache.hc.core5.http.io.HttpServerRequestHandler", MethodName: "handle", Description: "org.apache.hc.core5.http.io.HttpServerRequestHandler.handle — remote source", Assigns: "return"},
		{ID: "java.http.httpentity.getcontent", Category: taint.SrcExternal, Pattern: `\.getContent\s*\(`, ObjectType: "org.apache.http.HttpEntity", MethodName: "getContent", Description: "org.apache.http.HttpEntity.getContent — remote source", Assigns: "return"},
		{ID: "java.http.httpmessage.getparams", Category: taint.SrcExternal, Pattern: `\.getParams\s*\(`, ObjectType: "org.apache.http.HttpMessage", MethodName: "getParams", Description: "org.apache.http.HttpMessage.getParams — remote source", Assigns: "return"},
		{ID: "java.protocol.httprequesthandler.handle", Category: taint.SrcExternal, Pattern: `\.handle\s*\(`, ObjectType: "org.apache.http.protocol.HttpRequestHandler", MethodName: "handle", Description: "org.apache.http.protocol.HttpRequestHandler.handle — remote source", Assigns: "return"},
		{ID: "java.authc.authenticationtoken.getcredentials", Category: taint.SrcExternal, Pattern: `\.getCredentials\s*\(`, ObjectType: "org.apache.shiro.authc.AuthenticationToken", MethodName: "getCredentials", Description: "org.apache.shiro.authc.AuthenticationToken.getCredentials — remote source", Assigns: "return"},
		{ID: "java.bind.javascriptmethod.", Category: taint.SrcExternal, Pattern: `@JavaScriptMethod\b`, ObjectType: "org.kohsuke.stapler.bind.JavaScriptMethod", MethodName: "", Description: "org.kohsuke.stapler.bind.JavaScriptMethod. — remote source", Assigns: "return"},
		{ID: "java.json.submittedform.", Category: taint.SrcExternal, Pattern: `@SubmittedForm\b`, ObjectType: "org.kohsuke.stapler.json.SubmittedForm", MethodName: "", Description: "org.kohsuke.stapler.json.SubmittedForm. — remote source", Assigns: "return"},
		{ID: "java.json.jsonbody.", Category: taint.SrcExternal, Pattern: `@JsonBody\b`, ObjectType: "org.kohsuke.stapler.json.JsonBody", MethodName: "", Description: "org.kohsuke.stapler.json.JsonBody. — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getrequesturiwithquerystring", Category: taint.SrcExternal, Pattern: `\.getRequestURIWithQueryString\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getRequestURIWithQueryString", Description: "org.kohsuke.stapler.StaplerRequest.getRequestURIWithQueryString — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getrequesturlwithquerystring", Category: taint.SrcExternal, Pattern: `\.getRequestURLWithQueryString\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getRequestURLWithQueryString", Description: "org.kohsuke.stapler.StaplerRequest.getRequestURLWithQueryString — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getreferer", Category: taint.SrcExternal, Pattern: `\.getReferer\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getReferer", Description: "org.kohsuke.stapler.StaplerRequest.getReferer — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getoriginalrequesturi", Category: taint.SrcExternal, Pattern: `\.getOriginalRequestURI\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getOriginalRequestURI", Description: "org.kohsuke.stapler.StaplerRequest.getOriginalRequestURI — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getsubmittedform", Category: taint.SrcExternal, Pattern: `\.getSubmittedForm\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getSubmittedForm", Description: "org.kohsuke.stapler.StaplerRequest.getSubmittedForm — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getfileitem", Category: taint.SrcExternal, Pattern: `\.getFileItem\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getFileItem", Description: "org.kohsuke.stapler.StaplerRequest.getFileItem — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.bindparameterstolist", Category: taint.SrcExternal, Pattern: `\.bindParametersToList\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "bindParametersToList", Description: "org.kohsuke.stapler.StaplerRequest.bindParametersToList — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.bindparameters", Category: taint.SrcExternal, Pattern: `\.bindParameters\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "bindParameters", Description: "org.kohsuke.stapler.StaplerRequest.bindParameters — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.bindjson", Category: taint.SrcExternal, Pattern: `\.bindJSON\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "bindJSON", Description: "org.kohsuke.stapler.StaplerRequest.bindJSON — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.bindjsontolist", Category: taint.SrcExternal, Pattern: `\.bindJSONToList\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "bindJSONToList", Description: "org.kohsuke.stapler.StaplerRequest.bindJSONToList — remote source", Assigns: "return"},
		{ID: "java.stapler.staplerrequest.getrestofpath", Category: taint.SrcExternal, Pattern: `\.getRestOfPath\s*\(`, ObjectType: "org.kohsuke.stapler.StaplerRequest", MethodName: "getRestOfPath", Description: "org.kohsuke.stapler.StaplerRequest.getRestOfPath — remote source", Assigns: "return"},
		{ID: "java.stapler.queryparameter.", Category: taint.SrcExternal, Pattern: `@QueryParameter\b`, ObjectType: "org.kohsuke.stapler.QueryParameter", MethodName: "", Description: "org.kohsuke.stapler.QueryParameter. — remote source", Assigns: "return"},
		{ID: "java.stapler.header.", Category: taint.SrcExternal, Pattern: `@Header\b`, ObjectType: "org.kohsuke.stapler.Header", MethodName: "", Description: "org.kohsuke.stapler.Header. — remote source", Assigns: "return"},
		{ID: "java.stapler.databoundconstructor.", Category: taint.SrcExternal, Pattern: `@DataBoundConstructor\b`, ObjectType: "org.kohsuke.stapler.DataBoundConstructor", MethodName: "", Description: "org.kohsuke.stapler.DataBoundConstructor. — remote source", Assigns: "return"},
		{ID: "java.stapler.databoundsetter.", Category: taint.SrcExternal, Pattern: `@DataBoundSetter\b`, ObjectType: "org.kohsuke.stapler.DataBoundSetter", MethodName: "", Description: "org.kohsuke.stapler.DataBoundSetter. — remote source", Assigns: "return"},
		{ID: "java.web.execute.", Category: taint.SrcExternal, Pattern: `@Execute\b`, ObjectType: "org.lastaflute.web.Execute", MethodName: "", Description: "org.lastaflute.web.Execute. — remote source", Assigns: "return"},
		{ID: "java.savedrequest.savedrequest.getheadervalues", Category: taint.SrcExternal, Pattern: `\.getHeaderValues\s*\(`, ObjectType: "org.springframework.security.web.savedrequest.SavedRequest", MethodName: "getHeaderValues", Description: "org.springframework.security.web.savedrequest.SavedRequest.getHeaderValues — remote source", Assigns: "return"},
		{ID: "java.savedrequest.savedrequest.getredirecturl", Category: taint.SrcExternal, Pattern: `\.getRedirectUrl\s*\(`, ObjectType: "org.springframework.security.web.savedrequest.SavedRequest", MethodName: "getRedirectUrl", Description: "org.springframework.security.web.savedrequest.SavedRequest.getRedirectUrl — remote source", Assigns: "return"},
		{ID: "java.client.resttemplate.postforentity", Category: taint.SrcExternal, Pattern: `\.postForEntity\s*\(`, ObjectType: "org.springframework.web.client.RestTemplate", MethodName: "postForEntity", Description: "org.springframework.web.client.RestTemplate.postForEntity — remote source", Assigns: "return"},
		{ID: "java.request.webrequest.getdescription", Category: taint.SrcExternal, Pattern: `\.getDescription\s*\(`, ObjectType: "org.springframework.web.context.request.WebRequest", MethodName: "getDescription", Description: "org.springframework.web.context.request.WebRequest.getDescription — remote source", Assigns: "return"},
		{ID: "java.request.webrequest.getheadervalues", Category: taint.SrcExternal, Pattern: `\.getHeaderValues\s*\(`, ObjectType: "org.springframework.web.context.request.WebRequest", MethodName: "getHeaderValues", Description: "org.springframework.web.context.request.WebRequest.getHeaderValues — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartfile.getcontenttype", Category: taint.SrcExternal, Pattern: `\.getContentType\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartFile", MethodName: "getContentType", Description: "org.springframework.web.multipart.MultipartFile.getContentType — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartfile.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartFile", MethodName: "getName", Description: "org.springframework.web.multipart.MultipartFile.getName — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartfile.getoriginalfilename", Category: taint.SrcExternal, Pattern: `\.getOriginalFilename\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartFile", MethodName: "getOriginalFilename", Description: "org.springframework.web.multipart.MultipartFile.getOriginalFilename — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartfile.getresource", Category: taint.SrcExternal, Pattern: `\.getResource\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartFile", MethodName: "getResource", Description: "org.springframework.web.multipart.MultipartFile.getResource — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartrequest.getfile", Category: taint.SrcExternal, Pattern: `\.getFile\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartRequest", MethodName: "getFile", Description: "org.springframework.web.multipart.MultipartRequest.getFile — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartrequest.getfilemap", Category: taint.SrcExternal, Pattern: `\.getFileMap\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartRequest", MethodName: "getFileMap", Description: "org.springframework.web.multipart.MultipartRequest.getFileMap — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartrequest.getfilenames", Category: taint.SrcExternal, Pattern: `\.getFileNames\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartRequest", MethodName: "getFileNames", Description: "org.springframework.web.multipart.MultipartRequest.getFileNames — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartrequest.getfiles", Category: taint.SrcExternal, Pattern: `\.getFiles\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartRequest", MethodName: "getFiles", Description: "org.springframework.web.multipart.MultipartRequest.getFiles — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartrequest.getmultifilemap", Category: taint.SrcExternal, Pattern: `\.getMultiFileMap\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartRequest", MethodName: "getMultiFileMap", Description: "org.springframework.web.multipart.MultipartRequest.getMultiFileMap — remote source", Assigns: "return"},
		{ID: "java.multipart.multipartrequest.getmultipartcontenttype", Category: taint.SrcExternal, Pattern: `\.getMultipartContentType\s*\(`, ObjectType: "org.springframework.web.multipart.MultipartRequest", MethodName: "getMultipartContentType", Description: "org.springframework.web.multipart.MultipartRequest.getMultipartContentType — remote source", Assigns: "return"},
		{ID: "java.socket.websockethandler.afterconnectionclosed", Category: taint.SrcExternal, Pattern: `\.afterConnectionClosed\s*\(`, ObjectType: "org.springframework.web.socket.WebSocketHandler", MethodName: "afterConnectionClosed", Description: "org.springframework.web.socket.WebSocketHandler.afterConnectionClosed — remote source", Assigns: "return"},
		{ID: "java.socket.websockethandler.afterconnectionestablished", Category: taint.SrcExternal, Pattern: `\.afterConnectionEstablished\s*\(`, ObjectType: "org.springframework.web.socket.WebSocketHandler", MethodName: "afterConnectionEstablished", Description: "org.springframework.web.socket.WebSocketHandler.afterConnectionEstablished — remote source", Assigns: "return"},
		{ID: "java.socket.websockethandler.handlemessage", Category: taint.SrcExternal, Pattern: `\.handleMessage\s*\(`, ObjectType: "org.springframework.web.socket.WebSocketHandler", MethodName: "handleMessage", Description: "org.springframework.web.socket.WebSocketHandler.handleMessage — remote source", Assigns: "return"},
		{ID: "java.socket.websockethandler.handletransporterror", Category: taint.SrcExternal, Pattern: `\.handleTransportError\s*\(`, ObjectType: "org.springframework.web.socket.WebSocketHandler", MethodName: "handleTransportError", Description: "org.springframework.web.socket.WebSocketHandler.handleTransportError — remote source", Assigns: "return"},
		{ID: "java.handler.abstractwebsockethandler.handlebinarymessage", Category: taint.SrcExternal, Pattern: `\.handleBinaryMessage\s*\(`, ObjectType: "org.springframework.web.socket.handler.AbstractWebSocketHandler", MethodName: "handleBinaryMessage", Description: "org.springframework.web.socket.handler.AbstractWebSocketHandler.handleBinaryMessage — remote source", Assigns: "return"},
		{ID: "java.handler.abstractwebsockethandler.handlepongmessage", Category: taint.SrcExternal, Pattern: `\.handlePongMessage\s*\(`, ObjectType: "org.springframework.web.socket.handler.AbstractWebSocketHandler", MethodName: "handlePongMessage", Description: "org.springframework.web.socket.handler.AbstractWebSocketHandler.handlePongMessage — remote source", Assigns: "return"},
		{ID: "java.handler.abstractwebsockethandler.handletextmessage", Category: taint.SrcExternal, Pattern: `\.handleTextMessage\s*\(`, ObjectType: "org.springframework.web.socket.handler.AbstractWebSocketHandler", MethodName: "handleTextMessage", Description: "org.springframework.web.socket.handler.AbstractWebSocketHandler.handleTextMessage — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getlookuppathforrequest", Category: taint.SrcExternal, Pattern: `\.getLookupPathForRequest\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getLookupPathForRequest", Description: "org.springframework.web.util.UrlPathHelper.getLookupPathForRequest — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getoriginatingquerystring", Category: taint.SrcExternal, Pattern: `\.getOriginatingQueryString\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getOriginatingQueryString", Description: "org.springframework.web.util.UrlPathHelper.getOriginatingQueryString — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getoriginatingrequesturi", Category: taint.SrcExternal, Pattern: `\.getOriginatingRequestUri\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getOriginatingRequestUri", Description: "org.springframework.web.util.UrlPathHelper.getOriginatingRequestUri — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getpathwithinapplication", Category: taint.SrcExternal, Pattern: `\.getPathWithinApplication\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getPathWithinApplication", Description: "org.springframework.web.util.UrlPathHelper.getPathWithinApplication — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getpathwithinservletmapping", Category: taint.SrcExternal, Pattern: `\.getPathWithinServletMapping\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getPathWithinServletMapping", Description: "org.springframework.web.util.UrlPathHelper.getPathWithinServletMapping — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getrequesturi", Category: taint.SrcExternal, Pattern: `\.getRequestUri\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getRequestUri", Description: "org.springframework.web.util.UrlPathHelper.getRequestUri — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.getresolvedlookuppath", Category: taint.SrcExternal, Pattern: `\.getResolvedLookupPath\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "getResolvedLookupPath", Description: "org.springframework.web.util.UrlPathHelper.getResolvedLookupPath — remote source", Assigns: "return"},
		{ID: "java.util.urlpathhelper.resolveandcachelookuppath", Category: taint.SrcExternal, Pattern: `\.resolveAndCacheLookupPath\s*\(`, ObjectType: "org.springframework.web.util.UrlPathHelper", MethodName: "resolveAndCacheLookupPath", Description: "org.springframework.web.util.UrlPathHelper.resolveAndCacheLookupPath — remote source", Assigns: "return"},
		{ID: "java.v1.xmlpullparser.getname", Category: taint.SrcExternal, Pattern: `\.getName\s*\(`, ObjectType: "org.xmlpull.v1.XmlPullParser", MethodName: "getName", Description: "org.xmlpull.v1.XmlPullParser.getName — remote source", Assigns: "return"},
		{ID: "java.v1.xmlpullparser.getnamespace", Category: taint.SrcExternal, Pattern: `\.getNamespace\s*\(`, ObjectType: "org.xmlpull.v1.XmlPullParser", MethodName: "getNamespace", Description: "org.xmlpull.v1.XmlPullParser.getNamespace — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequest.body", Category: taint.SrcExternal, Pattern: `\.body\s*\(`, ObjectType: "play.mvc.Http$Request", MethodName: "body", Description: "play.mvc.Http$Request.body — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.cookie", Category: taint.SrcExternal, Pattern: `\.cookie\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "cookie", Description: "play.mvc.Http$RequestHeader.cookie — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.cookies", Category: taint.SrcExternal, Pattern: `\.cookies\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "cookies", Description: "play.mvc.Http$RequestHeader.cookies — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.header", Category: taint.SrcExternal, Pattern: `\.header\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "header", Description: "play.mvc.Http$RequestHeader.header — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.host", Category: taint.SrcExternal, Pattern: `\.host\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "host", Description: "play.mvc.Http$RequestHeader.host — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.path", Category: taint.SrcExternal, Pattern: `\.path\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "path", Description: "play.mvc.Http$RequestHeader.path — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.querystring", Category: taint.SrcExternal, Pattern: `\.queryString\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "queryString", Description: "play.mvc.Http$RequestHeader.queryString — remote source", Assigns: "return"},
		{ID: "java.mvc.httprequestheader.remoteaddress", Category: taint.SrcExternal, Pattern: `\.remoteAddress\s*\(`, ObjectType: "play.mvc.Http$RequestHeader", MethodName: "remoteAddress", Description: "play.mvc.Http$RequestHeader.remoteAddress — remote source", Assigns: "return"},
		{ID: "java.handling.context.parse", Category: taint.SrcExternal, Pattern: `\.parse\s*\(`, ObjectType: "ratpack.core.handling.Context", MethodName: "parse", Description: "ratpack.core.handling.Context.parse — remote source", Assigns: "return"},
		{ID: "java.http.request.getcontentlength", Category: taint.SrcExternal, Pattern: `\.getContentLength\s*\(`, ObjectType: "ratpack.core.http.Request", MethodName: "getContentLength", Description: "ratpack.core.http.Request.getContentLength — remote source", Assigns: "return"},
		{ID: "java.http.request.getquery", Category: taint.SrcExternal, Pattern: `\.getQuery\s*\(`, ObjectType: "ratpack.core.http.Request", MethodName: "getQuery", Description: "ratpack.core.http.Request.getQuery — remote source", Assigns: "return"},
		{ID: "java.http.request.getrawuri", Category: taint.SrcExternal, Pattern: `\.getRawUri\s*\(`, ObjectType: "ratpack.core.http.Request", MethodName: "getRawUri", Description: "ratpack.core.http.Request.getRawUri — remote source", Assigns: "return"},
		{ID: "java.http.request.geturi", Category: taint.SrcExternal, Pattern: `\.getUri\s*\(`, ObjectType: "ratpack.core.http.Request", MethodName: "getUri", Description: "ratpack.core.http.Request.getUri — remote source", Assigns: "return"},
		{ID: "java.http.request.onecookie", Category: taint.SrcExternal, Pattern: `\.oneCookie\s*\(`, ObjectType: "ratpack.core.http.Request", MethodName: "oneCookie", Description: "ratpack.core.http.Request.oneCookie — remote source", Assigns: "return"},
		{ID: "java.handling.context.parse", Category: taint.SrcExternal, Pattern: `\.parse\s*\(`, ObjectType: "ratpack.handling.Context", MethodName: "parse", Description: "ratpack.handling.Context.parse — remote source", Assigns: "return"},
		{ID: "java.http.request.getcontentlength", Category: taint.SrcExternal, Pattern: `\.getContentLength\s*\(`, ObjectType: "ratpack.http.Request", MethodName: "getContentLength", Description: "ratpack.http.Request.getContentLength — remote source", Assigns: "return"},
		{ID: "java.http.request.getquery", Category: taint.SrcExternal, Pattern: `\.getQuery\s*\(`, ObjectType: "ratpack.http.Request", MethodName: "getQuery", Description: "ratpack.http.Request.getQuery — remote source", Assigns: "return"},
		{ID: "java.http.request.getrawuri", Category: taint.SrcExternal, Pattern: `\.getRawUri\s*\(`, ObjectType: "ratpack.http.Request", MethodName: "getRawUri", Description: "ratpack.http.Request.getRawUri — remote source", Assigns: "return"},
		{ID: "java.http.request.geturi", Category: taint.SrcExternal, Pattern: `\.getUri\s*\(`, ObjectType: "ratpack.http.Request", MethodName: "getUri", Description: "ratpack.http.Request.getUri — remote source", Assigns: "return"},
		{ID: "java.http.request.onecookie", Category: taint.SrcExternal, Pattern: `\.oneCookie\s*\(`, ObjectType: "ratpack.http.Request", MethodName: "oneCookie", Description: "ratpack.http.Request.oneCookie — remote source", Assigns: "return"},

		// =================================================================
		// PR-BBjava: framework-aware Java sources — Spring MVC / Spring Boot,
		// JAX-RS (Jersey, RESTEasy), Micronaut, Quarkus RESTEasy Reactive.
		// Mirrors PR-BBpy (Python) and PR-BBjs (JS/TS).
		//
		// Each entry recognises the canonical parameter-binding annotation on
		// a handler method. Together with the per-language ts-flow walker
		// (which surfaces taint at param.body / param.headers reads) and the
		// new javaTypeCatalog entries in graph/extractor_java.go (which mark
		// the annotated parameter as a typed source so the interprocedural
		// graph propagates the taint across method boundaries), this widens
		// detection well beyond the bare-receiver `request.getParameter(...)`
		// shape the catalog has historically covered.
		// =================================================================

		// --- Spring MVC / Spring Boot — handler parameter annotations
		// (the regex matches the annotation at its usage site; the
		// extractor-side typed catalog handles per-param source tagging).
		{ID: "java.spring.modelattribute", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@ModelAttribute\b`, ObjectType: "Spring", MethodName: "@ModelAttribute", Description: "Spring @ModelAttribute — binds form/query data to a model object passed as a handler arg", Assigns: "return"},
		{ID: "java.spring.requestpart", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestPart\b`, ObjectType: "Spring", MethodName: "@RequestPart", Description: "Spring @RequestPart — multipart request part bound to a handler arg", Assigns: "return"},
		{ID: "java.spring.sessionattribute", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@SessionAttribute\b`, ObjectType: "Spring", MethodName: "@SessionAttribute", Description: "Spring @SessionAttribute — pre-populated session value bound to a handler arg (originally written from user input)", Assigns: "return"},
		{ID: "java.spring.requestattribute", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestAttribute\b`, ObjectType: "Spring", MethodName: "@RequestAttribute", Description: "Spring @RequestAttribute — request-scoped value bound to a handler arg (filter-populated, may carry attacker bytes)", Assigns: "return"},

		// --- JAX-RS — annotations not yet in the catalog. @QueryParam,
		// @PathParam, @FormParam, @HeaderParam, @CookieParam, @BeanParam
		// already exist above; add @MatrixParam (the last canonical
		// JAX-RS @-Param annotation per JSR-339/JSR-370) here.
		{ID: "java.jaxrs.matrixparam", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@MatrixParam\b`, ObjectType: "JAX-RS", MethodName: "@MatrixParam", Description: "JAX-RS @MatrixParam — semicolon-delimited matrix parameter on a URL path segment", Assigns: "return"},

		// --- Micronaut — HTTP parameter binding annotations.
		// @QueryValue already registered above.
		{ID: "java.micronaut.header", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@Header\b`, ObjectType: "Micronaut", MethodName: "@Header", Description: "Micronaut @Header — request header value bound to a handler arg", Assigns: "return"},
		{ID: "java.micronaut.body", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@Body\b`, ObjectType: "Micronaut", MethodName: "@Body", Description: "Micronaut @Body — request body bound to a handler arg (typed payload)", Assigns: "return"},
		{ID: "java.micronaut.part", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@Part\b`, ObjectType: "Micronaut", MethodName: "@Part", Description: "Micronaut @Part — multipart request part bound to a handler arg", Assigns: "return"},
		{ID: "java.micronaut.cookievalue", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@CookieValue\b`, ObjectType: "Micronaut", MethodName: "@CookieValue", Description: "Micronaut @CookieValue — cookie value bound to a handler arg (also shared shape with Spring)", Assigns: "return"},
		{ID: "java.micronaut.requestbean", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RequestBean\b`, ObjectType: "Micronaut", MethodName: "@RequestBean", Description: "Micronaut @RequestBean — composite bean param aggregating multiple HTTP inputs", Assigns: "return"},

		// --- Quarkus RESTEasy Reactive — split annotations.
		// `java.quarkus.rest.annotation` above bundles them into a single
		// alternation; splitting per-annotation makes hint output and
		// rule attribution cleaner. The bundled entry stays for backwards
		// compatibility — duplicate matches are de-duplicated downstream.
		{ID: "java.quarkus.restquery", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestQuery\b`, ObjectType: "Quarkus", MethodName: "@RestQuery", Description: "Quarkus RESTEasy Reactive @RestQuery — query parameter bound to a handler arg", Assigns: "return"},
		{ID: "java.quarkus.restpath", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestPath\b`, ObjectType: "Quarkus", MethodName: "@RestPath", Description: "Quarkus RESTEasy Reactive @RestPath — URL path segment bound to a handler arg", Assigns: "return"},
		{ID: "java.quarkus.restheader", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestHeader\b`, ObjectType: "Quarkus", MethodName: "@RestHeader", Description: "Quarkus RESTEasy Reactive @RestHeader — HTTP header bound to a handler arg", Assigns: "return"},
		{ID: "java.quarkus.restcookie", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestCookie\b`, ObjectType: "Quarkus", MethodName: "@RestCookie", Description: "Quarkus RESTEasy Reactive @RestCookie — cookie bound to a handler arg", Assigns: "return"},
		{ID: "java.quarkus.restform", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestForm\b`, ObjectType: "Quarkus", MethodName: "@RestForm", Description: "Quarkus RESTEasy Reactive @RestForm — form field bound to a handler arg", Assigns: "return"},
		{ID: "java.quarkus.restmatrix", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `@RestMatrix\b`, ObjectType: "Quarkus", MethodName: "@RestMatrix", Description: "Quarkus RESTEasy Reactive @RestMatrix — matrix parameter bound to a handler arg", Assigns: "return"},

		// --- Protocol Buffers / gRPC server-side input (parity with Go's
		// go.proto.unmarshal + go.grpc.metadata). protobuf-java's generated
		// message classes expose static parseFrom()/parseDelimitedFrom() factory
		// methods that decode attacker-supplied wire bytes (carried over gRPC,
		// Kafka, files or sockets) into a typed message; the decoded fields are
		// untrusted and reach SQL/exec/SSRF/deserialization sinks through the
		// generated getters (receiver-taint propagates through the getter call,
		// like the cache-read second-order sources above). Protobuf itself has no
		// gadget-chain RCE, so these are data sources (SrcDeserialized), not
		// deserialization-RCE sinks. parseFrom/parseDelimitedFrom are
		// protobuf-specific method names (zero occurrences elsewhere in the
		// ecosystem), so ObjectType is left empty — mirroring go.proto.unmarshal's
		// empty-ObjectType "Unmarshal" entry.
		{ID: "java.protobuf.parsefrom", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `\.parseFrom\s*\(`, ObjectType: "", MethodName: "parseFrom", Description: "Protocol Buffers message decoded from untrusted wire bytes via a generated parseFrom() factory (protobuf-java) — the decoded fields are untrusted input (gRPC/Kafka/file payloads)", Assigns: "return"},
		{ID: "java.protobuf.parsedelimitedfrom", Category: taint.SrcDeserialized, Language: rules.LangJava, Pattern: `\.parseDelimitedFrom\s*\(`, ObjectType: "", MethodName: "parseDelimitedFrom", Description: "Protocol Buffers message decoded from an untrusted length-delimited stream via a generated parseDelimitedFrom() factory (protobuf-java) — the decoded fields are untrusted input", Assigns: "return"},
		// grpc-java client-set request metadata (custom headers). Scoped to a
		// receiver matching io.grpc.Metadata so the generic get() method name does
		// not over-match; the canonical interceptor idiom names the variable
		// `metadata`/`headers`. Parallels go.grpc.metadata and cpp.grpc.servercontext.client_metadata.
		{ID: "java.grpc.metadata.get", Category: taint.SrcUserInput, Language: rules.LangJava, Pattern: `(?:metadata|headers)\.get\s*\(`, ObjectType: "io.grpc.Metadata", MethodName: "get", Description: "grpc-java io.grpc.Metadata.get(key) — client-supplied request metadata (custom header value), fully attacker-controlled", Assigns: "return"},
	}
}
