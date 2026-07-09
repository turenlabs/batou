package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C libxml2 XXE / XML parsing sinks (CWE-611, SnkDeserialize)
// Tests cover the unified xmlRead* / xmlCtxtRead* / xmlSAXParse* / legacy
// xmlParse* family. Each test seeds taint via getenv (CGI-style input)
// and expects a SnkDeserialize flow.
// =========================================================================

func TestC_Libxml_xmlReadDoc_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>

void parse_user_doc(void) {
    char *body = getenv("XML_DOC");
    xmlDocPtr doc = xmlReadDoc((const xmlChar *)body, NULL, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_readdoc.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlReadDoc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlReadFile_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>

void parse_user_file(void) {
    char *path = getenv("XML_PATH");
    xmlDocPtr doc = xmlReadFile(path, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_readfile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlReadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlReadMemory_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>
#include <string.h>

void parse_user_memory(void) {
    char *buf = getenv("XML_BUFFER");
    xmlDocPtr doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_readmemory.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlReadMemory")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlCtxtReadDoc_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>

void parse_with_ctxt(xmlParserCtxtPtr ctxt) {
    char *body = getenv("XML_DOC");
    xmlDocPtr doc = xmlCtxtReadDoc(ctxt, (const xmlChar *)body, NULL, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_ctxtreaddoc.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlCtxtReadDoc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlCtxtReadFile_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>

void parse_with_ctxt(xmlParserCtxtPtr ctxt) {
    char *path = getenv("XML_PATH");
    xmlDocPtr doc = xmlCtxtReadFile(ctxt, path, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_ctxtreadfile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlCtxtReadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlCtxtReadMemory_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>
#include <string.h>

void parse_with_ctxt(xmlParserCtxtPtr ctxt) {
    char *buf = getenv("XML_BUFFER");
    xmlDocPtr doc = xmlCtxtReadMemory(ctxt, buf, strlen(buf), NULL, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_ctxtreadmemory.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlCtxtReadMemory")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlSAXParseFile_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <libxml/SAX.h>
#include <stdlib.h>

void parse_user_sax(xmlSAXHandlerPtr sax) {
    char *path = getenv("XML_PATH");
    xmlDocPtr doc = xmlSAXParseFile(sax, path, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_saxparsefile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlSAXParseFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlSAXParseMemory_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <libxml/SAX.h>
#include <stdlib.h>
#include <string.h>

void parse_user_sax(xmlSAXHandlerPtr sax) {
    char *buf = getenv("XML_BUFFER");
    xmlDocPtr doc = xmlSAXParseMemory(sax, buf, strlen(buf), 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_saxparsememory.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlSAXParseMemory")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlParseDoc_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>

void parse_legacy(void) {
    char *body = getenv("XML_DOC");
    xmlDocPtr doc = xmlParseDoc((const xmlChar *)body);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_parsedoc.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlParseDoc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlParseChunk_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>
#include <string.h>

void push_user_chunk(xmlParserCtxtPtr ctxt) {
    char *chunk = getenv("XML_CHUNK");
    xmlParseChunk(ctxt, chunk, strlen(chunk), 0);
}
`
	flows := Analyze(code, "/app/xml_parsechunk.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlParseChunk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxml_xmlParseEntity_FromCGI(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <stdlib.h>

void parse_external_entity(void) {
    char *path = getenv("ENTITY_PATH");
    xmlParseEntity(path);
}
`
	flows := Analyze(code, "/app/xml_parseentity.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow for getenv -> xmlParseEntity")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: literal/constant XML buffer must NOT produce a flow.
func TestC_Libxml_ConstantBuffer_NoFlow(t *testing.T) {
	code := `
#include <libxml/parser.h>

void parse_constant(void) {
    const char *body = "<root><a>safe</a></root>";
    xmlDocPtr doc = xmlReadDoc((const xmlChar *)body, NULL, NULL, 0);
    xmlFreeDoc(doc);
}
`
	flows := Analyze(code, "/app/xml_constant.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("did not expect XXE flow for constant XML buffer")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
