package com.example.vulnerable

import java.io.ObjectInputStream
import java.net.URL
import javax.servlet.http.HttpServletRequest
import com.fasterxml.jackson.databind.ObjectMapper
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context

// CWE-502: native deserialization of an attacker-controlled stream.
class DeserHandler {
    fun handle(req: HttpServletRequest): Any {
        val ois = ObjectInputStream(req.inputStream)
        return ois.readObject()
    }

    // CWE-502: Jackson polymorphic default typing makes readValue a gadget sink.
    fun jackson(req: HttpServletRequest): Any {
        val mapper = ObjectMapper()
        mapper.enableDefaultTyping()
        return mapper.readValue(req.getParameter("data"), Any::class.java)
    }
}

// CWE-1336: server-side template injection — user input concatenated into template source.
class TemplateHandler {
    fun render(engine: TemplateEngine, ctx: Context, name: String): String {
        return engine.process("Hello " + name, ctx)
    }
}

// CWE-918: SSRF — URL built from a non-literal target is opened.
class FetchHandler {
    fun fetch(target: String): String {
        return URL(target).openConnection().getInputStream().bufferedReader().readText()
    }
}
