package com.example.safe

import java.net.URL
import com.fasterxml.jackson.databind.ObjectMapper
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context

data class MyDto(val name: String)

// Safe: static template name, no user input in template source.
class TemplateHandlerSafe {
    fun render(engine: TemplateEngine, ctx: Context): String {
        return engine.process("welcome-page", ctx)
    }
}

// Safe: URL is a hardcoded literal, no SSRF.
class FetchHandlerSafe {
    fun health(): String {
        return URL("https://internal.example.com/health").readText()
    }
}

// Safe: typed readValue without default typing enabled.
class JsonHandlerSafe {
    fun parse(mapper: ObjectMapper, data: String): MyDto {
        return mapper.readValue(data, MyDto::class.java)
    }
}
