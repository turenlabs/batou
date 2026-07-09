package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.net.URI

// Safe: URL validation with host allowlist
suspend fun handler00111(call: ApplicationCall) {
    val url = call.parameters["url"]
    val allowed = setOf("example.com", "app.example.com")
    val parsed = URI(url ?: "/")
    if (parsed.host != null && parsed.host !in allowed) {
        call.respondRedirect("/")
        return
    }
    call.respondRedirect(parsed.toString())
}
