package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.net.URI

// Safe: strip protocol and validate host before redirect
suspend fun handler00120(call: ApplicationCall) {
    val url = call.request.queryParameters["goto"] ?: "/"
    val parsed = try { URI(url) } catch (e: Exception) { URI("/") }
    val safe = if (parsed.host == null || parsed.host == "example.com") url else "/"
    call.respondRedirect(safe)
}
