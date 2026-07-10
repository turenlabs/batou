package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via string concatenation
suspend fun handler00103(call: ApplicationCall) {
    val path = call.parameters["path"]
    call.respondRedirect("https://example.com/" + path)
}
