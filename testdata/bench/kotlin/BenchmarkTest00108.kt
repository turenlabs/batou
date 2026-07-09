package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via string template
suspend fun handler00108(call: ApplicationCall) {
    val page = call.parameters["page"]
    call.respondRedirect("${page}")
}
