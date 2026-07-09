package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via query parameter
suspend fun handler00102(call: ApplicationCall) {
    val next = call.request.queryParameters["next"]
    call.respondRedirect(next ?: "/")
}
