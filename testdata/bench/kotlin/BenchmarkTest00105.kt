package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via cookie value
suspend fun handler00105(call: ApplicationCall) {
    val returnUrl = call.request.cookies["return_url"]
    call.respondRedirect(returnUrl ?: "/")
}
