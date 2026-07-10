package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via header value
suspend fun handler00107(call: ApplicationCall) {
    val referer = call.request.headers["Referer"]
    call.respondRedirect(referer ?: "/")
}
