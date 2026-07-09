package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: redirect to relative path only (starts with /)
suspend fun handler00112(call: ApplicationCall) {
    val next = call.request.queryParameters["next"]
    if (next == null || !next.startsWith("/") || next.startsWith("//")) {
        call.respondRedirect("/")
        return
    }
    call.respondRedirect(next)
}
