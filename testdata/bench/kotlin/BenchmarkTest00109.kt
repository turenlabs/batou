package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

// Vulnerable: open redirect via receive body
suspend fun handler00109(call: ApplicationCall) {
    val body = call.receive<Map<String, String>>()
    val destination = body["destination"]
    call.respondRedirect(destination ?: "/")
}
