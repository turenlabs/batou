package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via receiveText
suspend fun handler00110(call: ApplicationCall) {
    val url = call.request.queryParameters["goto"]
    call.respondRedirect(url ?: "/home")
}
