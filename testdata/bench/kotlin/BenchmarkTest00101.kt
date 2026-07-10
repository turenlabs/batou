package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: open redirect via user-supplied URL
suspend fun handler00101(call: ApplicationCall) {
    val url = call.parameters["url"]
    call.respondRedirect(url!!)
}
