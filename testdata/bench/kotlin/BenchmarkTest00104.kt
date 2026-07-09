package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

// Vulnerable: open redirect via form data
suspend fun handler00104(call: ApplicationCall) {
    val params = call.receiveParameters()
    val redirect = params["redirect_url"]
    call.respondRedirect(redirect ?: "/")
}
