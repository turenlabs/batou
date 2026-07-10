package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: hardcoded redirect with no user input
suspend fun handler00113(call: ApplicationCall) {
    call.respondRedirect("/dashboard")
}
