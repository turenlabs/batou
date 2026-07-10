package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: redirect to static path based on enum-like parameter
suspend fun handler00119(call: ApplicationCall) {
    val action = call.parameters["action"]
    val target = when (action) {
        "login" -> "/auth/login"
        "register" -> "/auth/register"
        "logout" -> "/auth/logout"
        else -> "/"
    }
    call.respondRedirect(target)
}
