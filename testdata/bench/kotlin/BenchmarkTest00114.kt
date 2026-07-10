package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: allowlist of redirect paths
suspend fun handler00114(call: ApplicationCall) {
    val page = call.parameters["page"]
    val allowed = mapOf("home" to "/", "profile" to "/profile", "settings" to "/settings")
    val target = allowed[page] ?: "/"
    call.respondRedirect(target)
}
