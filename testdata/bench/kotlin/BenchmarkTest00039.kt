package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: regex validation before output
suspend fun handler00039(call: ApplicationCall) {
    val username = call.parameters["username"]
    val safe = if (username?.matches(Regex("^[a-zA-Z0-9_]+$")) == true) username else "anonymous"
    call.respondText("<html><body>Profile: $safe</body></html>", ContentType.Text.Html)
}
