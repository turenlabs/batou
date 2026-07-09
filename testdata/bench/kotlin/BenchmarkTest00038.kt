package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: integer-only parameter in HTML
suspend fun handler00038(call: ApplicationCall) {
    val id = call.parameters["id"]?.toIntOrNull() ?: 0
    call.respondText("<html><body>Item #$id</body></html>", ContentType.Text.Html)
}
