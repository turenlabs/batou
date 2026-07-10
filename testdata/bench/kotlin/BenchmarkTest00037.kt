package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: allowlist-based validation
suspend fun handler00037(call: ApplicationCall) {
    val color = call.parameters["color"]
    val allowed = setOf("red", "green", "blue", "yellow")
    val safeColor = if (color in allowed) color else "white"
    call.respondText("<div style='background-color: $safeColor'>Content</div>", ContentType.Text.Html)
}
