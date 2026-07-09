package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via input in HTML attribute
suspend fun handler00028(call: ApplicationCall) {
    val color = call.parameters["color"]
    call.respondText("<div style='background-color: $color'>Content</div>", ContentType.Text.Html)
}
