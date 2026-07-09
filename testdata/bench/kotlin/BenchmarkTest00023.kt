package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via form data reflected in HTML
suspend fun handler00023(call: ApplicationCall) {
    val params = call.receiveParameters()
    val comment = params["comment"]
    call.respondText("<div class='comment'>$comment</div>", ContentType.Text.Html)
}
