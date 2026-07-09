package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via header value in HTML
suspend fun handler00025(call: ApplicationCall) {
    val referer = call.request.headers["Referer"]
    call.respondText("<a href='$referer'>Go back</a>", ContentType.Text.Html)
}
