package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via string concatenation in HTML
suspend fun handler00022(call: ApplicationCall) {
    val query = call.request.queryParameters["q"]
    val html = "<html><body><h1>Search results for: " + query + "</h1></body></html>"
    call.respondText(html, ContentType.Text.Html)
}
