package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via receive body in HTML table
suspend fun handler00029(call: ApplicationCall) {
    val body = call.receive<Map<String, String>>()
    val title = body["title"]
    call.respondText("<table><tr><td>$title</td></tr></table>", ContentType.Text.Html)
}
