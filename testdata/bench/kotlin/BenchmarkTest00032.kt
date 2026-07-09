package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: plain text content type (no HTML interpretation)
suspend fun handler00032(call: ApplicationCall) {
    val query = call.request.queryParameters["q"]
    call.respondText("Search results for: $query", ContentType.Text.Plain)
}
