package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: JSON response, not HTML
suspend fun handler00035(call: ApplicationCall) {
    val user = call.request.cookies["username"]
    call.respondText("{\"user\": \"$user\"}", ContentType.Application.Json)
}
