package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: integer ID used to construct redirect path
suspend fun handler00116(call: ApplicationCall) {
    val id = call.parameters["id"]?.toIntOrNull() ?: 0
    call.respondRedirect("/items/$id")
}
