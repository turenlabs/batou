package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: no deserialization at all, hardcoded data
suspend fun handler00095(call: ApplicationCall) {
    val data = mapOf("status" to "ok", "version" to "1.0")
    call.respondText(data.toString())
}
