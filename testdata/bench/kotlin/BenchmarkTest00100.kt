package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

// Safe: manual JSON parsing from form parameters (no deserialization)
suspend fun handler00100(call: ApplicationCall) {
    val params = call.receiveParameters()
    val name = params["name"] ?: "unknown"
    val age = params["age"]?.toIntOrNull() ?: 0
    call.respondText("Name: $name, Age: $age")
}
