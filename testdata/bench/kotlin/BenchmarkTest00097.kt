package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

// Safe: Ktor's built-in ContentNegotiation (type-safe receive)
data class LoginRequest97(val username: String, val password: String)

suspend fun handler00097(call: ApplicationCall) {
    val login = call.receive<LoginRequest97>()
    call.respondText("Login: ${login.username}")
}
