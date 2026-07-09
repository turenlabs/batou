package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: hardcoded HTML with no user input
suspend fun handler00033(call: ApplicationCall) {
    call.respondText("<html><body><h1>Welcome</h1></body></html>", ContentType.Text.Html)
}
