package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via cookie value in HTML response
suspend fun handler00024(call: ApplicationCall) {
    val user = call.request.cookies["username"]
    call.respondText("<html><body>Welcome back, $user!</body></html>", ContentType.Text.Html)
}
