package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via query parameter in img src
suspend fun handler00030(call: ApplicationCall) {
    val url = call.request.queryParameters["avatar"]
    call.respondText("<img src='$url' alt='avatar'>", ContentType.Text.Html)
}
