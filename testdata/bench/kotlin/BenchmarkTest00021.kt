package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via unescaped user input in HTML response
suspend fun handler00021(call: ApplicationCall) {
    val name = call.parameters["name"]
    call.respondText("<html><body>Hello $name</body></html>", ContentType.Text.Html)
}
