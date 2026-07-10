package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Vulnerable: XSS via template string in script tag
suspend fun handler00027(call: ApplicationCall) {
    val data = call.parameters["data"]
    call.respondText("<script>var x = '$data';</script>", ContentType.Text.Html)
}
