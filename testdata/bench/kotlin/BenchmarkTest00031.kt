package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: HTML-encoded output
suspend fun handler00031(call: ApplicationCall) {
    val name = call.parameters["name"]
    val safe = name?.replace("&", "&amp;")?.replace("<", "&lt;")?.replace(">", "&gt;")
    call.respondText("<html><body>Hello $safe</body></html>", ContentType.Text.Html)
}
