package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via cookie value
suspend fun handler00068(call: ApplicationCall) {
    val theme = call.request.cookies["theme"]
    val css = File("/themes/$theme/style.css").readText()
    call.respondText(css)
}
