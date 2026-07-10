package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via string template
suspend fun handler00063(call: ApplicationCall) {
    val filename = call.parameters["file"]
    val content = File("/uploads/$filename").readText()
    call.respondText(content)
}
