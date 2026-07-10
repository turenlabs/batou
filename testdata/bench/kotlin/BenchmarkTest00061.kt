package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via File(input).readText()
suspend fun handler00061(call: ApplicationCall) {
    val path = call.parameters["path"]
    val content = File(path!!).readText()
    call.respondText(content)
}
