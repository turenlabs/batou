package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via string concatenation
suspend fun handler00062(call: ApplicationCall) {
    val name = call.request.queryParameters["name"]
    val file = File("/var/data/" + name)
    val content = file.readText()
    call.respondText(content)
}
