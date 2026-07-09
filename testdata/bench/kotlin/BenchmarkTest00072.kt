package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: filename-only with no directory separators
suspend fun handler00072(call: ApplicationCall) {
    val name = call.request.queryParameters["name"]
    val safeName = name?.replace("/", "")?.replace("\\", "")?.replace("..", "") ?: "default"
    val content = File("/var/data/$safeName").readText()
    call.respondText(content)
}
