package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.nio.file.Files
import java.nio.file.Paths

// Vulnerable: path traversal via Paths.get
suspend fun handler00067(call: ApplicationCall) {
    val name = call.parameters["name"]
    val path = Paths.get("/data", name)
    val content = String(Files.readAllBytes(path))
    call.respondText(content)
}
