package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.nio.file.Path

// Safe: Path.resolve + normalize + startsWith
suspend fun handler00074(call: ApplicationCall) {
    val name = call.parameters["name"]
    val base = Path.of("/uploads")
    val resolved = base.resolve(name ?: "").normalize()
    if (!resolved.startsWith(base)) {
        call.respondText("Access denied")
        return
    }
    call.respondText(resolved.toFile().readText())
}
