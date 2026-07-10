package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: canonicalPath + startsWith check
suspend fun handler00071(call: ApplicationCall) {
    val path = call.parameters["path"]
    val baseDir = File("/var/data")
    val resolved = File(baseDir, path ?: "").canonicalFile
    if (!resolved.path.startsWith(baseDir.canonicalPath)) {
        call.respondText("Access denied")
        return
    }
    call.respondText(resolved.readText())
}
