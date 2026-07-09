package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: canonicalPath validation with base directory
suspend fun handler00080(call: ApplicationCall) {
    val filepath = call.parameters["path"]
    val base = "/var/www/public"
    val resolved = File(base, filepath ?: "").canonicalPath
    if (!resolved.startsWith(base)) {
        call.respondText("Forbidden", status = io.ktor.http.HttpStatusCode.Forbidden)
        return
    }
    call.respondText(File(resolved).readText())
}
