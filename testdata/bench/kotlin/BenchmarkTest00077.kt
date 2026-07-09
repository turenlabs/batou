package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: regex validation of filename (alphanumeric + dots only)
suspend fun handler00077(call: ApplicationCall) {
    val file = call.parameters["file"]
    if (file == null || !file.matches(Regex("^[a-zA-Z0-9_.-]+$"))) {
        call.respondText("Invalid filename")
        return
    }
    val content = File("/uploads/$file").readText()
    call.respondText(content)
}
