package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: hardcoded file path, no user input
suspend fun handler00073(call: ApplicationCall) {
    val content = File("/var/data/config.json").readText()
    call.respondText(content)
}
