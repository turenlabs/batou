package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via receiveText
suspend fun handler00070(call: ApplicationCall) {
    val filepath = call.receiveText()
    val content = File(filepath).readText()
    call.respondText(content)
}
