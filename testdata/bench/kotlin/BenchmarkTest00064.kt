package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via receive body
suspend fun handler00064(call: ApplicationCall) {
    val body = call.receive<Map<String, String>>()
    val doc = body["document"]
    val content = File("/docs/$doc").readText()
    call.respondText(content)
}
