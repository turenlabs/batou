package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: using ProcessBuilder list constructor with sanitized input
suspend fun handler00060(call: ApplicationCall) {
    val domain = call.parameters["domain"]
    val safeDomain = domain?.replace(Regex("[^a-zA-Z0-9.-]"), "") ?: "example.com"
    val pb = ProcessBuilder(listOf("nslookup", safeDomain))
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
