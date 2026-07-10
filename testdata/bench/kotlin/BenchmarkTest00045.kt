package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via query parameter in ProcessBuilder
suspend fun handler00045(call: ApplicationCall) {
    val dir = call.request.queryParameters["dir"]
    val pb = ProcessBuilder("/bin/sh", "-c", "ls -la $dir")
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
