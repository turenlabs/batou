package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: integer-only port validation before command
suspend fun handler00056(call: ApplicationCall) {
    val port = call.parameters["port"]?.toIntOrNull()
    if (port == null || port < 1 || port > 65535) {
        call.respondText("Invalid port")
        return
    }
    val pb = ProcessBuilder("lsof", "-i", ":$port")
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
