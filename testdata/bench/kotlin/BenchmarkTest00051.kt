package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: ProcessBuilder with separate arguments, no shell
suspend fun handler00051(call: ApplicationCall) {
    val host = call.parameters["host"]
    val pb = ProcessBuilder("ping", "-c", "1", host ?: "localhost")
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
