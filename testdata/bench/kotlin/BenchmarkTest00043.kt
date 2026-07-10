package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via ProcessBuilder with user input in command
suspend fun handler00043(call: ApplicationCall) {
    val filename = call.parameters["file"]
    val pb = ProcessBuilder("/bin/sh", "-c", "cat $filename")
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
