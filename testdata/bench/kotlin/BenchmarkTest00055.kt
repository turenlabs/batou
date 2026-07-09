package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: ProcessBuilder with explicit args array, no shell invocation
suspend fun handler00055(call: ApplicationCall) {
    val filename = call.parameters["file"]
    val pb = ProcessBuilder("cat", filename ?: "/dev/null")
    pb.redirectErrorStream(true)
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
