package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: no user input in command at all
suspend fun handler00057(call: ApplicationCall) {
    val pb = ProcessBuilder("date", "+%Y-%m-%d")
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
