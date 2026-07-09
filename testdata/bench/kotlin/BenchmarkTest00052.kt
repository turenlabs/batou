package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: hardcoded command with no user input
suspend fun handler00052(call: ApplicationCall) {
    val process = Runtime.getRuntime().exec("uptime")
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
