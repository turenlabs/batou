package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via Runtime.exec with string concatenation
suspend fun handler00041(call: ApplicationCall) {
    val host = call.parameters["host"]
    val process = Runtime.getRuntime().exec("ping -c 1 $host")
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
