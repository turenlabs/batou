package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

// Vulnerable: command injection via receiveText in exec
suspend fun handler00050(call: ApplicationCall) {
    val script = call.receiveText()
    val process = Runtime.getRuntime().exec(arrayOf("/bin/bash", "-c", script))
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
