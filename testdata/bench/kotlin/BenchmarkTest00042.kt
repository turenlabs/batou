package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via Runtime.exec with array containing user input
suspend fun handler00042(call: ApplicationCall) {
    val cmd = call.parameters["cmd"]
    val process = Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", cmd))
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
