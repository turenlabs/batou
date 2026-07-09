package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via cookie value
suspend fun handler00048(call: ApplicationCall) {
    val tool = call.request.cookies["tool"]
    val process = Runtime.getRuntime().exec("/bin/sh -c $tool --version")
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
