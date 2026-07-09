package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via string template in exec
suspend fun handler00047(call: ApplicationCall) {
    val port = call.parameters["port"]
    val process = Runtime.getRuntime().exec("netstat -an | grep $port")
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
