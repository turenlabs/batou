package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

// Vulnerable: command injection via receive body
suspend fun handler00044(call: ApplicationCall) {
    val body = call.receive<Map<String, String>>()
    val ip = body["ip"]
    val process = Runtime.getRuntime().exec("nslookup $ip")
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
