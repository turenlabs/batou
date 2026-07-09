package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: regex validation of IP address before use
suspend fun handler00054(call: ApplicationCall) {
    val ip = call.parameters["ip"]
    val ipRegex = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
    if (ip == null || !ipRegex.matches(ip)) {
        call.respondText("Invalid IP")
        return
    }
    val pb = ProcessBuilder("ping", "-c", "1", ip)
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
