package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: alphanumeric-only validation before exec
suspend fun handler00058(call: ApplicationCall) {
    val name = call.parameters["name"]
    if (name == null || !name.matches(Regex("^[a-zA-Z0-9]+$"))) {
        call.respondText("Invalid name")
        return
    }
    val pb = ProcessBuilder("id", name)
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
