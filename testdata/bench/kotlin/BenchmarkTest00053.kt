package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: allowlist validation before command execution
suspend fun handler00053(call: ApplicationCall) {
    val tool = call.parameters["tool"]
    val allowed = setOf("git", "node", "python3")
    if (tool !in allowed) {
        call.respondText("Invalid tool")
        return
    }
    val pb = ProcessBuilder(tool!!, "--version")
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
