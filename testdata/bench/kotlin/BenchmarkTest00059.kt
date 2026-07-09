package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: hardcoded arguments array with env-only input
suspend fun handler00059(call: ApplicationCall) {
    val pb = ProcessBuilder("env")
    pb.environment()["APP_MODE"] = "production"
    val process = pb.start()
    val output = process.inputStream.bufferedReader().readText()
    call.respondText(output)
}
