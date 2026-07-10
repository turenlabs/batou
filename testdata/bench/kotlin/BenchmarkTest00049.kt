package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Vulnerable: command injection via header value
suspend fun handler00049(call: ApplicationCall) {
    val userAgent = call.request.headers["User-Agent"]
    val process = Runtime.getRuntime().exec("echo $userAgent >> /var/log/agents.log")
    call.respondText("Logged")
}
