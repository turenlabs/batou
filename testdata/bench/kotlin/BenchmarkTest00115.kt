package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.net.URI

// Safe: validate same-origin before redirect
suspend fun handler00115(call: ApplicationCall) {
    val url = call.parameters["url"] ?: "/"
    val parsed = URI(url)
    if (parsed.isAbsolute && parsed.host != "example.com") {
        call.respondRedirect("/")
        return
    }
    call.respondRedirect(url)
}
