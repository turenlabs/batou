package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: regex validation of redirect path
suspend fun handler00118(call: ApplicationCall) {
    val path = call.parameters["path"]
    if (path == null || !path.matches(Regex("^/[a-zA-Z0-9/_-]+$"))) {
        call.respondRedirect("/")
        return
    }
    call.respondRedirect(path)
}
