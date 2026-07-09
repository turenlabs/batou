package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: allowlist of filenames
suspend fun handler00075(call: ApplicationCall) {
    val doc = call.parameters["doc"]
    val allowed = setOf("readme.txt", "license.txt", "changelog.txt")
    if (doc !in allowed) {
        call.respondText("Not found")
        return
    }
    val content = File("/docs/$doc").readText()
    call.respondText(content)
}
