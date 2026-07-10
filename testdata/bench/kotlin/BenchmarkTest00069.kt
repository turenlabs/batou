package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Vulnerable: path traversal via header value
suspend fun handler00069(call: ApplicationCall) {
    val lang = call.request.headers["Accept-Language"]
    val content = File("/i18n/${lang}.json").readText()
    call.respondText(content)
}
