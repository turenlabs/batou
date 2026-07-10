package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: strip path separators and null bytes
suspend fun handler00079(call: ApplicationCall) {
    val lang = call.request.headers["Accept-Language"]
    val safeLang = lang?.replace(Regex("[^a-z-]"), "")?.take(5) ?: "en"
    val content = File("/i18n/$safeLang.json").readText()
    call.respondText(content)
}
