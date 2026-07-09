package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

// Safe: escapeHTML utility function
fun escapeHtml(input: String?): String {
    return input?.replace("&", "&amp;")
        ?.replace("<", "&lt;")
        ?.replace(">", "&gt;")
        ?.replace("\"", "&quot;")
        ?.replace("'", "&#x27;") ?: ""
}

suspend fun handler00036(call: ApplicationCall) {
    val referer = call.request.headers["Referer"]
    call.respondText("<a href='${escapeHtml(referer)}'>Go back</a>", ContentType.Text.Html)
}
