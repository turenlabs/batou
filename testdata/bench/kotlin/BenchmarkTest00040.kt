package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*
import org.apache.commons.text.StringEscapeUtils

// Safe: Apache Commons escapeHtml4
suspend fun handler00040(call: ApplicationCall) {
    val title = call.parameters["title"]
    val safe = StringEscapeUtils.escapeHtml4(title)
    call.respondText("<html><head><title>$safe</title></head></html>", ContentType.Text.Html)
}
