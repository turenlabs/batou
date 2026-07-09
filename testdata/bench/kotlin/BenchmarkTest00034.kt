package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*
import org.owasp.encoder.Encode

// Safe: OWASP encoder used for HTML context
suspend fun handler00034(call: ApplicationCall) {
    val comment = call.parameters["comment"]
    val safe = Encode.forHtml(comment)
    call.respondText("<div class='comment'>$safe</div>", ContentType.Text.Html)
}
