package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: cookie value used as lookup key in a map, not file path
suspend fun handler00078(call: ApplicationCall) {
    val theme = call.request.cookies["theme"]
    val themes = mapOf("dark" to "/themes/dark/style.css", "light" to "/themes/light/style.css")
    val path = themes[theme] ?: "/themes/default/style.css"
    val css = File(path).readText()
    call.respondText(css)
}
