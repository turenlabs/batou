package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.File

// Safe: integer ID used to construct filename
suspend fun handler00076(call: ApplicationCall) {
    val id = call.parameters["id"]?.toIntOrNull() ?: 0
    val content = File("/var/data/item_$id.json").readText()
    call.respondText(content)
}
