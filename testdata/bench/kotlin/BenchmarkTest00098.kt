package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

// Safe: kotlinx.serialization list deserialization to typed class
@Serializable
data class Item98(val id: Int, val name: String)

suspend fun handler00098(call: ApplicationCall) {
    val body = call.receiveText()
    val items = Json.decodeFromString<List<Item98>>(body)
    call.respondText("Items: ${items.size}")
}
