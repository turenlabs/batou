package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

// Safe: kotlinx.serialization with typed class
@Serializable
data class UserRequest92(val name: String, val email: String)

suspend fun handler00092(call: ApplicationCall) {
    val body = call.receiveText()
    val user = Json.decodeFromString<UserRequest92>(body)
    call.respondText("User: ${user.name}")
}
