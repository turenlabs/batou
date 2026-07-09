package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

// Safe: kotlinx.serialization with ignoreUnknownKeys
@Serializable
data class Config94(val key: String, val value: String)

suspend fun handler00094(call: ApplicationCall) {
    val body = call.receiveText()
    val json = Json { ignoreUnknownKeys = true }
    val config = json.decodeFromString<Config94>(body)
    call.respondText("Config: ${config.key}=${config.value}")
}
