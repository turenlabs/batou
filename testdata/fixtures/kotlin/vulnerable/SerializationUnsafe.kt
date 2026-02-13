package com.example.vulnerable

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class UserCommand(val action: String, val target: String)

// Vulnerable: deserializing untrusted input without validation
fun Route.userRoutes() {
    post("/execute") {
        val body = call.receiveText()
        val command = Json.decodeFromString<UserCommand>(body)
        executeCommand(command)
        call.respondText("OK")
    }
}

fun executeCommand(command: UserCommand) {
    // Process command
}
