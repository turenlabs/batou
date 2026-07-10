package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import com.google.gson.Gson

// Safe: Gson deserialization to typed class
data class UserRequest91(val name: String, val age: Int)

suspend fun handler00091(call: ApplicationCall) {
    val body = call.receiveText()
    val user = Gson().fromJson(body, UserRequest91::class.java)
    call.respondText("Hello ${user.name}")
}
