package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import com.google.gson.Gson

// Safe: Gson with specific type, not Object
data class SearchQuery96(val query: String, val page: Int)

suspend fun handler00096(call: ApplicationCall) {
    val body = call.receiveText()
    val search = Gson().fromJson(body, SearchQuery96::class.java)
    call.respondText("Searching: ${search.query}")
}
