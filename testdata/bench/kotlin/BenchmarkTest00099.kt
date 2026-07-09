package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

// Safe: Jackson with ObjectInputFilter and typed class
data class Comment99(val text: String, val author: String)

suspend fun handler00099(call: ApplicationCall) {
    val body = call.receiveText()
    val mapper = ObjectMapper()
    val comment = mapper.readValue<Comment99>(body)
    call.respondText("Comment by ${comment.author}")
}
