package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import com.fasterxml.jackson.databind.ObjectMapper

// Vulnerable: Jackson polymorphic deserialization with enableDefaultTyping
suspend fun handler00086(call: ApplicationCall) {
    val body = call.receiveText()
    val mapper = ObjectMapper()
    mapper.enableDefaultTyping()
    val obj = mapper.readValue(body, Any::class.java)
    call.respondText(obj.toString())
}
