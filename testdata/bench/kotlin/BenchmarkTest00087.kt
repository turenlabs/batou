package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream
import java.io.ByteArrayInputStream

// Vulnerable: ObjectInputStream from cookie value
suspend fun handler00087(call: ApplicationCall) {
    val data = call.request.cookies["session_data"]
    val bytes = java.util.Base64.getDecoder().decode(data)
    val ois = ObjectInputStream(ByteArrayInputStream(bytes))
    val obj = ois.readObject()
    call.respondText(obj.toString())
}
