package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream

// Vulnerable: ObjectInputStream from header value
suspend fun handler00089(call: ApplicationCall) {
    val data = call.request.headers["X-Serialized-Data"]
    val bytes = java.util.Base64.getDecoder().decode(data)
    val ois = ObjectInputStream(bytes.inputStream())
    val obj = ois.readObject()
    call.respondText(obj.toString())
}
