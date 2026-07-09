package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream

// Vulnerable: ObjectInputStream with query parameter data
suspend fun handler00090(call: ApplicationCall) {
    val data = call.request.queryParameters["obj"]
    val bytes = java.util.Base64.getDecoder().decode(data)
    val ois = ObjectInputStream(bytes.inputStream())
    val obj = ois.readObject()
    call.respondText(obj.toString())
}
