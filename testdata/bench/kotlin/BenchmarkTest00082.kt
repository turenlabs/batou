package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream
import java.util.Base64

// Vulnerable: ObjectInputStream from Base64-decoded request body
suspend fun handler00082(call: ApplicationCall) {
    val body = call.receiveText()
    val decoded = Base64.getDecoder().decode(body)
    val ois = ObjectInputStream(decoded.inputStream())
    val obj = ois.readObject()
    call.respondText(obj.toString())
}
