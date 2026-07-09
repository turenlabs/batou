package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream

// Vulnerable: ObjectInputStream deserialization of user input
suspend fun handler00081(call: ApplicationCall) {
    val bytes = call.receive<ByteArray>()
    val ois = ObjectInputStream(bytes.inputStream())
    val obj = ois.readObject()
    call.respondText(obj.toString())
}
