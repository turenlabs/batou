package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream
import java.net.URL

// Vulnerable: ObjectInputStream from URL provided by user
suspend fun handler00085(call: ApplicationCall) {
    val url = call.parameters["url"]
    val stream = URL(url!!).openStream()
    val ois = ObjectInputStream(stream)
    val obj = ois.readObject()
    call.respondText(obj.toString())
}
