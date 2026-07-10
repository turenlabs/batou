package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.beans.XMLDecoder
import java.io.ByteArrayInputStream

// Vulnerable: XMLDecoder deserialization of user input
suspend fun handler00088(call: ApplicationCall) {
    val xml = call.receiveText()
    val decoder = XMLDecoder(ByteArrayInputStream(xml.toByteArray()))
    val obj = decoder.readObject()
    decoder.close()
    call.respondText(obj.toString())
}
