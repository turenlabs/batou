package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.io.ObjectInputStream

// Vulnerable: ObjectInputStream from multipart upload
suspend fun handler00084(call: ApplicationCall) {
    val multipart = call.receiveMultipart()
    multipart.forEachPart { part ->
        if (part is io.ktor.http.content.PartData.FileItem) {
            val ois = ObjectInputStream(part.streamProvider())
            val obj = ois.readObject()
            call.respondText(obj.toString())
        }
        part.dispose()
    }
}
