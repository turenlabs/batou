package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.io.FileInputStream

// Vulnerable: path traversal via FileInputStream
suspend fun handler00065(call: ApplicationCall) {
    val path = call.parameters["path"]
    val fis = FileInputStream(path!!)
    val content = fis.bufferedReader().readText()
    fis.close()
    call.respondText(content)
}
