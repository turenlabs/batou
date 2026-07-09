package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via cookie value
suspend fun handler00009(call: ApplicationCall) {
    val role = call.request.cookies["role"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().executeQuery("SELECT * FROM users WHERE role = '${role}'")
    call.respondText("OK")
}
