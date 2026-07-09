package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via string template in Ktor
suspend fun handler00001(call: ApplicationCall) {
    val id = call.parameters["id"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val rs = conn.createStatement().executeQuery("SELECT * FROM users WHERE id = $id")
    call.respondText(rs.toString())
}
