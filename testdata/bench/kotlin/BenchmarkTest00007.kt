package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via concatenation with WHERE IN
suspend fun handler00007(call: ApplicationCall) {
    val ids = call.parameters["ids"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val query = "SELECT * FROM users WHERE id IN (" + ids + ")"
    conn.createStatement().executeQuery(query)
    call.respondText("OK")
}
