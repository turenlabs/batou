package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: integer parsing before use in query
suspend fun handler00017(call: ApplicationCall) {
    val id = call.parameters["id"]?.toIntOrNull() ?: 0
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setInt(1, id)
    stmt.executeQuery()
    call.respondText("OK")
}
