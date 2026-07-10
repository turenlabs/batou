package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: cookie value used with prepared statement
suspend fun handler00019(call: ApplicationCall) {
    val role = call.request.cookies["role"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE role = ?")
    stmt.setString(1, role)
    stmt.executeQuery()
    call.respondText("OK")
}
