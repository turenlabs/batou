package bench

import io.ktor.server.application.*
import io.ktor.server.response.*

// Safe: hardcoded query with no user input
suspend fun handler00013(call: ApplicationCall) {
    val conn = java.sql.DriverManager.getConnection("jdbc:sqlite::memory:")
    val rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM users")
    call.respondText(rs.toString())
}
